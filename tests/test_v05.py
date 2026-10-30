import copy
import hashlib
import json
import urllib.error
import zipfile
from pathlib import Path

import pytest

import oap
from oap import trust
from oap.core import main
from oap.v04 import manifest_payload

NOW = '2026-10-30T12:00:00Z'
LATER = '2026-11-06T00:00:00Z'
PAST = '2026-10-01T00:00:00Z'
VECTORS = Path(__file__).parent / 'vectors'


class World:
    def __init__(self, root):
        self.root = root
        self.agent = oap.generate_identity()
        self.recipient = oap.generate_recipient_identity()
        self.authority = oap.generate_identity()
        self.issuer = oap.generate_identity()
        self.agent_id = oap.calculate_key_id(self.agent['public_key'])
        self.recipient_id = oap.calculate_key_id(self.recipient['public_key'])
        self.authority_id = oap.calculate_key_id(self.authority['public_key'])
        self.issuer_id = oap.calculate_key_id(self.issuer['public_key'])
        self.revokers = [{'key_id': self.authority_id, 'public_key': self.authority['public_key'],
                          'name': 'Authority'}]
        self.issuers = [{'key_id': self.issuer_id, 'public_key': self.issuer['public_key'],
                         'name': 'Agency', 'accepted_claim_types': ['representation', 'union_status']}]
        manifest = oap.new_manifest('lead')
        manifest['agent']['public_key'] = self.agent['public_key']
        manifest['assets'] = [
            {'file': 'portfolio/face.txt', 'clearance': 'public', 'role': 'headshot'},
            {'file': 'identity/ref.bin', 'clearance': 'cast', 'role': 'reference_sheet'}]
        (root / 'portfolio').mkdir()
        (root / 'identity').mkdir()
        (root / 'portfolio/face.txt').write_bytes(b'public pixels')
        (root / 'identity/ref.bin').write_bytes(b'private pixels')
        (root / 'manifest.json').write_text(json.dumps(manifest))

    def package(self, name='full.oap', **kwargs):
        path = self.root / name
        oap.package_actor(str(self.root), str(path), 'full', self.agent['_private'],
                          [self.recipient['public_key']], **kwargs)
        return path

    def fresh_list(self, entries=(), signer=None, **kwargs):
        kwargs.setdefault('issued_at', PAST)
        kwargs.setdefault('next_update', LATER)
        return oap.create_revocation_list('urn:oap:revocation:list:test', list(entries),
                                          (signer or self.authority)['_private'], **kwargs)

    def revoke(self, key_id, key_type, signer=None, **kwargs):
        kwargs.setdefault('revoked_at', PAST)
        return oap.create_revocation_entry(key_id, key_type, 'compromised',
                                           (signer or self.authority)['_private'], **kwargs)

    def attest(self, **kwargs):
        kwargs.setdefault('issued_at', PAST)
        claims = kwargs.pop('claims', {'representation': 'example-agency'})
        return oap.create_attestation(kwargs.pop('actor_id', 'lead'), claims,
                                      kwargs.pop('signer', self.issuer)['_private'], **kwargs)

    def verify(self, path, **kwargs):
        kwargs.setdefault('known_agents', [self.agent['public_key']])
        kwargs.setdefault('known_revokers', self.revokers)
        kwargs.setdefault('attestation_issuers', self.issuers)
        kwargs.setdefault('revocation_lists', [self.fresh_list()])
        kwargs.setdefault('now', NOW)
        return oap.verify_package(path, **kwargs)


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def rewrite(source, target, edits=None, drop=()):
    edits = edits or {}
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, 'w') as changed:
        for name in original.namelist():
            if name not in drop:
                changed.writestr(name, edits.get(name, original.read(name)))


def downgrade_to_v04(world, name='v04.oap'):
    source = world.package('v04-source.oap')
    with zipfile.ZipFile(source) as archive:
        manifest = json.loads(archive.read('manifest.json'))
    manifest['oap_version'] = '0.4.0'
    oap.sign_manifest(manifest, world.agent['_private'])
    target = world.root / name
    rewrite(source, target, {'manifest.json': json.dumps(manifest).encode()})
    return target


def test_key_id_is_stable_lowercase_and_raw_key_based(world):
    key = world.recipient['public_key']
    assert oap.calculate_key_id(key) == oap.calculate_key_id(key)
    assert oap.calculate_key_id(key) == 'sha256:' + hashlib.sha256(trust._b64d(key)).hexdigest()
    assert oap.calculate_key_id(key) == oap.calculate_key_id(key).lower()
    with pytest.raises(ValueError):
        oap.calculate_key_id('c2hvcnQ')


def test_canonical_json_rules():
    assert oap.canonical_json({'b': 1, 'a': [None, True, 'é']}) == '{"a":[null,true,"é"],"b":1}'.encode()
    assert oap.canonical_json({'\U0001F600': 1, '�': 2}) == '{"\U0001F600":1,"�":2}'.encode()
    assert oap.canonical_json({'a': '\n"\x1f'}) == b'{"a":"\\n\\"\\u001f"}'
    for bad in (1.5, float('nan'), 2**53, '\ud800', {1: 2}):
        with pytest.raises(ValueError):
            oap.canonical_json(bad)


def test_revocation_entry_signing_and_authority(world):
    entry = world.revoke(world.agent_id, 'agent_signing')
    assert oap.verify_revocation_entry(entry, world.revokers)['ok']
    assert not oap.verify_revocation_entry(entry, [])['ok']
    tampered = dict(entry, reason='retired')
    assert 'signature' in oap.verify_revocation_entry(tampered, world.revokers)['issues'][0]
    own = world.revoke(world.agent_id, 'agent_signing', signer=world.agent)
    checked = oap.verify_revocation_entry(own, [])
    assert checked['ok'] and checked['self_revocation']
    # X25519 keys cannot sign, so nobody can claim a Director self-revocation without trust.
    forged = world.revoke(world.agent_id, 'director_recipient', signer=world.agent)
    assert not oap.verify_revocation_entry(forged, [])['ok']
    scoped = [dict(world.revokers[0], key_types=['director_recipient'])]
    assert not oap.verify_revocation_entry(entry, scoped)['ok']


def test_revocation_list_signing_expiry_and_unknown_signer(world):
    document = world.fresh_list()
    found = oap.verify_revocation_list(document, world.revokers, now=NOW)
    assert found['ok'] and found['trusted'] and not found['expired']
    assert not oap.verify_revocation_list(dict(document, list_id='x'), world.revokers, now=NOW)['valid']
    expired = oap.verify_revocation_list(document, world.revokers, now='2026-12-01T00:00:00Z')
    assert expired['valid'] and expired['expired'] and not expired['ok']
    stranger = oap.generate_identity()
    bad = world.fresh_list([world.revoke(world.agent_id, 'agent_signing', signer=stranger)], signer=stranger)
    assert not oap.verify_revocation_list(bad, world.revokers, now=NOW)['valid']
    future = world.fresh_list(issued_at='2027-01-01T00:00:00Z', next_update='2027-02-01T00:00:00Z')
    assert not oap.verify_revocation_list(future, world.revokers, now=NOW)['valid']


def test_duplicate_entries_latest_wins(world):
    first = world.revoke(world.agent_id, 'agent_signing', revoked_at='2026-01-01T00:00:00Z')
    second = oap.create_revocation_entry(world.agent_id, 'agent_signing', 'retired',
                                         world.authority['_private'], revoked_at='2026-02-01T00:00:00Z')
    document = world.fresh_list([first, second])
    assert [entry['reason'] for entry in document['entries']] == ['retired']
    state = oap.build_revocation_state([world.fresh_list([first]), world.fresh_list([second])],
                                       world.revokers, now=NOW)
    assert oap.check_key_revocation(world.agent_id, 'agent_signing', state)['reason'] == 'retired'
    assert oap.check_key_revocation(world.agent_id, 'director_recipient', state) is None


def test_revoked_agent_key_is_rejected(world):
    path = world.package()
    assert world.verify(path)['ok']
    result = world.verify(path, revocation_lists=[world.fresh_list([world.revoke(world.agent_id, 'agent_signing')])])
    assert not result['ok'] and result['revocation_ok'] is False
    assert result['signature_valid'] and result['integrity_ok'] and result['agent_known']
    assert result['revoked_keys'][0]['key_id'] == world.agent_id
    # Backdating cannot help: revocation applies regardless of package issue time.
    old = world.revoke(world.agent_id, 'agent_signing', revoked_at='2000-01-01T00:00:00Z')
    assert not world.verify(path, revocation_lists=[world.fresh_list([old])])['ok']


def test_revoked_director_key_is_rejected(world):
    path = world.package()
    result = world.verify(path, revocation_lists=[
        world.fresh_list([world.revoke(world.recipient_id, 'director_recipient')])])
    assert not result['ok']
    assert result['revoked_keys'][0]['key_type'] == 'director_recipient'


def test_missing_lists_under_each_policy(world):
    path = world.package()
    strict = world.verify(path, revocation_lists=[])
    assert not strict['ok'] and strict['revocation_ok'] is False
    best = world.verify(path, revocation_lists=[], revocation_policy='best_effort')
    assert best['ok'] and best['revocation_ok'] is None and best['warnings']
    ignored = world.verify(path, revocation_lists=[], revocation_policy='ignore')
    assert ignored['ok'] and ignored['revocation_ok'] is None and not ignored['warnings']
    with pytest.raises(ValueError):
        world.verify(path, revocation_policy='lenient')


def test_default_policy_follows_revoker_configuration(world):
    path = world.package()
    agents = [world.agent['public_key']]
    quiet = oap.verify_package(path, known_agents=agents, now=NOW)
    assert quiet['ok'] and quiet['revocation_ok'] is None and quiet['warnings'] == []
    assert quiet['revocation_policy'] == 'best_effort'
    assert oap.verify_package(path, known_agents=agents, known_revokers=[], now=NOW)['warnings'] == []
    assert oap.verify_package(path, now=NOW)['ok'] is False  # Agent trust is still required.
    target = world.root / 'target'
    assert oap.import_actor(path, target, known_agents=agents)['ok']
    assert oap.open_asset_buffer(path, 'identity/ref.bin', world.recipient['_private'],
                                 known_agents=agents) == b'private pixels'
    # Revocations still apply, and asking for best_effort by name turns the warnings on.
    own = world.fresh_list([world.revoke(world.agent_id, 'agent_signing', signer=world.agent)], signer=world.agent)
    assert not oap.verify_package(path, known_agents=agents, revocation_lists=[own], now=NOW)['ok']
    assert oap.verify_package(path, known_agents=agents, revocation_policy='best_effort', now=NOW)['warnings']
    tampered = dict(world.fresh_list(signer=world.agent), list_id='changed')
    assert not oap.verify_package(path, known_agents=agents, revocation_lists=[tampered], now=NOW)['ok']
    # Naming a revoker makes a current list mandatory; a manifest cannot opt out.
    strict = oap.verify_package(path, known_agents=agents, known_revokers=world.revokers, now=NOW)
    assert not strict['ok'] and strict['revocation_policy'] == 'strict'
    assert world.verify(path)['revocation_ok'] is True


def test_expired_lists_and_sticky_revocation(world):
    path = world.package()
    stale = world.fresh_list(next_update='2026-10-02T00:00:00Z')
    assert not world.verify(path, revocation_lists=[stale])['ok']
    # An expired list fails strict even beside a current one.
    assert not world.verify(path, revocation_lists=[stale, world.fresh_list()])['ok']
    best = world.verify(path, revocation_lists=[stale], revocation_policy='best_effort')
    assert best['ok'] and best['warnings']
    revoked = world.fresh_list([world.revoke(world.agent_id, 'agent_signing')],
                               next_update='2026-10-02T00:00:00Z')
    assert not world.verify(path, revocation_lists=[revoked], revocation_policy='best_effort')['ok']


def test_invalid_list_fails_even_best_effort(world):
    path = world.package()
    bad = dict(world.fresh_list(), list_id='tampered')
    assert not world.verify(path, revocation_lists=[bad], revocation_policy='best_effort')['ok']
    stranger = oap.generate_identity()
    unknown = world.fresh_list([world.revoke(world.agent_id, 'director_recipient', signer=stranger)],
                               signer=stranger)
    assert not world.verify(path, revocation_lists=[unknown], revocation_policy='best_effort')['ok']


def test_compromised_key_cannot_vouch_for_itself(world):
    own_list = world.fresh_list(signer=world.agent)
    path = world.package(revocation_metadata={'policy': 'embedded', 'lists': [own_list]})
    assert not world.verify(path, revocation_lists=[])['ok']
    best = world.verify(path, revocation_lists=[], revocation_policy='best_effort')
    assert best['ok'] and best['revocation_ok'] is None
    # A self-signed list may still revoke.
    own = world.fresh_list([world.revoke(world.agent_id, 'agent_signing', signer=world.agent)], signer=world.agent)
    assert not world.verify(world.package('r.oap'), revocation_lists=[own, world.fresh_list()])['ok']


def test_manifest_policy_cannot_weaken_receiver(world):
    path = world.package(revocation_metadata={'policy': 'ignore'})
    assert not world.verify(path, revocation_lists=[])['ok']
    revoked = world.fresh_list([world.revoke(world.agent_id, 'agent_signing')])
    assert not world.verify(path, revocation_lists=[revoked])['ok']


def test_revoked_revoker_loses_trust(world):
    second = oap.generate_identity()
    revokers = world.revokers + [{'key_id': oap.calculate_key_id(second['public_key']),
                                  'public_key': second['public_key']}]
    fall = world.fresh_list([world.revoke(world.authority_id, 'agent_signing', signer=second)], signer=second)
    forged = world.fresh_list([world.revoke(world.recipient_id, 'director_recipient')])
    state = oap.build_revocation_state([fall, forged], revokers, now=NOW)
    assert oap.check_key_revocation(world.recipient_id, 'director_recipient', state) is None
    assert any('revoked revoker' in issue for issue in state['issues'])
    # A list mixing a revoker's self-revocation with other entries must not lose them silently.
    path = world.package()
    mixed = world.fresh_list([world.revoke(world.authority_id, 'agent_signing'),
                              world.revoke(world.agent_id, 'agent_signing')])
    current = world.fresh_list(signer=second)
    for policy in ('strict', 'best_effort'):
        assert not world.verify(path, known_revokers=revokers, revocation_lists=[mixed, current],
                                revocation_policy=policy)['ok']
    # A revoker that only retires itself leaves other authorities working.
    retired = world.fresh_list([world.revoke(world.authority_id, 'agent_signing', signer=world.authority)],
                               signer=world.authority)
    assert world.verify(path, known_revokers=revokers, revocation_lists=[retired, current])['ok']
    only = oap.build_revocation_state([world.fresh_list(), world.fresh_list(
        [world.revoke(world.authority_id, 'agent_signing', signer=world.authority)])], world.revokers, now=NOW)
    assert not only['covered']


def test_attestation_verification(world):
    document = world.attest()
    assert oap.verify_attestation(document, world.issuers, now=NOW)['ok']
    assert not oap.verify_attestation(dict(document, id='x'), world.issuers, now=NOW)['ok']
    assert 'unknown' in oap.verify_attestation(document, [], now=NOW)['issues'][0]
    assert not oap.verify_attestation(document, world.issuers, actor_id='other', now=NOW)['ok']
    expired = world.attest(expires_at='2026-10-02T00:00:00Z')
    assert 'expired' in oap.verify_attestation(expired, world.issuers, now=NOW)['issues'][0]
    assert oap.verify_attestation(expired, world.issuers, allow_expired=True, now=NOW)['ok']
    outside = world.attest(claims={'consent_scope': 'festival'})
    assert 'consent_scope' in oap.verify_attestation(outside, world.issuers, now=NOW)['issues'][0]
    bound = world.attest(package_hash='sha256:' + 'a' * 64)
    open_result = oap.verify_attestation(bound, world.issuers, now=NOW)
    assert open_result['ok'] and open_result['package_bound'] and not open_result['package_binding_checked']
    assert not oap.verify_attestation(bound, world.issuers, 'sha256:' + 'b' * 64, now=NOW)['ok']
    state = oap.build_revocation_state([world.fresh_list([world.revoke(world.issuer_id, 'agent_signing')])],
                                       world.revokers, now=NOW)
    assert 'revoked' in oap.verify_attestation(document, world.issuers, revocation_state=state, now=NOW)['issues'][0]


def test_attestation_refuses_private_material(world):
    for claims in ({'private_key': 'x'}, {'nested': [{'Secret': 'x'}]}, {'seed': 'x'},
                   {'representation': world.issuer['_private']}):
        with pytest.raises(ValueError, match='private'):
            world.attest(claims=claims)
    with pytest.raises(ValueError):
        world.attest(claims={})


def test_embedded_attestation_policies_and_binding(world):
    document = world.attest(agent_key_id=world.agent_id)
    path = world.package(attestations=[document])
    assert world.verify(path)['attestations_ok'] is True
    unknown = world.verify(path, attestation_issuers=[])
    assert not unknown['ok'] and unknown['failed_attestations'][0]['file'].startswith('attestations/')
    assert world.verify(path, attestation_issuers=[], attestation_policy='ignore')['ok']
    assert not world.verify(path, require_package_bound_attestations=True)['ok']
    plain = world.package('plain.oap')
    assert world.verify(plain)['ok']
    assert not world.verify(plain, attestation_policy='require')['ok']
    with pytest.raises(ValueError):
        world.verify(plain, attestation_policy='ignore', require_package_bound_attestations=True)
    other_agent = world.attest(agent_key_id='sha256:' + 'c' * 64)
    assert not world.verify(world.package('o.oap', attestations=[other_agent]))['ok']
    other_actor = world.attest(actor_id='someone-else')
    assert not world.verify(world.package('a.oap', attestations=[other_actor]))['ok']


def test_package_bound_attach_flow_preserves_sealed_bytes(world):
    path = world.package()
    package_hash = oap.package_content_hash(path)
    document = world.attest(package_hash=package_hash)
    attached = world.root / 'attached.oap'
    oap.attach_attestations(path, attached, world.agent['_private'], [document])
    assert oap.package_content_hash(attached) == package_hash
    assert world.verify(attached, require_package_bound_attestations=True)['ok']
    with zipfile.ZipFile(path) as a, zipfile.ZipFile(attached) as b:
        sealed = [n for n in a.namelist() if n.startswith('sealed/')]
        assert sealed and all(a.read(n) == b.read(n) for n in sealed)
    assert oap.open_asset_buffer(attached, 'identity/ref.bin', world.recipient['_private'],
                                 known_agents=[world.agent['public_key']], known_revokers=world.revokers,
                                 revocation_lists=[world.fresh_list()], attestation_issuers=world.issuers,
                                 now=NOW) == b'private pixels'
    wrong = world.attest(package_hash='sha256:' + 'd' * 64)
    bad = world.root / 'bad.oap'
    oap.attach_attestations(path, bad, world.agent['_private'], [wrong])
    assert not world.verify(bad)['ok']
    with pytest.raises(ValueError):
        oap.attach_attestations(path, world.root / 'x.oap', oap.generate_identity()['_private'], [document])


@pytest.mark.parametrize('prefix', ['attestations/', 'revocations/'])
def test_trust_document_hash_and_inventory(world, prefix):
    path = world.package(attestations=[world.attest()],
                         revocation_metadata={'policy': 'embedded', 'lists': [world.fresh_list()]})
    assert world.verify(path)['ok']
    with zipfile.ZipFile(path) as archive:
        name = next(n for n in archive.namelist() if n.startswith(prefix))
    changed, missing, stray = (world.root / n for n in ('changed.oap', 'missing.oap', 'stray.oap'))
    rewrite(path, changed, {name: b'{}'})
    rewrite(path, missing, drop=[name])
    rewrite(path, stray)
    with zipfile.ZipFile(stray, 'a') as archive:
        archive.writestr(prefix + 'extra.json', b'{}')
    for bad in (changed, missing, stray):
        for policy in ('strict', 'ignore'):
            result = world.verify(bad, revocation_policy=policy, attestation_policy='ignore')
            assert not result['ok'] and not result['integrity_ok'], (bad, policy)


def test_embedded_policy_needs_a_list_and_rejects_invalid(world):
    with pytest.raises(ValueError, match='at least one'):
        world.package(revocation_metadata={'policy': 'embedded'})
    invalid = dict(world.fresh_list(), list_id='tampered')
    path = world.package(revocation_metadata={'policy': 'embedded', 'lists': [invalid]})
    assert not world.verify(path)['ok']


def test_reserved_paths_cannot_be_assets(world):
    manifest = json.loads((world.root / 'manifest.json').read_text())
    manifest['assets'][0]['file'] = 'attestations/face.txt'
    (world.root / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='reserved'):
        world.package()


def test_import_and_decryption_enforce_policy(world):
    path = world.package()
    revoked = world.fresh_list([world.revoke(world.agent_id, 'agent_signing')])
    director = world.fresh_list([world.revoke(world.recipient_id, 'director_recipient')])
    base = {'known_agents': [world.agent['public_key']], 'known_revokers': world.revokers, 'now': NOW}
    target = world.root / 'target'
    failed = oap.import_actor(path, target, revocation_lists=[revoked], **base)
    assert not failed['ok'] and failed['revoked_keys'] and not target.exists()
    assert not oap.import_actor(path, target, **base)['ok'] and not target.exists()
    for document in (revoked, director):
        with pytest.raises(ValueError, match='revoked'):
            oap.open_asset_buffer(path, 'identity/ref.bin', world.recipient['_private'],
                                  revocation_lists=[document], **base)
    with pytest.raises(ValueError):
        oap.open_asset_buffer(path, 'identity/ref.bin', world.recipient['_private'], **base)
    attested = world.package('att.oap', attestations=[world.attest()])
    with pytest.raises(ValueError, match='unknown attestation issuer'):
        oap.open_asset_buffer(attested, 'identity/ref.bin', world.recipient['_private'],
                              revocation_lists=[world.fresh_list()], **base)
    done = oap.import_actor(path, target, revocation_lists=[world.fresh_list()], **base)
    assert done['ok'] and not (target / 'identity/ref.bin').exists()
    assert list((target / 'sealed').glob('*.bin'))


def test_v04_needs_explicit_acceptance_and_still_checks_revocation(world):
    path = downgrade_to_v04(world)
    assert not world.verify(path)['ok']
    assert world.verify(path, allow_legacy_manifest=True)['ok']
    revoked = world.fresh_list([world.revoke(world.agent_id, 'agent_signing')])
    assert not world.verify(path, allow_legacy_manifest=True, revocation_lists=[revoked])['ok']
    target = world.root / 'old'
    assert oap.import_actor(path, target, known_agents=[world.agent['public_key']], revocation_policy='ignore',
                            allow_legacy_manifest=True)['ok']
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read('manifest.json'))
    manifest['attestations'] = []
    oap.sign_manifest(manifest, world.agent['_private'])
    carrying = world.root / 'carrying.oap'
    rewrite(path, carrying, {'manifest.json': json.dumps(manifest).encode()})
    assert not world.verify(carrying, allow_legacy_manifest=True)['ok']


def test_v05_signature_cannot_be_replayed_as_v04(world):
    path = world.package()
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read('manifest.json'))
    manifest['oap_version'] = '0.4.0'
    downgraded = world.root / 'downgraded.oap'
    rewrite(path, downgraded, {'manifest.json': json.dumps(manifest).encode()})
    assert not world.verify(downgraded, allow_legacy_manifest=True)['signature_valid']


def test_migration_from_v04(world):
    path = downgrade_to_v04(world)
    out = world.root / 'migrated.oap'
    document = world.attest()
    oap.migrate_v04_package(path, out, world.agent['_private'], attestations=[document],
                            revocation_metadata={'policy': 'embedded', 'lists': [world.fresh_list()]})
    result = world.verify(out, revocation_lists=[])
    assert result['ok'] and result['revocation_ok'] and result['attestations_ok']
    with zipfile.ZipFile(path) as a, zipfile.ZipFile(out) as b:
        assert json.loads(b.read('manifest.json'))['oap_version'] == '0.5.0'
        sealed = [n for n in a.namelist() if n.startswith('sealed/')]
        assert sealed and all(a.read(n) == b.read(n) for n in sealed)
    assert oap.open_asset_buffer(out, 'identity/ref.bin', world.recipient['_private'],
                                 known_agents=[world.agent['public_key']], known_revokers=world.revokers,
                                 attestation_issuers=world.issuers, now=NOW) == b'private pixels'
    with pytest.raises(ValueError):
        oap.migrate_v04_package(path, world.root / 'y.oap', oap.generate_identity()['_private'])
    with pytest.raises(ValueError):
        oap.migrate_v04_package(out, world.root / 'z.oap', world.agent['_private'])


class FakeResponse:
    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.raw[:limit]


def test_remote_lists_fetch_only_when_enabled(world, monkeypatch):
    calls = []
    served = json.dumps(world.fresh_list()).encode()

    def opener(url):
        calls.append(url)
        return FakeResponse(served)

    monkeypatch.setattr(trust, '_open_url', opener)
    path = world.package(revocation_metadata={'policy': 'remote_opt_in',
                                              'endpoints': ['https://revocations.example/list.json']})
    assert not world.verify(path, revocation_lists=[])['ok']
    assert calls == []
    assert world.verify(path, revocation_lists=[], allow_remote_revocation=True)['ok']
    assert calls == ['https://revocations.example/list.json']

    def offline(url):
        raise urllib.error.URLError('offline')

    monkeypatch.setattr(trust, '_open_url', offline)
    failed = world.verify(path, revocation_lists=[], allow_remote_revocation=True)
    assert not failed['ok'] and any('unavailable' in note for note in failed['warnings'])


def test_remote_endpoint_count_is_capped(world, monkeypatch):
    calls = []

    def offline(url):
        calls.append(url)
        raise urllib.error.URLError('offline')

    monkeypatch.setattr(trust, '_open_url', offline)
    endpoints = [f'https://revocations.example/{index}.json' for index in range(20)]
    path = world.package(revocation_metadata={'policy': 'remote_opt_in', 'endpoints': endpoints})
    result = world.verify(path, revocation_lists=[], allow_remote_revocation=True)
    assert not result['ok'] and len(calls) == trust.MAX_REMOTE_ENDPOINTS


def test_fractional_seconds_are_compared(world):
    document = world.attest(expires_at='2026-10-30T12:00:00.900Z')
    assert oap.verify_attestation(document, world.issuers, now='2026-10-30T12:00:00.100Z')['ok']
    assert not oap.verify_attestation(document, world.issuers, now='2026-10-30T12:00:01Z')['ok']


def test_remote_fetch_rejects_plain_http_and_large_documents(monkeypatch):
    with pytest.raises(ValueError, match='https'):
        trust.fetch_revocation_list('http://revocations.example/list.json')
    monkeypatch.setattr(trust, '_open_url', lambda url: FakeResponse(b' ' * (trust.MAX_REMOTE_DOCUMENT + 1)))
    with pytest.raises(ValueError, match='size'):
        trust.fetch_revocation_list('https://revocations.example/list.json')
    handler = trust._RefuseRedirect()
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(None, None, 302, 'Found', {}, 'http://elsewhere.example/')


def test_schema_constrains_endpoints_and_documents(world):
    manifest = oap.new_manifest('lead')
    manifest['revocation'] = {'policy': 'remote_opt_in', 'endpoints': ['http://plain.example']}
    assert not oap.validate_document(manifest)['ok']
    assert oap.validate_document(world.fresh_list())['ok']
    assert oap.validate_document(world.attest())['ok']
    assert oap.validate_document(world.revoke(world.agent_id, 'agent_signing'))['ok']
    assert not oap.validate_document(dict(world.attest(), extra=1))['ok']


def test_cli_round_trip(world, capsys):
    root = world.root
    def write(name, value):
        (root / name).write_text(json.dumps(value))
        return str(root / name)
    agent_key = write('agent.private.json', world.agent)
    authority_key = write('authority.private.json', world.authority)
    issuer_key = write('issuer.private.json', world.issuer)
    recipient_public = write('recipient.public.json', {'public_key': world.recipient['public_key']})
    agents = write('agents.json', [world.agent['public_key']])
    revokers = write('revokers.json', world.revokers)
    issuers = write('issuers.json', world.issuers)
    claims = write('claims.json', {'representation': 'example-agency'})
    full, attached, listed = str(root / 'full.oap'), str(root / 'attached.oap'), str(root / 'list.json')
    entry, att = str(root / 'entry.json'), str(root / 'att.json')
    assert main(['package', '--source', str(root), '--out', full, '--tier', 'full',
                 '--sign-key-file', agent_key, '--recipient-key', recipient_public]) == 0
    capsys.readouterr()
    assert main(['package-hash', '--oap', full]) == 0
    package_hash = json.loads(capsys.readouterr().out)['package_hash']
    assert main(['attest', '--subject-actor-id', 'lead', '--claims-file', claims, '--sign-key-file', issuer_key,
                 '--package-hash', package_hash, '--out', att]) == 0
    assert main(['verify-attestation', '--attestation', att, '--known-issuers', issuers, '--package', full]) == 0
    assert main(['attach-attestation', '--oap', full, '--attestation', att, '--sign-key-file', agent_key,
                 '--out', attached]) == 0
    assert main(['create-revocation-list', '--list-id', 'urn:l', '--entries', write('none.json', []),
                 '--sign-key-file', authority_key, '--out', listed]) == 0
    assert main(['verify-revocation-list', '--list', listed, '--known-revokers', revokers]) == 0
    trust_flags = ['--known-agents', agents, '--known-revokers', revokers, '--attestation-issuers', issuers]
    assert main(['verify', '--oap', attached, '--revocation-lists', listed, '--require-package-bound-attestations',
                 *trust_flags]) == 0
    assert main(['verify', '--oap', attached, *trust_flags]) == 1
    capsys.readouterr()
    assert main(['verify', '--oap', full, '--known-agents', agents]) == 0
    assert json.loads(capsys.readouterr().out)['warnings'] == []
    capsys.readouterr()
    assert main(['verify', '--oap', attached, '--revocation-lists', str(root / 'absent.json'), *trust_flags]) == 1
    assert json.loads(capsys.readouterr().out)['ok'] is False
    assert main(['revoke-key', '--key-id', world.agent_id, '--key-type', 'agent_signing', '--reason', 'compromised',
                 '--sign-key-file', authority_key, '--out', entry]) == 0
    assert main(['create-revocation-list', '--list-id', 'urn:l', '--entries', entry,
                 '--sign-key-file', authority_key, '--out', listed]) == 0
    capsys.readouterr()
    assert main(['verify', '--oap', attached, '--revocation-lists', listed, *trust_flags]) == 1
    assert json.loads(capsys.readouterr().out)['revoked_keys'][0]['key_id'] == world.agent_id
    assert main(['import', '--oap', attached, '--target', str(root / 'in'), '--revocation-lists', listed,
                 *trust_flags]) == 1
    assert not (root / 'in').exists()
    output = capsys.readouterr().out
    for secret in (world.agent['_private'], world.authority['_private'], world.issuer['_private']):
        assert secret not in output


def test_migrate_cli_for_v04_needs_no_recipient(world, capsys):
    path = downgrade_to_v04(world)
    key = world.root / 'agent.key'
    key.write_text(world.agent['_private'])
    out = world.root / 'cli-migrated.oap'
    assert main(['migrate', '--oap', str(path), '--out', str(out), '--sign-key-file', str(key)]) == 0
    assert world.verify(out)['ok']


def _seed_key(hex_seed):
    return trust._b64e(bytes.fromhex(hex_seed))


def test_fixed_vectors():
    vector = json.loads((VECTORS / 'revocation' / 'list.json').read_text())
    key = _seed_key(vector['signer_seed_hex'])
    entry = oap.create_revocation_entry(vector['entry']['key_id'], vector['entry']['key_type'],
                                        vector['entry']['reason'], key, revoked_at=vector['entry']['revoked_at'])
    assert entry == vector['entry']
    assert trust._payload(trust.ENTRY_DOMAIN, entry).hex() == vector['entry_payload_hex']
    document = oap.create_revocation_list(vector['list']['list_id'], [entry], key,
                                          issued_at=vector['list']['issued_at'],
                                          next_update=vector['list']['next_update'])
    assert document == vector['list']
    assert trust._payload(trust.LIST_DOMAIN, document).hex() == vector['list_payload_hex']
    assert oap.verify_revocation_list(document, [{'key_id': document['signer']['key_id'],
                                                  'public_key': document['signer']['public_key']}],
                                      now=vector['list']['issued_at'])['ok']

    vector = json.loads((VECTORS / 'attestation' / 'attestation.json').read_text())
    source = vector['attestation']
    document = oap.create_attestation(source['subject']['actor_id'], source['claims'],
                                      _seed_key(vector['issuer_seed_hex']), issuer_name=source['issuer']['name'],
                                      package_hash=source['subject']['package_hash'],
                                      agent_key_id=source['subject']['agent_key_id'],
                                      attestation_id=source['id'], issued_at=source['issued_at'],
                                      expires_at=source['expires_at'])
    assert document == source
    assert trust._payload(trust.ATTESTATION_DOMAIN, document).hex() == vector['payload_hex']

    vector = json.loads((VECTORS / 'manifests' / 'manifest.json').read_text())
    manifest = vector['manifest']
    assert manifest_payload(manifest).hex() == vector['payload_hex']
    assert oap.verify_signature(manifest)[0]
    unsigned = copy.deepcopy(manifest)
    unsigned['signature']['value'] = None
    assert oap.sign_manifest(unsigned, _seed_key(vector['agent_seed_hex'])) == manifest

    vector = json.loads((VECTORS / 'packages' / 'content_hash.json').read_text())
    assert oap.package_content_hash(vector['manifest']) == vector['package_hash']
    assert oap.package_content_hash(vector['manifest_with_attestation']) == vector['package_hash']
