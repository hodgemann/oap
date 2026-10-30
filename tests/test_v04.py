import copy
import base64
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

import oap
from oap.core import main
from oap.core import _canonical
from oap.agreements import _payload
from oap.v04 import verify_package as verify_v04


def make_source(tmp_path, payload=b'private actor pixels'):
    agent = oap.generate_identity()
    recipient = oap.generate_recipient_identity()
    manifest = oap.new_manifest('lead')
    manifest['agent']['public_key'] = agent['public_key']
    manifest['identity']['did'] = agent['did'] + '#lead'
    manifest['assets'] = [
        {'file': 'portfolio/face.txt', 'clearance': 'public', 'role': 'headshot'},
        {'file': 'identity/ref.bin', 'clearance': 'cast', 'role': 'reference_sheet'},
    ]
    (tmp_path / 'portfolio').mkdir()
    (tmp_path / 'identity').mkdir()
    (tmp_path / 'portfolio/face.txt').write_bytes(b'public actor pixels')
    (tmp_path / 'identity/ref.bin').write_bytes(payload)
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    return agent, recipient, manifest


def rewrite_archive(source, target, edits=None, extras=None):
    edits, extras = edits or {}, extras or {}
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, 'w') as changed:
        for info in original.infolist():
            changed.writestr(info, edits.get(info.filename, original.read(info.filename)))
        for name, data in extras.items():
            changed.writestr(name, data)


def test_encrypted_handover_and_import(tmp_path):
    data = os.urandom(2 * 1024 * 1024 + 25)
    agent, recipient, _ = make_source(tmp_path, data)
    portfolio = tmp_path / 'portfolio.oap'
    full = tmp_path / 'full.oap'
    oap.package_actor(str(tmp_path), str(portfolio), 'portfolio', agent['_private'])
    oap.package_actor(str(tmp_path), str(full), 'full', agent['_private'],
                      [recipient['public_key']])
    with zipfile.ZipFile(portfolio) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        assert archive.namelist() == ['manifest.json', 'portfolio/face.txt']
        assert manifest['assets'][1]['sha256'] is None
        assert 'sealed' not in manifest['assets'][1]
    with zipfile.ZipFile(full) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        assert 'identity/ref.bin' not in archive.namelist()
        assert len([name for name in archive.namelist() if name.startswith('sealed/')]) == 1
        assert data not in full.read_bytes()
        assert manifest['protection']['tier'] == 1
    assert not oap.verify_package(full, revocation_policy='ignore')['ok']
    assert oap.verify_package(full, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    assert oap.verify_package(full, allow_untrusted=True, revocation_policy='ignore')['integrity_ok']
    wrong = oap.generate_recipient_identity()
    with pytest.raises(ValueError, match='not authorized'):
        oap.open_asset_buffer(full, 'identity/ref.bin', wrong['_private'],
                              known_agents=[agent['public_key']], revocation_policy='ignore')
    assert oap.open_asset_buffer(full, 'identity/ref.bin', recipient['_private'],
                                 known_agents=[agent['public_key']], revocation_policy='ignore') == data
    target = tmp_path / 'imported'
    assert oap.import_actor(full, target, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    assert not (target / 'identity/ref.bin').exists()
    assert len(list((target / 'sealed').glob('*.bin'))) == 1
    assert not oap.import_actor(full, target, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']


def test_missing_wrong_or_duplicate_recipient(tmp_path):
    agent, recipient, _ = make_source(tmp_path)
    with pytest.raises(ValueError, match='recipient'):
        oap.package_actor(str(tmp_path), str(tmp_path / 'full.oap'), 'full', agent['_private'])
    with pytest.raises(ValueError, match='duplicate recipient'):
        oap.package_actor(str(tmp_path), str(tmp_path / 'full.oap'), 'full', agent['_private'],
                          [recipient['public_key'], recipient['public_key']])
    with pytest.raises(ValueError, match='Agent signing key'):
        oap.package_actor(str(tmp_path), str(tmp_path / 'full.oap'), 'full',
                          oap.generate_identity()['_private'], [recipient['public_key']])


@pytest.mark.parametrize('attack', ['extra', 'duplicate', 'symlink', 'traversal', 'missing', 'ciphertext', 'manifest'])
def test_archive_attacks_fail(tmp_path, attack):
    agent, recipient, _ = make_source(tmp_path)
    original = tmp_path / 'full.oap'
    oap.package_actor(str(tmp_path), str(original), 'full', agent['_private'],
                      [recipient['public_key']])
    bad = tmp_path / 'bad.oap'
    with zipfile.ZipFile(original) as archive:
        sealed = next(name for name in archive.namelist() if name.startswith('sealed/'))
        manifest = json.loads(archive.read('manifest.json'))
    if attack == 'missing':
        with zipfile.ZipFile(original) as src, zipfile.ZipFile(bad, 'w') as out:
            out.writestr('manifest.json', src.read('manifest.json'))
    elif attack == 'duplicate':
        with zipfile.ZipFile(original) as src, zipfile.ZipFile(bad, 'w') as out:
            for name in src.namelist():
                out.writestr(name, src.read(name))
            out.writestr('manifest.json', src.read('manifest.json'))
    elif attack == 'symlink':
        link = zipfile.ZipInfo('link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(original) as src, zipfile.ZipFile(bad, 'w') as out:
            for name in src.namelist():
                out.writestr(name, src.read(name))
            out.writestr(link, 'identity/ref.bin')
    elif attack == 'traversal':
        rewrite_archive(original, bad, extras={'../escape': b'evil'})
    elif attack == 'extra':
        rewrite_archive(original, bad, extras={'stray.txt': b'evil'})
    elif attack == 'ciphertext':
        rewrite_archive(original, bad, edits={sealed: b'changed'})
    else:
        manifest['issued_at'] = '2026-01-01T00:00:00Z'
        rewrite_archive(original, bad, edits={'manifest.json': json.dumps(manifest).encode()})
    checked = oap.verify_package(bad, known_agents=[agent['public_key']], revocation_policy='ignore')
    assert not checked['ok'], attack
    assert not oap.import_actor(bad, tmp_path / 'target',
                                known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    assert not (tmp_path / 'target').exists()


def test_sealed_stream_authentication_and_limits(tmp_path):
    agent, recipient, _ = make_source(tmp_path)
    full = tmp_path / 'full.oap'
    oap.package_actor(str(tmp_path), str(full), 'full', agent['_private'],
                      [recipient['public_key']])
    assert not verify_v04(full, known_agents=[agent['public_key']], max_members=1, revocation_policy='ignore')['ok']
    assert not verify_v04(full, known_agents=[agent['public_key']], max_member=10, revocation_policy='ignore')['ok']
    assert not verify_v04(full, known_agents=[agent['public_key']], max_total=10, revocation_policy='ignore')['ok']
    with pytest.raises(ValueError, match='memory limit'):
        oap.open_asset_buffer(full, 'identity/ref.bin', recipient['_private'],
                              known_agents=[agent['public_key']], max_bytes=4, revocation_policy='ignore')
    with zipfile.ZipFile(full) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        sealed = manifest['assets'][1]['sealed']['path']
        ciphertext = archive.read(sealed)
    # A signer can bind corrupt ciphertext, but recipient decryption must still fail.
    manifest['assets'][1]['sealed']['sha256'] = oap.core.sha256_bytes(ciphertext[:-1])
    manifest['assets'][1]['sealed']['size'] = len(ciphertext) - 1
    oap.sign_manifest(manifest, agent['_private'])
    bad = tmp_path / 'truncated.oap'
    rewrite_archive(full, bad, edits={'manifest.json': json.dumps(manifest).encode(),
                                      sealed: ciphertext[:-1]})
    assert oap.verify_package(bad, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    with pytest.raises(ValueError, match='truncated'):
        oap.open_asset_buffer(bad, 'identity/ref.bin', recipient['_private'],
                              known_agents=[agent['public_key']], revocation_policy='ignore')


def test_patch_version_and_duplicate_json_keys(tmp_path):
    agent, recipient, _ = make_source(tmp_path)
    original = tmp_path / 'full.oap'
    oap.package_actor(str(tmp_path), str(original), 'full', agent['_private'],
                      [recipient['public_key']])
    with zipfile.ZipFile(original) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        raw = archive.read('manifest.json')
    manifest['oap_version'] = '0.5.9'
    oap.sign_manifest(manifest, agent['_private'])
    patch = tmp_path / 'patch.oap'
    rewrite_archive(original, patch, edits={'manifest.json': json.dumps(manifest).encode()})
    assert oap.verify_package(patch, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    duplicated = raw.replace(b'"issued_at":', b'"issued_at": "2026-01-01T00:00:00Z", "issued_at":', 1)
    bad = tmp_path / 'duplicate-key.oap'
    rewrite_archive(original, bad, edits={'manifest.json': duplicated})
    assert not oap.verify_package(bad, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']


def test_cli_keys_and_package(tmp_path, capsys):
    agent, recipient, _ = make_source(tmp_path)
    agent_file, agent_public = tmp_path / 'agent.private.json', tmp_path / 'agent.public.json'
    recipient_file, recipient_public = tmp_path / 'recipient.private.json', tmp_path / 'recipient.public.json'
    assert main(['identity', '--private-out', str(agent_file),
                 '--public-out', str(agent_public)]) == 0
    assert main(['recipient-key', '--private-out', str(recipient_file),
                 '--public-out', str(recipient_public)]) == 0
    assert agent_file.stat().st_mode & 0o777 == 0o600
    assert recipient_file.stat().st_mode & 0o777 == 0o600
    assert '_private' not in agent_public.read_text()
    assert '_private' not in recipient_public.read_text()
    assert main(['package', '--source', str(tmp_path), '--out', str(tmp_path / 'bad.oap'),
                 '--tier', 'full', '--sign-key-file', str(agent_file),
                 '--recipient-key', str(recipient_file)]) == 1
    with pytest.raises(SystemExit):
        main(['identity', '--private-out', str(agent_file),
              '--public-out', str(agent_public)])
    assert agent_file.read_text().find('"_private"') > 0
    assert agent['_private'] not in capsys.readouterr().out
    source = json.loads((tmp_path / 'manifest.json').read_text())
    source['agent']['public_key'] = json.loads(agent_file.read_text())['public_key']
    (tmp_path / 'manifest.json').write_text(json.dumps(source))
    output = tmp_path / 'cli.oap'
    assert main(['package', '--source', str(tmp_path), '--out', str(output),
                 '--tier', 'full', '--sign-key-file', str(agent_file),
                 '--recipient-key', str(recipient_public)]) == 0
    trust = tmp_path / 'trust.json'
    trust.write_text(json.dumps([source['agent']['public_key']]))
    assert main(['verify', '--oap', str(output), '--known-agents', str(trust),
                 '--revocation-policy', 'ignore']) == 0


def test_legacy_migration_requires_resigning(tmp_path):
    agent, recipient, _ = make_source(tmp_path)
    legacy = tmp_path / 'old.oap'
    manifest = oap.new_manifest('lead')
    manifest['oap_version'] = '0.2.0'
    manifest.pop('issued_at')
    manifest.pop('bundle')
    manifest['agent']['public_key'] = agent['public_key']
    manifest['assets'] = [{'file': 'identity/ref.bin', 'clearance': 'cast',
                           'sha256': oap.core.sha256_file(tmp_path / 'identity/ref.bin')}]
    oap.sign_manifest(manifest, agent['_private'])
    with zipfile.ZipFile(legacy, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(manifest))
        archive.write(tmp_path / 'identity/ref.bin', 'identity/ref.bin')
    assert not oap.verify_package(legacy, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    assert oap.verify_package(legacy, legacy=True, strict=True, require_signature=True)['ok']
    new = tmp_path / 'migrated.oap'
    oap.migrate_legacy_package(legacy, new, agent['_private'], [recipient['public_key']],
                               known_agents=[agent['public_key']])
    assert oap.verify_package(new, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']
    assert oap.open_asset_buffer(new, 'identity/ref.bin', recipient['_private'],
                                 known_agents=[agent['public_key']], revocation_policy='ignore') == b'private actor pixels'
    agent_file, recipient_file = tmp_path / 'agent.key', tmp_path / 'recipient.pub'
    agent_file.write_text(agent['_private'])
    recipient_file.write_text(recipient['public_key'])
    migrated_cli = tmp_path / 'migrated-cli.oap'
    assert main(['migrate', '--oap', str(legacy), '--out', str(migrated_cli),
                 '--sign-key-file', str(agent_file),
                 '--recipient-key', str(recipient_file)]) == 0
    assert oap.verify_package(migrated_cli, known_agents=[agent['public_key']], revocation_policy='ignore')['ok']


def test_fixed_signing_conformance_vectors():
    vector = json.loads(Path('tests/vectors/oap_v04.json').read_text())
    manifest, call, agreement = vector['manifest'], vector['call'], vector['agreement']
    assert _canonical(manifest).hex() == vector['manifest_payload_hex']
    assert oap.verify_signature(manifest)[0]
    assert oap.document_sha256(manifest) == vector['manifest_sha256']
    assert oap.document_sha256(call) == vector['call_sha256']
    assert _payload(agreement).hex() == vector['agreement_payload_hex']
    assert oap.verify_agreement(agreement, manifest=manifest, casting_call=call)['ok']
    agent_key = base64.urlsafe_b64encode(bytes.fromhex(vector['agent_seed_hex'])).decode().rstrip('=')
    director_key = base64.urlsafe_b64encode(bytes.fromhex(vector['director_seed_hex'])).decode().rstrip('=')
    unsigned_manifest = copy.deepcopy(manifest)
    unsigned_manifest['signature']['value'] = None
    assert oap.sign_manifest(unsigned_manifest, agent_key) == manifest
    unsigned_agreement = copy.deepcopy(agreement)
    unsigned_agreement['signatures'] = {}
    signed = oap.sign_agreement(unsigned_agreement, 'agent', agent_key)
    signed = oap.sign_agreement(signed, 'director', director_key)
    assert signed == agreement


def test_schema_rejects_malformed_sealed_descriptor():
    manifest = oap.new_manifest('lead')
    manifest['assets'] = [{
        'file': 'identity/ref.bin', 'clearance': 'cast', 'sha256': None,
        'sealed': {'path': 'sealed/not-a-digest.bin', 'sha256': 'bad',
                   'size': -1, 'wraps': []},
    }]
    result = oap.validate_document(manifest)
    assert not result['ok']
    assert any('sealed' in issue for issue in result['issues'])
