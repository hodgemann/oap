import copy
import json
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import oap
from oap.core import main


def agreement_sources():
    agent, director = oap.generate_identity(), oap.generate_identity()
    manifest = oap.new_manifest('lead')
    manifest['identity']['did'] = agent['did'] + '#lead'
    manifest['agent']['public_key'] = agent['public_key']
    call = {'oap_version': '0.3.0', 'kind': 'oap.casting_call', 'call_id': 'call_1',
            'director': {'did': director['did']}, 'project': {}, 'role': {}}
    agreement = oap.new_role_agreement(manifest, call, {'amount': '150.00', 'currency': 'USD'}, 'agree_1')
    return agreement, agent, director, manifest, call


def test_schemas_and_examples():
    for path in Path('oap/schemas').glob('*.json'):
        Draft202012Validator.check_schema(json.loads(path.read_text()))
    for path in Path('examples').glob('*.json'):
        assert oap.validate_document(json.loads(path.read_text()))['ok'], path
    for version in ('0.1.9', '0.2.99', '0.3.50'):
        manifest = oap.new_manifest('lead')
        manifest['oap_version'] = version
        manifest['extension'] = {'custom': [1, 'test']}
        before = copy.deepcopy(manifest)
        assert oap.validate_document(manifest)['ok']
        assert manifest == before


@pytest.mark.parametrize('document', [None, [], {'kind': []}, {'kind': 'unknown'},
    {'kind': 'oap.actor.manifest', 'oap_version': '0.4.0', 'identity': {'actor_id': 'x'}},
    dict(oap.new_manifest('lead'), visual=[]),
    dict(oap.new_manifest('lead'), assets=[{'file': 'x', 'clearance': 'secret'}]),
    dict(oap.new_manifest('lead'), rider={'content': {'violence': 'unknown'}}),
    dict(oap.new_manifest('lead'), voice={'anchor': 'not-an-object'})])
def test_validation_malformed(document):
    result = oap.validate_document(document)
    assert not result['ok'] and all(issue.startswith('$') for issue in result['issues'])


def test_audition_clearance_roundtrip(tmp_path):
    manifest = oap.new_manifest('lead')
    agent = oap.generate_identity()
    manifest['agent']['public_key'] = agent['public_key']
    manifest['assets'] = [{'file': name + '.bin', 'clearance': name}
                          for name in ('public', 'audition', 'cast')]
    for ref in manifest['assets']:
        (tmp_path / ref['file']).write_bytes(ref['file'].encode())
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    for tier, expected in [('portfolio', {'public.bin'}),
                           ('audition', {'public.bin', 'audition.bin'}),
                           ('full', {'public.bin', 'audition.bin', 'cast.bin'})]:
        archive = tmp_path / f'{tier}.oap'
        result = oap.package_actor(str(tmp_path), str(archive), tier, agent['_private'])
        assert set(result['included']) == expected | {'manifest.json'}
        assert oap.verify_package(archive, strict=True, require_signature=True)['ok']
        assert oap.import_actor(archive, str(tmp_path / tier))['ok']
        with zipfile.ZipFile(archive) as zf:
            refs = json.loads(zf.read('manifest.json'))['assets']
            assert all(ref['sha256'] for ref in refs)
    assert main(['package', '--source', str(tmp_path), '--out', str(tmp_path / 'cli.oap'),
                 '--tier', 'audition']) == 0


def test_agreement_workflow_and_bindings():
    draft, agent, director, manifest, call = agreement_sources()
    assert oap.validate_document(draft)['ok']
    assert not oap.verify_agreement(draft)['ok']
    for first, second in [('agent', 'director'), ('director', 'agent')]:
        keys = {'agent': agent['_private'], 'director': director['_private']}
        partial = oap.sign_agreement(draft, first, keys[first])
        assert draft['signatures'] == {}
        assert oap.verify_agreement(partial, require_both=False)['ok']
        assert not oap.verify_agreement(partial)['ok']
        signed = oap.sign_agreement(partial, second, keys[second])
        result = oap.verify_agreement(signed, manifest=manifest, casting_call=call)
        assert result['ok'] and result['complete']
        assert result['signatures_valid'] == {'agent': True, 'director': True}
        assert oap.verify_agreement(signed, manifest=dict(manifest, extension=True))['issues'] == ['manifest: hash mismatch']
        assert not oap.verify_agreement(signed, casting_call=dict(call, call_id='different'))['ok']
        stripped = copy.deepcopy(signed)
        del stripped['signatures'][first]
        assert not oap.verify_agreement(stripped)['ok']


@pytest.mark.parametrize('field,value', [('accepted_compensation', {'amount': '999', 'currency': 'USD'}),
    ('rider_amendments', ['Allow wardrobe change']), ('manifest_sha256', '0'*64),
    ('call_sha256', '0'*64), ('agreement_id', 'different'), ('created_at', '2026-01-01T00:00:00Z'),
    ('extension', {'any': 'change'})])
def test_agreement_tampering(field, value):
    draft, agent, director, _, _ = agreement_sources()
    partial = oap.sign_agreement(draft, 'agent', agent['_private'])
    partial[field] = value
    assert not oap.verify_agreement(partial, require_both=False)['ok']
    with pytest.raises(ValueError):
        oap.sign_agreement(partial, 'director', director['_private'])


def test_bad_signers_and_documents():
    draft, agent, director, _, _ = agreement_sources()
    with pytest.raises(ValueError, match='does not match'):
        oap.sign_agreement(draft, 'agent', director['_private'])
    with pytest.raises(ValueError, match='role must'):
        oap.sign_agreement(draft, 'other', agent['_private'])
    for document in [None, [], oap.new_manifest('x'), dict(draft, signatures={'other': {}}),
                     dict(draft, created_at='yesterday'), dict(draft, agent_did='oap:uuid:x')]:
        assert not oap.verify_agreement(document)['ok']
        with pytest.raises(ValueError):
            oap.sign_agreement(document, 'agent', agent['_private'])
    partial = oap.sign_agreement(draft, 'agent', agent['_private'])
    partial['signatures']['agent']['value'] = 'A'*86
    assert not oap.verify_agreement(partial, require_both=False)['ok']


def test_cli_validation_and_signing(tmp_path, capsys, monkeypatch):
    draft, agent, director, manifest, call = agreement_sources()
    path = tmp_path / 'agreement.json'
    path.write_text(json.dumps(draft))
    key = tmp_path / 'agent.key'
    key.write_text(agent['_private'])
    assert main(['validate', '--document', str(path)]) == 0
    assert main(['sign-agreement', '--agreement', str(path), '--role', 'agent',
                 '--sign', '@' + str(key), '--out', str(path)]) == 0
    assert main(['verify-agreement', '--agreement', str(path)]) == 1
    monkeypatch.setenv('OAP_TEST_DIRECTOR_KEY', director['_private'])
    assert main(['sign-agreement', '--agreement', str(path), '--role', 'director',
                 '--sign', 'env:OAP_TEST_DIRECTOR_KEY', '--out', str(path)]) == 0
    manifest_path, call_path = tmp_path / 'manifest.json', tmp_path / 'call.json'
    manifest_path.write_text(json.dumps(manifest)); call_path.write_text(json.dumps(call))
    assert main(['verify-agreement', '--agreement', str(path), '--manifest', str(manifest_path),
                 '--call', str(call_path)]) == 0
    assert agent['_private'] not in capsys.readouterr().out
    path.write_text('{bad json')
    assert main(['validate', '--document', str(path)]) == 1
    assert main(['validate', '--document', str(tmp_path / 'missing.json')]) == 1


def test_agreement_crypto_unavailable(monkeypatch):
    import oap.agreements as agreements
    draft, agent, _, _, _ = agreement_sources()
    monkeypatch.setattr(agreements, 'HAS_CRYPTO', False)
    with pytest.raises(RuntimeError, match='requires cryptography'):
        oap.sign_agreement(draft, 'agent', agent['_private'])


def test_agreement_nonfinite_json_and_signer_changes():
    draft, agent, director, _, _ = agreement_sources()
    signed = oap.sign_agreement(draft, 'agent', agent['_private'])
    for field, value in [('actor_did', director['did'] + '#other'),
                          ('agent_did', director['did']), ('director_did', agent['did']),
                          ('extension', float('nan'))]:
        changed = copy.deepcopy(signed)
        changed[field] = value
        assert not oap.verify_agreement(changed, require_both=False)['ok']
    assert oap.document_sha256({'a': 'é', 'b': 2}) == oap.document_sha256({'b': 2, 'a': 'é'})


@pytest.mark.parametrize('field', ['agent_did', 'actor_did', 'director_did', 'call_id'])
def test_agreement_source_identity_bindings(field):
    draft, agent, director, manifest, call = agreement_sources()
    replacement = oap.generate_identity()
    if field == 'call_id':
        draft[field] = 'wrong-call'
    else:
        draft[field] = replacement['did']
    keys = {'agent': agent['_private'], 'director': director['_private']}
    if field in ('agent_did', 'director_did'):
        keys[field.removesuffix('_did')] = replacement['_private']
    # Self-consistent attacker signatures do not prove a match to referenced sources.
    signed = oap.sign_agreement(draft, 'agent', keys['agent'])
    signed = oap.sign_agreement(signed, 'director', keys['director'])
    assert oap.verify_agreement(signed)['ok']
    result = oap.verify_agreement(signed, manifest=manifest, casting_call=call)
    assert not result['ok'] and any(field in issue for issue in result['issues'])
    with pytest.raises(ValueError, match=field):
        oap.sign_agreement(draft, 'agent', keys['agent'], manifest=manifest, casting_call=call)


def test_agreement_distinct_keys_and_version():
    draft, agent, _, _, _ = agreement_sources()
    for changed in [dict(draft, director_did=agent['did']), dict(draft, oap_version='0.2.0')]:
        assert not oap.validate_document(changed)['ok']
        assert not oap.verify_agreement(changed)['ok']
        with pytest.raises(ValueError):
            oap.sign_agreement(changed, 'agent', agent['_private'])


def test_cli_countersign_source_mismatch_leaves_output(tmp_path):
    draft, agent, director, manifest, _ = agreement_sources()
    draft['actor_did'] = director['did'] + '#other'
    agreement_path, source_path, key_path, output = [tmp_path / name for name in
        ('agreement.json', 'manifest.json', 'key', 'output.json')]
    agreement_path.write_text(json.dumps(draft)); source_path.write_text(json.dumps(manifest))
    key_path.write_text(agent['_private']); output.write_text('preserve')
    assert main(['sign-agreement', '--agreement', str(agreement_path), '--role', 'agent',
                 '--sign', '@' + str(key_path), '--out', str(output),
                 '--manifest', str(source_path)]) == 1
    assert output.read_text() == 'preserve'
