import json
import struct
import wave
import zipfile

import pytest
from PIL import Image, PngImagePlugin

import oap
from oap.core import main


def bundle(tmp_path, manifest=None, entries=None):
    path = tmp_path / 'actor.oap'
    if manifest is None:
        manifest = oap.new_manifest('lead')
        manifest['oap_version'] = '0.2.0'
        manifest.pop('issued_at')
        manifest.pop('bundle')
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(manifest))
        for name, data in (entries or {}).items():
            archive.writestr(name, data)
    return path


def test_generic_assets_roundtrip(tmp_path):
    identity = oap.generate_identity()
    recipient = oap.generate_recipient_identity()
    manifest = oap.new_manifest('lead')
    manifest['agent']['public_key'] = identity['public_key']
    manifest['identity']['did'] = identity['did'] + '#lead'
    manifest['extensions'] = {'future': {'anything': True}}
    manifest['assets'] = [
        {'file': 'personality.md', 'clearance': 'cast', 'role': 'personality'},
        {'file': 'take.wav', 'clearance': 'public', 'role': 'voice_take'},
    ]
    for name in ('personality.md', 'take.wav'):
        (tmp_path / name).write_bytes(name.encode())
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    path = tmp_path / 'full.oap'
    oap.package_actor(str(tmp_path), str(path), 'full', identity['_private'],
                      [recipient['public_key']])
    result = oap.verify_package(path, require_signature=True, strict=True,
                                known_agents=[identity['public_key']], revocation_policy='ignore')
    assert result['ok'] and result['agent_known'] and result['checked'] == 2
    assert oap.verify_package(path, known_agents=[], revocation_policy='ignore')['agent_known'] is False
    assert oap.verify_package(path, revocation_policy='ignore')['agent_known'] is None
    assert oap.import_actor(path, str(tmp_path / 'installed'),
                            known_agents=[identity['public_key']], revocation_policy='ignore')['ok']
    assert not (tmp_path / 'installed/personality.md').exists()
    assert oap.open_asset_buffer(path, 'personality.md', recipient['_private'],
                                 known_agents=[identity['public_key']], revocation_policy='ignore') == b'personality.md'
    oap.package_actor(str(tmp_path), str(path), 'portfolio', identity['_private'])
    assert oap.verify_package(path, known_agents=[identity['public_key']], revocation_policy='ignore')['checked'] == 1
    with zipfile.ZipFile(path) as archive:
        assert 'personality.md' not in archive.namelist()
        assert json.loads(archive.read('manifest.json'))['assets'][0]['sha256'] is None


def test_generic_asset_tamper(tmp_path):
    manifest = oap.new_manifest('lead')
    manifest['assets'] = [{'file': 'personality.md', 'sha256': 'wrong', 'role': 'personality'}]
    assert not oap.verify_package(bundle(tmp_path, manifest, {'personality.md': b'changed'}), revocation_policy='ignore')['ok']


@pytest.mark.parametrize('name', ['/absolute', '../escape', 'a/../escape', 'a\\evil', 'C:evil', 'C:/evil', 'a//evil'])
def test_strict_unsafe_and_import(tmp_path, name):
    path = bundle(tmp_path, entries={name: b'bad'})
    result = oap.verify_package(path, strict=True, revocation_policy='ignore')
    assert not result['ok'] and any('unsafe' in issue for issue in result['issues'])
    assert not oap.import_actor(path, str(tmp_path / 'imported'), verify=False)['ok']


def test_strict_signature_and_extras(tmp_path, capsys):
    path = bundle(tmp_path, entries={'stray.txt': b'x', 'signatures/note': b'ok'})
    assert not oap.verify_package(path, revocation_policy='ignore')['ok']
    assert oap.verify_package(path, legacy=True)['ok']
    assert not oap.verify_package(path, legacy=True, require_signature=True)['ok']
    assert not oap.verify_package(path, legacy=True, strict=True)['ok']
    assert main(['verify', '--oap', str(path), '--legacy']) == 1
    assert 'signature required' in capsys.readouterr().out
    path = bundle(tmp_path, entries={'signatures/note': b'ok'})
    assert oap.verify_package(path, legacy=True, strict=True)['ok']
    with pytest.warns(UserWarning), zipfile.ZipFile(path, 'a') as archive:
        archive.writestr('manifest.json', json.dumps(oap.new_manifest('other')))
    assert not oap.verify_package(path, legacy=True, strict=True)['ok']


@pytest.mark.parametrize('name', ['../outside', '/outside', 'C:outside', 'a\\outside', 'manifest.json'])
def test_packaging_rejects_unsafe_assets(tmp_path, name):
    manifest = oap.new_manifest('lead')
    manifest['assets'] = [{'file': name}]
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        oap.package_actor(str(tmp_path), str(tmp_path / 'out.oap'))


def test_trust_store(tmp_path):
    path = tmp_path / 'known_agents.json'
    path.write_text('["public-key"]')
    assert oap.load_known_agents(path) == ['public-key']
    path.write_text('{"key": true}')
    with pytest.raises(ValueError):
        oap.load_known_agents(path)


def test_new_fields_signed_roundtrip(tmp_path):
    manifest = oap.new_manifest('lead')
    manifest['oap_version'] = '0.2.0'
    manifest.pop('issued_at')
    manifest.pop('bundle')
    manifest['visual']['height'] = {'cm': 185, 'ft_in': '6\'1"', 'source': 'director'}
    manifest['visual']['contract'] = {'default_sheet': 'ref.png', 'sheets': {
        'ref.png': {'views': ['front'], 'identity': 'hazel eyes', 'hair': 'bob',
                    'makeup': '', 'wardrobe': 'coat', 'footwear': 'boots',
                    'accessories': '', 'expression_range': 'reserved',
                    'detail_notes': '', 'canonical_summary': 'Hazel eyes, dark bob.'}}}
    manifest['visual']['sheets'] = [{'file': 'ref.png', 'clearance': 'cast'}]
    manifest['voice'].update(status='provisional', profile_source='from_look', model_revision='revision1')
    identity = oap.generate_identity()
    manifest['agent']['public_key'] = identity['public_key']
    oap.sign_manifest(manifest, identity['_private'])
    path = bundle(tmp_path, manifest)
    assert oap.verify_package(path, require_signature=True, legacy=True)['ok']
    manifest['visual']['height']['cm'] = 186
    assert not oap.verify_signature(manifest)[0]


def test_png_cleaning_preserves_pixels_and_transparency(tmp_path):
    source, output = tmp_path / 'raw.png', tmp_path / 'clean.png'
    image = Image.new('RGBA', (3, 2), (10, 20, 30, 100))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text('workflow', 'secret prompts')
    metadata.add_itxt('description', 'private')
    metadata.add_text('compressed', 'private', zip=True)
    image.save(source, pnginfo=metadata, exif=b'Exif\x00\x00private')
    oap.clean_asset(source, output)
    with Image.open(output) as cleaned:
        assert cleaned.tobytes() == image.tobytes()
        assert not cleaned.info
    assert b'secret' not in output.read_bytes()
    oap.clean_asset(output, output)  # atomic in-place use


def test_wav_cleaning_preserves_pcm(tmp_path):
    source, output = tmp_path / 'raw.wav', tmp_path / 'clean.wav'
    frames = b'\x00\x01\x02\x03' * 10
    with wave.open(str(source), 'wb') as audio:
        audio.setparams((1, 2, 16000, 0, 'NONE', 'not compressed'))
        audio.writeframes(frames)
    data = source.read_bytes()
    chunk = b'LIST' + struct.pack('<I', 12) + b'INFOsecret!!'
    data = data[:4] + struct.pack('<I', len(data) + len(chunk) - 8) + data[8:] + chunk
    source.write_bytes(data)
    oap.clean_asset(source, output)
    assert b'LIST' not in output.read_bytes()
    with wave.open(str(output), 'rb') as audio:
        assert audio.readframes(100) == frames
        assert audio.getframerate() == 16000 and audio.getsampwidth() == 2


def test_clean_asset_rejects_unsupported_without_overwrite(tmp_path):
    source, output = tmp_path / 'raw.png', tmp_path / 'clean.png'
    Image.new('I;16', (1, 1), 40000).save(source)
    output.write_bytes(b'keep')
    with pytest.raises(ValueError):
        oap.clean_asset(source, output)
    assert output.read_bytes() == b'keep'
    with pytest.raises(ValueError):
        oap.clean_asset(tmp_path / 'input.mp3', tmp_path / 'output.mp3')


def test_deprecated_bridge_preserves_files_and_refuses_overwrite(tmp_path):
    extracted = tmp_path / 'extracted/identity'
    extracted.mkdir(parents=True)
    for name in ['one.wav', 'two.wav']:
        (extracted / name).write_bytes(name.encode())
    manifest = oap.new_manifest('lead')
    with pytest.warns(DeprecationWarning):
        result = oap.oap_to_studio(manifest, str(extracted.parent), str(tmp_path / 'studio'))
    refs = tmp_path / 'studio/actors/lead/refs'
    assert (refs / 'one.wav').read_bytes() == b'one.wav'
    assert (refs / 'two.wav').read_bytes() == b'two.wav'
    before = open(result['actor_json']).read()
    with pytest.warns(DeprecationWarning), pytest.raises(FileExistsError):
        oap.oap_to_studio(manifest, str(extracted.parent), str(tmp_path / 'studio'))
    assert open(result['actor_json']).read() == before


@pytest.mark.parametrize('version,accepted', [('0.1.0', False), ('0.1.99', False),
    ('0.2.0', False), ('0.2.100', False), ('0.3.0', False), ('0.3.100', False), ('0.4.0', True), ('0.5.0', True), ('1.0.0', False),
    ('0.2', False), (None, False)])
def test_version_policy(tmp_path, version, accepted):
    manifest = oap.new_manifest('lead')
    manifest['oap_version'] = version
    manifest['unknown_future_key'] = {'preserve': True}
    assert oap.supports_version(version) is accepted
    # A manifest alone is never a valid signed package.
    assert not oap.verify_package(bundle(tmp_path, manifest), revocation_policy='ignore')['ok']


def test_malformed_packages_fail_verification(tmp_path):
    path = tmp_path / 'invalid.oap'
    path.write_bytes(b'not a zip')
    assert not oap.verify_package(path, revocation_policy='ignore')['ok']
    for content in ['[]', 'null', '{"visual": []}']:
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('manifest.json', content)
        assert not oap.verify_package(path, revocation_policy='ignore')['ok']


def test_palette_transparency_survives_cleaning(tmp_path):
    source, output = tmp_path / 'palette.png', tmp_path / 'clean.png'
    image = Image.new('P', (2, 2))
    image.putpalette([255, 0, 0] + [0, 0, 0] * 255)
    image.save(source, transparency=0)
    oap.clean_asset(source, output)
    with Image.open(source) as original, Image.open(output) as clean:
        assert original.convert('RGBA').tobytes() == clean.convert('RGBA').tobytes()
        assert set(clean.info) == {'transparency'}


def test_pack_deduplicates_and_rejects_conflicting_clearance(tmp_path):
    manifest = oap.new_manifest('lead')
    identity = oap.generate_identity()
    manifest['agent']['public_key'] = identity['public_key']
    manifest['visual']['sheets'] = [{'file': 'ref.png', 'clearance': 'cast'}]
    manifest['assets'] = [{'file': 'ref.png', 'clearance': 'cast', 'role': 'turnaround'}]
    (tmp_path / 'ref.png').write_bytes(b'ref')
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    path = tmp_path / 'out.oap'
    with pytest.raises(ValueError, match='duplicate asset reference'):
        oap.package_actor(str(tmp_path), str(path), 'full', identity['_private'])
    manifest['assets'][0]['clearance'] = 'public'
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='duplicate asset reference'):
        oap.package_actor(str(tmp_path), str(path), sign_key=identity['_private'])


def test_pack_clears_stale_signature(tmp_path):
    manifest = oap.new_manifest('lead')
    identity = oap.generate_identity()
    manifest['agent']['public_key'] = identity['public_key']
    oap.sign_manifest(manifest, identity['_private'])
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    path = tmp_path / 'out.oap'
    oap.package_actor(str(tmp_path), str(path), sign_key=identity['_private'])
    assert oap.verify_package(path, known_agents=[identity['public_key']], revocation_policy='ignore')['ok']
    with zipfile.ZipFile(path) as archive:
        assert json.loads(archive.read('manifest.json'))['signature']['value'] != manifest['signature']['value']


def test_studio_cli_refuses_untrusted_legacy_package(tmp_path, capsys):
    source = bundle(tmp_path)
    assert main(['studio-import', '--oap', str(source),
                 '--studio-root', str(tmp_path / 'studio')]) == 1
    assert not (tmp_path / 'studio/actors').exists()


def test_cli_trust_store_and_signed_package(tmp_path, capsys):
    identity = oap.generate_identity()
    manifest = oap.new_manifest('lead')
    manifest['agent']['public_key'] = identity['public_key']
    oap.sign_manifest(manifest, identity['_private'])
    path = bundle(tmp_path, manifest)
    trusted = tmp_path / 'known_agents.json'
    trusted.write_text(json.dumps([identity['public_key']]))
    assert main(['verify', '--oap', str(path),
                 '--known-agents', str(trusted),
                 '--revocation-policy', 'ignore']) == 0
    assert json.loads(capsys.readouterr().out)['ok'] is True
