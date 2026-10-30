"""OAP 0.4 signed, recipient-encrypted package operations.

New packages and imports never write decrypted cast assets. Migration stages
legacy plaintext briefly because legacy packages already contain plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import struct
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite
from nacl import bindings as sodium
from nacl.exceptions import CryptoError


VERSION = '0.4.0'
DOMAIN = b'OAP actor manifest v0.4\x00'
HPKE_INFO = b'OAP cast asset key v0.4\x00'
CHUNK_SIZE = 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_MEMBER = 8 * 1024**3
MAX_TOTAL = 16 * 1024**3
SUITE = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_256_GCM)


def _b64e(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def _b64d(value):
    if not isinstance(value, str):
        raise ValueError('expected base64url text')
    raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    if _b64e(raw) != value:
        raise ValueError('noncanonical base64url text')
    return raw


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f'nonfinite JSON value: {value}')

    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def manifest_payload(manifest):
    if not isinstance(manifest.get('oap_version'), str) or not re.fullmatch(r'0\.4\.[0-9]+', manifest['oap_version']):
        raise ValueError('expected OAP 0.4 manifest')
    body = {key: value for key, value in manifest.items() if key != 'signature'}
    return DOMAIN + _json_bytes(body)


def generate_recipient_identity():
    key = X25519PrivateKey.generate()
    return {'algorithm': 'x25519-hpke',
            'public_key': _b64e(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            '_private': _b64e(key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))}


def _recipient_id(public_raw):
    return hashlib.sha256(public_raw).hexdigest()


def _asset_info(manifest, logical_path):
    return HPKE_INFO + manifest['identity']['actor_id'].encode('utf-8') + b'\x00' + logical_path.encode('utf-8')


def _asset_ad(manifest, logical_path):
    return b'OAP sealed asset v0.4\x00' + manifest['identity']['actor_id'].encode('utf-8') + b'\x00' + logical_path.encode('utf-8')


def _sealed_path(logical_path):
    return 'sealed/' + hashlib.sha256(logical_path.encode('utf-8')).hexdigest() + '.bin'


def _encrypt_stream(source, output, key, ad):
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    output.write(sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key))
    with open(source, 'rb') as stream:
        chunk = stream.read(CHUNK_SIZE)
        while True:
            following = stream.read(CHUNK_SIZE)
            tag = (sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
                   if not following else sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
            ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag)
            output.write(struct.pack('>I', len(ciphertext)))
            output.write(ciphertext)
            if not following:
                break
            chunk = following


def _decrypt_chunks(stream, key, ad, limit):
    header = stream.read(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    if len(header) != sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES:
        raise ValueError('sealed asset header is truncated')
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
    total = 0
    while True:
        length_raw = stream.read(4)
        if len(length_raw) != 4:
            raise ValueError('sealed asset is missing its final record')
        length = struct.unpack('>I', length_raw)[0]
        if not sodium.crypto_secretstream_xchacha20poly1305_ABYTES <= length <= CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES:
            raise ValueError('invalid sealed record length')
        ciphertext = stream.read(length)
        if len(ciphertext) != length:
            raise ValueError('sealed asset record is truncated')
        try:
            chunk, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(state, ciphertext, ad)
        except CryptoError as exc:
            raise ValueError('sealed asset authentication failed') from exc
        total += len(chunk)
        if total > limit:
            raise ValueError('decrypted asset exceeds memory limit')
        yield chunk
        if tag == sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            if stream.read(1):
                raise ValueError('sealed asset has trailing data')
            return
        if tag != sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE:
            raise ValueError('unsupported sealed record tag')


def _check_zip(zf, max_members=MAX_MEMBERS, max_member=MAX_MEMBER, max_total=MAX_TOTAL):
    from .core import _safe_member_name
    members = zf.infolist()
    if len(members) > max_members:
        raise ValueError('archive has too many members')
    seen, total = set(), 0
    for member in members:
        name = member.filename
        kind = (member.external_attr >> 16) & 0o170000
        if (not _safe_member_name(name) or member.is_dir() or member.flag_bits & 1 or
                kind not in (0, stat.S_IFREG) or name in seen):
            raise ValueError('archive has an unsafe, special, or duplicate member')
        seen.add(name)
        if member.file_size > max_member:
            raise ValueError('archive member exceeds size limit')
        total += member.file_size
        if total > max_total:
            raise ValueError('archive exceeds expanded size limit')
    if 'manifest.json' not in seen or zf.getinfo('manifest.json').file_size > MAX_MANIFEST:
        raise ValueError('manifest missing or too large')
    return seen


def _digest_zip_member(zf, name, limit):
    digest, size = hashlib.sha256(), 0
    with zf.open(name) as stream:
        while chunk := stream.read(CHUNK_SIZE):
            size += len(chunk)
            if size > limit:
                raise ValueError('archive member exceeds size limit while reading')
            digest.update(chunk)
    return digest.hexdigest(), size


def _reference_map(manifest):
    from .core import iter_asset_refs, _safe_member_name
    refs = {}
    for ref in iter_asset_refs(manifest):
        path = ref['file']
        if not _safe_member_name(path) or path == 'manifest.json' or path.startswith('sealed/'):
            raise ValueError('unsafe or reserved asset path')
        if path in refs:
            raise ValueError('duplicate asset reference')
        if ref.get('clearance') not in ('public', 'audition', 'cast'):
            raise ValueError('unknown asset clearance')
        refs[path] = ref
    return refs


def package_actor(source_dir, output_path, tier='portfolio', sign_key=None, recipient_public_keys=None):
    from .core import _is_safe_path, sign_manifest
    if tier not in ('portfolio', 'audition', 'full'):
        raise ValueError('unknown package tier')
    if not sign_key:
        raise ValueError('OAP 0.4 packages require an Agent signing key')
    with open(os.path.join(source_dir, 'manifest.json'), encoding='utf-8') as stream:
        manifest = _strict_json(stream.read())
    if not isinstance(manifest, dict) or not isinstance(manifest.get('oap_version'), str) or not re.fullmatch(r'0\.4\.[0-9]+', manifest['oap_version']):
        raise ValueError('source manifest must be OAP 0.4')
    refs = _reference_map(manifest)
    recipients = []
    for encoded in recipient_public_keys or []:
        raw = _b64d(encoded)
        if len(raw) != 32:
            raise ValueError('recipient X25519 key must be 32 bytes')
        recipients.append((encoded, raw, _recipient_id(raw), X25519PublicKey.from_public_bytes(raw)))
    if len({entry[2] for entry in recipients}) != len(recipients):
        raise ValueError('duplicate recipient')
    if tier != 'full' and recipients:
        raise ValueError('recipient keys are only used for full packages')
    if tier == 'full' and any(ref['clearance'] == 'cast' for ref in refs.values()) and not recipients:
        raise ValueError('full cast package requires at least one recipient key')
    included, staged = [], {}
    with tempfile.TemporaryDirectory() as temp:
        for path, ref in refs.items():
            if not _is_safe_path(source_dir, path):
                raise ValueError('unsafe source asset path')
            source = os.path.join(source_dir, path)
            clearance = ref['clearance']
            present = clearance == 'public' or (tier in ('audition', 'full') and clearance == 'audition') or (tier == 'full' and clearance == 'cast')
            ref.pop('sealed', None)
            ref['sha256'] = None
            ref.pop('size', None)
            if not present:
                continue
            if not os.path.isfile(source):
                raise ValueError(f'missing asset: {path}')
            if clearance == 'cast':
                key = sodium.crypto_secretstream_xchacha20poly1305_keygen()
                sealed_path = _sealed_path(path)
                sealed_file = os.path.join(temp, os.path.basename(sealed_path))
                with open(sealed_file, 'wb') as sink:
                    _encrypt_stream(source, sink, key, _asset_ad(manifest, path))
                wraps = [{'recipient': rid, 'public_key': encoded,
                          'key': _b64e(SUITE.encrypt(key, public, info=_asset_info(manifest, path)))}
                         for encoded, _, rid, public in recipients]
                ref['sealed'] = {'path': sealed_path, 'sha256': _sha256_file(sealed_file),
                                 'size': os.path.getsize(sealed_file), 'wraps': wraps}
                included.append(sealed_path)
                staged[sealed_path] = sealed_file
            else:
                ref['sha256'] = _sha256_file(source)
                ref['size'] = os.path.getsize(source)
                included.append(path)
                staged[path] = source
        manifest['bundle'] = {'tier': tier, 'members': sorted(included)}
        manifest['protection'] = {'tier': 1 if tier == 'full' and any(r['clearance'] == 'cast' for r in refs.values()) else 0,
                                  'mechanism': 'hpke-x25519-secretstream' if tier == 'full' and any(r['clearance'] == 'cast' for r in refs.values()) else 'plain'}
        sign_manifest(manifest, sign_key)
        encoded_manifest = json.dumps(manifest, indent=2, allow_nan=False).encode('utf-8')
        if len(encoded_manifest) > MAX_MANIFEST:
            raise ValueError('manifest exceeds size limit')
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.oap-', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
        try:
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json', encoded_manifest)
                for path in sorted(staged):
                    archive.write(staged[path], path)
            checked = verify_package(temporary, allow_untrusted=True)
            if not checked['ok']:
                raise ValueError('new package failed verification: ' + '; '.join(checked['issues']))
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    return {'output': str(output_path), 'tier': tier, 'included': ['manifest.json', *sorted(included)]}


def verify_package(path, known_agents=None, allow_untrusted=False,
                   max_members=MAX_MEMBERS, max_member=MAX_MEMBER, max_total=MAX_TOTAL):
    from .core import verify_signature
    result = {'ok': False, 'integrity_ok': False, 'signature_valid': False,
              'agent_known': None if known_agents is None else False,
              'checked': 0, 'issues': []}
    try:
        with zipfile.ZipFile(path) as archive:
            names = _check_zip(archive, max_members, max_member, max_total)
            manifest = _strict_json(archive.read('manifest.json'))
            if not isinstance(manifest, dict) or not isinstance(manifest.get('oap_version'), str) or not re.fullmatch(r'0\.4\.[0-9]+', manifest['oap_version']):
                raise ValueError('normal verification requires an OAP 0.4 package')
            if manifest.get('kind') != 'oap.actor.manifest':
                raise ValueError('wrong document kind')
            from .validation import validate_document
            validation = validate_document(manifest)
            if not validation['ok']:
                raise ValueError('; '.join(validation['issues']))
            refs = _reference_map(manifest)
            inventory = manifest['bundle']['members']
            if len(inventory) != len(set(inventory)) or set(inventory) | {'manifest.json'} != names:
                raise ValueError('signed member inventory does not match archive')
            expected = {}
            tier = manifest['bundle']['tier']
            rank = {'portfolio': 0, 'audition': 1, 'full': 2}[tier]
            for logical, ref in refs.items():
                clearance = ref['clearance']
                present = {'public': 0, 'audition': 1, 'cast': 2}[clearance] <= rank
                if clearance == 'cast' and present:
                    sealed = ref.get('sealed')
                    if (not isinstance(sealed, dict) or ref.get('sha256') is not None
                            or 'size' in ref):
                        raise ValueError(f'{logical}: cast asset is not sealed')
                    if sealed.get('path') != _sealed_path(logical):
                        raise ValueError(f'{logical}: sealed path does not match asset')
                    if sealed['path'] in expected:
                        raise ValueError('duplicate sealed path')
                    wraps = sealed.get('wraps')
                    if not isinstance(wraps, list) or not wraps:
                        raise ValueError(f'{logical}: no recipients')
                    recipient_ids = set()
                    for wrap in wraps:
                        public_raw = _b64d(wrap['public_key'])
                        if len(public_raw) != 32 or wrap['recipient'] != _recipient_id(public_raw):
                            raise ValueError(f'{logical}: invalid recipient descriptor')
                        if wrap['recipient'] in recipient_ids or not _b64d(wrap['key']):
                            raise ValueError(f'{logical}: duplicate or empty recipient key')
                        recipient_ids.add(wrap['recipient'])
                    if (not isinstance(sealed.get('size'), int) or
                            isinstance(sealed['size'], bool) or
                            not 0 <= sealed['size'] <= max_member or
                            not isinstance(sealed.get('sha256'), str) or
                            not re.fullmatch(r'[a-f0-9]{64}', sealed['sha256'])):
                        raise ValueError(f'{logical}: invalid sealed size or hash')
                    expected[sealed['path']] = (sealed['sha256'], sealed['size'])
                elif present:
                    if ref.get('sealed') or ref.get('sha256') is None:
                        raise ValueError(f'{logical}: plain asset lacks hash')
                    if (not isinstance(ref.get('size'), int) or isinstance(ref['size'], bool)
                            or not 0 <= ref['size'] <= max_member):
                        raise ValueError(f'{logical}: invalid plain asset size')
                    if logical in expected:
                        raise ValueError('duplicate package member')
                    expected[logical] = (ref['sha256'], ref['size'])
                elif ref.get('sealed') or ref.get('sha256') is not None or 'size' in ref:
                    raise ValueError(f'{logical}: omitted higher-clearance asset leaks metadata')
            if set(expected) != set(inventory):
                raise ValueError('member inventory does not match asset references')
            has_cast = any(ref['clearance'] == 'cast' and rank == 2 for ref in refs.values())
            protection = manifest.get('protection')
            expected_protection = {'tier': 1, 'mechanism': 'hpke-x25519-secretstream'} if has_cast else {'tier': 0, 'mechanism': 'plain'}
            if not isinstance(protection, dict) or any(
                    protection.get(key) != value for key, value in expected_protection.items()):
                raise ValueError('protection descriptor does not match package contents')
            expanded = 0
            for name, (digest, size) in expected.items():
                actual_digest, actual_size = _digest_zip_member(archive, name, max_member)
                expanded += actual_size
                if expanded > max_total:
                    raise ValueError('archive exceeds expanded size limit while reading')
                result['checked'] += 1
                if (actual_digest, actual_size) != (digest, size):
                    raise ValueError(f'{name}: hash or size mismatch')
            valid, message = verify_signature(manifest)
            result['signature_valid'] = valid
            if not valid:
                raise ValueError(message)
            key = manifest['agent']['public_key']
            result['agent_known'] = None if known_agents is None else key in known_agents
            result['integrity_ok'] = True
            if not allow_untrusted and result['agent_known'] is not True:
                raise ValueError('trusted Agent key required')
            result['ok'] = True
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError, UnicodeError,
            zipfile.BadZipFile, EOFError) as exc:
        result['issues'].append(str(exc))
    return result


def open_asset_buffer(path, logical_path, recipient_private, *, known_agents=None,
                      allow_untrusted=False, max_bytes=512 * 1024 * 1024):
    from .core import iter_asset_refs
    with open(path, 'rb') as package:
        result = verify_package(package, known_agents=known_agents, allow_untrusted=allow_untrusted)
        if not result['ok']:
            raise ValueError('; '.join(result['issues']))
        package.seek(0)
        with zipfile.ZipFile(package) as archive:
            manifest = _strict_json(archive.read('manifest.json'))
            ref = next((r for r in iter_asset_refs(manifest) if r['file'] == logical_path), None)
            if ref is None or not isinstance(ref.get('sealed'), dict):
                raise ValueError('requested asset is not sealed in this package')
            private = X25519PrivateKey.from_private_bytes(_b64d(recipient_private))
            public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            recipient_id = _recipient_id(public_raw)
            wrap = next((w for w in ref['sealed']['wraps'] if w['recipient'] == recipient_id), None)
            if wrap is None:
                raise ValueError('recipient key is not authorized for this asset')
            key = SUITE.decrypt(_b64d(wrap['key']), private, info=_asset_info(manifest, logical_path))
            with archive.open(ref['sealed']['path']) as stream:
                return b''.join(_decrypt_chunks(stream, key, _asset_ad(manifest, logical_path), max_bytes))


def import_actor(path, target_dir, *, known_agents=None, allow_untrusted=False):
    """Install only signed archive bytes; cast assets remain encrypted."""
    target = Path(target_dir)
    if target.exists() or target.is_symlink():
        return {'ok': False, 'issues': ['import target already exists'], 'extracted': False}
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix='.oap-import-') as temporary:
        root = Path(temporary)
        snapshot = root / 'snapshot.oap'
        stage = root / 'stage'
        stage.mkdir()
        try:
            copied = 0
            with open(path, 'rb') as source, snapshot.open('xb') as sink:
                while chunk := source.read(CHUNK_SIZE):
                    copied += len(chunk)
                    if copied > MAX_TOTAL + 256 * 1024 * 1024:
                        raise ValueError('package exceeds compressed size limit')
                    sink.write(chunk)
            verification = verify_package(snapshot, known_agents=known_agents,
                                          allow_untrusted=allow_untrusted)
            if not verification['ok']:
                return {'ok': False, 'issues': verification['issues'], 'extracted': False}
            with zipfile.ZipFile(snapshot) as archive:
                manifest = _strict_json(archive.read('manifest.json'))
                for name in archive.namelist():
                    destination = stage / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(name) as source, destination.open('xb') as sink:
                        while chunk := source.read(CHUNK_SIZE):
                            sink.write(chunk)
            if target.exists() or target.is_symlink():
                raise ValueError('import target already exists')
            stage.rename(target)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            return {'ok': False, 'issues': [str(exc)], 'extracted': False}
    return {'ok': True, 'issues': [], 'extracted': True, 'manifest': manifest}


def migrate_legacy_package(old_path, output_path, sign_key, recipient_public_keys,
                           *, known_agents=None):
    """Re-sign and seal a complete 0.2/0.3 legacy package as OAP 0.4."""
    from .core import verify_package as verify, iter_asset_refs, _safe_member_name, now_iso
    checked = verify(old_path, strict=True, require_signature=True,
                     known_agents=known_agents, legacy=True)
    if not checked['ok'] or (known_agents is not None and checked['agent_known'] is not True):
        raise ValueError('legacy package failed signature, archive, or Agent trust verification')
    with zipfile.ZipFile(old_path) as archive:
        names = _check_zip(archive)
        manifest = _strict_json(archive.read('manifest.json'))
        refs = list(iter_asset_refs(manifest))
        if any(ref['file'] not in names for ref in refs):
            raise ValueError('migration requires a complete legacy package')
        if names != {'manifest.json'} | {ref['file'] for ref in refs}:
            raise ValueError('legacy archive contains unlisted files')
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for name in names - {'manifest.json'}:
                if not _safe_member_name(name):
                    raise ValueError('unsafe legacy asset path')
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as stream, target.open('xb') as sink:
                    while chunk := stream.read(CHUNK_SIZE):
                        sink.write(chunk)
            manifest['oap_version'] = VERSION
            manifest['issued_at'] = now_iso()
            manifest['bundle'] = {'tier': 'full', 'members': []}
            manifest['signature'] = {'algorithm': 'ed25519', 'value': None}
            (source / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            return package_actor(str(source), str(output_path), 'full', sign_key,
                                 recipient_public_keys)
