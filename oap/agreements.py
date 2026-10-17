"""Countersigned role records. Signature validity is separate from identity trust."""
import copy
import json

from .core import HAS_CRYPTO, _b64d, _b64e, now_iso, sha256_bytes
from .validation import validate_document


def document_sha256(document):
    """Hash complete JSON using OAP's sorted, compact, ASCII JSON encoding."""
    return sha256_bytes(json.dumps(document, sort_keys=True, separators=(',', ':'),
                                  allow_nan=False).encode('utf-8'))


def _payload(agreement):
    body = {key: value for key, value in agreement.items() if key != 'signatures'}
    return b'OAP role agreement v0.3\x00' + json.dumps(
        body, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def new_role_agreement(manifest, casting_call, accepted_compensation, agreement_id):
    """Build an unsigned record bound to the exact supplied manifest and call.

    Callers negotiate compensation/amendments and confirm signer identity themselves.
    No rider exceptions or payments are approved by creating this record.
    """
    for document in (manifest, casting_call):
        result = validate_document(document)
        if not result['ok']:
            raise ValueError('; '.join(result['issues']))
    if manifest['kind'] != 'oap.actor.manifest' or casting_call['kind'] != 'oap.casting_call':
        raise ValueError('expected actor manifest and casting call')
    result = {
        'oap_version': '0.3.0', 'kind': 'oap.role_agreement',
        'agreement_id': agreement_id, 'call_id': casting_call['call_id'],
        'actor_did': manifest['identity'].get('did'),
        'agent_did': 'oap:ed25519:' + (manifest.get('agent', {}).get('public_key') or ''),
        'director_did': casting_call['director'].get('did'),
        'manifest_sha256': document_sha256(manifest),
        'call_sha256': document_sha256(casting_call),
        'accepted_compensation': copy.deepcopy(accepted_compensation),
        'rider_amendments': [], 'created_at': now_iso(), 'signatures': {},
    }
    validation = validate_document(result)
    if not validation['ok']:
        raise ValueError('; '.join(validation['issues']))
    return result


def _validate_agreement(agreement):
    if not isinstance(agreement, dict) or agreement.get('kind') != 'oap.role_agreement':
        return {'ok': False, 'issues': ['$.kind: expected oap.role_agreement']}
    return validate_document(agreement)


def sign_agreement(agreement, role, private_b64, manifest=None, casting_call=None):
    """Return a copy with one party's signature; preserve only valid peer signatures."""
    if not HAS_CRYPTO:
        raise RuntimeError('Signing requires cryptography')
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    validation = _validate_agreement(agreement)
    if not validation['ok']:
        raise ValueError('; '.join(validation['issues']))
    if role not in ('agent', 'director'):
        raise ValueError('role must be agent or director')
    key = Ed25519PrivateKey.from_private_bytes(_b64d(private_b64))
    public = _b64e(key.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw))
    if agreement[role + '_did'] != 'oap:ed25519:' + public:
        raise ValueError('private key does not match the declared signer DID')
    # Do not countersign a document carrying stale or forged peer signatures.
    result = verify_agreement(agreement, require_both=False, manifest=manifest,
                              casting_call=casting_call)
    if not result['ok']:
        raise ValueError('; '.join(result['issues']))
    signed = copy.deepcopy(agreement)
    signed['signatures'][role] = {'algorithm': 'ed25519',
                                  'value': _b64e(key.sign(_payload(signed)))}
    return signed


def verify_agreement(agreement, require_both=True, manifest=None, casting_call=None):
    """Verify declared signers and optional exact source bindings; no trust enrollment.

    Complete verification requires both signatures by default. Partial verification
    permits unsigned drafts and is intended only for the countersigning workflow.
    """
    validation = _validate_agreement(agreement)
    if not validation['ok']:
        return dict(validation, signatures_valid={'agent': False, 'director': False}, complete=False)
    issues = []
    valid = {'agent': False, 'director': False}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        payload = _payload(agreement)
        for role in valid:
            signature = agreement['signatures'].get(role)
            if signature is None:
                if require_both:
                    issues.append(f'{role}: signature required')
                continue
            try:
                public = agreement[role + '_did'].removeprefix('oap:ed25519:')
                Ed25519PublicKey.from_public_bytes(_b64d(public)).verify(
                    _b64d(signature['value']), payload)
                valid[role] = True
            except Exception:
                issues.append(f'{role}: signature invalid')
    except (ImportError, ValueError, TypeError) as exc:
        issues.append(f'cannot verify agreement: {exc}')
    for label, document in [('manifest', manifest), ('call', casting_call)]:
        if document is not None:
            try:
                if document_sha256(document) != agreement[label + '_sha256']:
                    issues.append(f'{label}: hash mismatch')
            except (TypeError, ValueError):
                issues.append(f'{label}: invalid JSON document')
    for label, source, kind, bindings in [
        ('manifest', manifest, 'oap.actor.manifest', {
            'actor_did': lambda d: d['identity'].get('did'),
            'agent_did': lambda d: 'oap:ed25519:' + (d.get('agent', {}).get('public_key') or ''),
        }),
        ('call', casting_call, 'oap.casting_call', {
            'director_did': lambda d: d['director'].get('did'),
            'call_id': lambda d: d['call_id'],
        }),
    ]:
        if source is None:
            continue
        validation = validate_document(source)
        if not validation['ok'] or source.get('kind') != kind:
            issues.append(f'{label}: invalid source document')
            continue
        for field, get_value in bindings.items():
            if agreement[field] != get_value(source):
                issues.append(f'{label}: {field} does not match source')
    return {'ok': not issues, 'issues': issues, 'signatures_valid': valid,
            'complete': all(valid.values())}
