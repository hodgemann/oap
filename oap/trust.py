"""OAP 0.5 trust lifecycle: key IDs, revocation lists, and attestations.

Signature validity never implies trust. Trust comes only from local files the
receiver supplies, and revocation and attestation data travelling inside a
package can never weaken the receiver's policy.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.request
import uuid
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .v04 import _b64d, _b64e, _json_bytes, _strict_json
from .validation import validate_document


VERSION = '0.5.0'
KEY_TYPES = ('agent_signing', 'director_recipient')
REVOCATION_REASONS = ('unspecified', 'compromised', 'retired', 'agency_change',
                      'superseded', 'policy_violation')
REVOCATION_POLICIES = ('strict', 'best_effort', 'ignore')
ATTESTATION_POLICIES = ('verify_present', 'require', 'ignore')
MAX_DOCUMENT = 2 * 1024 * 1024
MAX_REMOTE_DOCUMENT = 1024 * 1024
REMOTE_TIMEOUT = 10
MAX_REMOTE_ENDPOINTS = 8
REMOTE_DEADLINE = 30
CLOCK_SKEW = datetime.timedelta(minutes=5)
MAX_SAFE_INTEGER = 2**53 - 1
ENTRY_DOMAIN = b'OAP revocation entry v0.5\x00'
LIST_DOMAIN = b'OAP revocation list v0.5\x00'
ATTESTATION_DOMAIN = b'OAP attestation v0.5\x00'
PACKAGE_DOMAIN = b'OAP package content v0.5\x00'
_KEY_ID = re.compile(r'sha256:[a-f0-9]{64}')
_SECRET_NAME = re.compile(r'private|secret|(^|[_-])seed($|[_-])', re.IGNORECASE)


def canonical_json(value):
    """Encode the integer-only subset of JSON on which RFC 8785 is unambiguous."""
    return _canonical_text(value).encode('utf-8')


def _canonical_text(value):
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError('canonical JSON integer is out of range')
        return str(value)
    if isinstance(value, float):
        raise ValueError('canonical JSON does not allow floating point numbers')
    if isinstance(value, str):
        value.encode('utf-8')  # A lone surrogate raises UnicodeError here.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(_canonical_text(item) for item in value) + ']'
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError('canonical JSON object keys must be strings')
        names = sorted(value, key=lambda name: name.encode('utf-16-be', 'surrogatepass'))
        return '{' + ','.join(_canonical_text(name) + ':' + _canonical_text(value[name])
                              for name in names) + '}'
    raise ValueError('value cannot be represented as canonical JSON')


def calculate_key_id(public_key):
    """Return sha256:<hex> over the raw key, the same digest as a 0.4 wrap recipient."""
    return 'sha256:' + hashlib.sha256(_raw_public_key(public_key)).hexdigest()


def _raw_public_key(public_key):
    raw = _b64d(public_key)
    if len(raw) != 32:
        raise ValueError('public key must be 32 bytes')
    return raw


def _is_key_id(value):
    return isinstance(value, str) and _KEY_ID.fullmatch(value) is not None


def _timestamp(value=None):
    if value is None:
        return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    _parse_time(value)
    return value


def _parse_time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        raise ValueError('expected an RFC 3339 timestamp')
    fraction = re.search(r'\.\d+', value)
    if fraction:  # Python 3.9 parses only three or six fractional digits.
        value = value.replace(fraction.group(0), fraction.group(0)[:7].ljust(7, '0'))
    return datetime.datetime.fromisoformat(value.upper().replace('Z', '+00:00'))


def _clock(now):
    if now is None:
        return datetime.datetime.now(datetime.timezone.utc)
    return _parse_time(now) if isinstance(now, str) else now


def _signer(private_b64):
    key = Ed25519PrivateKey.from_private_bytes(_b64d(private_b64))
    return key, _b64e(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _payload(domain, document):
    return domain + canonical_json({k: v for k, v in document.items() if k != 'signature'})


def _sign(domain, document, key):
    return _b64e(key.sign(_payload(domain, document)))


def _signature_valid(domain, document, public_key):
    try:
        Ed25519PublicKey.from_public_bytes(_raw_public_key(public_key)).verify(
            _b64d(document['signature']), _payload(domain, document))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, UnicodeError):
        return False


def _schema_issues(document):
    return validate_document(document)['issues']


def load_json_document(path):
    with open(path, 'rb') as stream:
        raw = stream.read(MAX_DOCUMENT + 1)
    if len(raw) > MAX_DOCUMENT:
        raise ValueError(f'{path}: document exceeds size limit')
    return _strict_json(raw)


def _trust_index(entries, what):
    index = {}
    if not isinstance(entries, (list, tuple)):
        raise ValueError(f'{what} must be a JSON array')
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('public_key'), str):
            raise ValueError(f'{what} entries need a public_key')
        if '_private' in entry:
            raise ValueError(f'{what} must not contain private keys')
        if entry.get('key_id') != calculate_key_id(entry['public_key']):
            raise ValueError(f'{what} entry key_id does not match its public_key')
        index[entry['key_id']] = entry
    return index


def load_known_revokers(path):
    entries = load_json_document(path)
    for entry in _trust_index(entries, 'known_revokers').values():
        scope = entry.get('key_types')
        if scope is not None and (not isinstance(scope, list) or set(scope) - set(KEY_TYPES)):
            raise ValueError('known_revokers key_types must list OAP key types')
    return entries


def load_attestation_issuers(path):
    entries = load_json_document(path)
    _issuer_index(entries)
    return entries


def _issuer_index(entries):
    index = _trust_index(entries, 'known_attestation_issuers')
    for entry in index.values():
        accepted = entry.get('accepted_claim_types')
        if not isinstance(accepted, list) or any(not isinstance(item, str) for item in accepted):
            raise ValueError('known_attestation_issuers entries need accepted_claim_types')
    return index


def load_revocation_lists(paths):
    """Read list documents; one file may hold a single list or a JSON array of lists."""
    documents = []
    for path in paths or []:
        loaded = load_json_document(path)
        documents.extend(loaded if isinstance(loaded, list) else [loaded])
    return documents


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #
def create_revocation_entry(key_id, key_type, reason, sign_key, *, revoked_at=None):
    if not _is_key_id(key_id):
        raise ValueError('key_id must be sha256:<lowercase hex>')
    if key_type not in KEY_TYPES:
        raise ValueError('unknown key type')
    if reason not in REVOCATION_REASONS:
        raise ValueError('unknown revocation reason')
    key, public = _signer(sign_key)
    entry = {'oap_revocation_entry_version': VERSION, 'key_id': key_id, 'key_type': key_type,
             'revoked_at': _timestamp(revoked_at), 'reason': reason,
             'revoked_by': calculate_key_id(public), 'revoked_by_public_key': public}
    entry['signature'] = _sign(ENTRY_DOMAIN, entry, key)
    return entry


def _entry_ranking(entry):
    return (_parse_time(entry['revoked_at']), canonical_json(entry))


def create_revocation_list(list_id, entries, sign_key, *, next_update=None, issued_at=None):
    latest = {}
    for entry in entries:
        slot = (entry['key_id'], entry['key_type'])
        if slot not in latest or _entry_ranking(entry) > _entry_ranking(latest[slot]):
            latest[slot] = entry
    key, public = _signer(sign_key)
    document = {'oap_revocation_list_version': VERSION, 'list_id': list_id,
                'issued_at': _timestamp(issued_at),
                'next_update': None if next_update is None else _timestamp(next_update),
                'signer': {'key_id': calculate_key_id(public), 'public_key': public},
                'entries': [latest[slot] for slot in sorted(latest)]}
    document['signature'] = _sign(LIST_DOMAIN, document, key)
    return document


def _entry_authority(entry, trusted, distrusted=()):
    """Return (authorized, is_self, issue); assumes the entry signature already verified."""
    signer = entry['revoked_by']
    is_self = entry['key_type'] == 'agent_signing' and signer == entry['key_id']
    if is_self:
        return True, True, None
    if signer in trusted:
        scope = trusted[signer].get('key_types')
        if scope is not None and entry['key_type'] not in scope:
            return False, False, f'revoker {signer} is not scoped for {entry["key_type"]}'
        return True, False, None
    if signer in distrusted:
        return False, False, f'revoker {signer} is itself revoked'
    return False, False, f'unknown revocation signer {signer}'


def _entry_form_issues(entry):
    issues = _schema_issues(entry) if isinstance(entry, dict) else ['entry must be an object']
    if issues:
        return issues
    if 'oap_revocation_entry_version' not in entry:
        return ['not a revocation entry']
    try:
        if calculate_key_id(entry['revoked_by_public_key']) != entry['revoked_by']:
            return ['revoked_by does not match revoked_by_public_key']
    except (ValueError, TypeError) as exc:
        return [f'invalid revoker key: {exc}']
    if not _signature_valid(ENTRY_DOMAIN, entry, entry['revoked_by_public_key']):
        return ['revocation entry signature invalid']
    return []


def verify_revocation_entry(entry, trusted_revokers):
    """Check signature and authority; X25519 Director keys cannot revoke themselves."""
    issues = _entry_form_issues(entry)
    if issues:
        return {'ok': False, 'issues': issues, 'self_revocation': False}
    authorized, is_self, issue = _entry_authority(
        entry, _trust_index(trusted_revokers or [], 'known_revokers'))
    return {'ok': authorized, 'issues': [] if authorized else [issue], 'self_revocation': is_self}


def _evaluate_list(document, trusted, distrusted, now):
    result = {'valid': False, 'trusted': False, 'expired': False, 'entries': [],
              'issues': [], 'warnings': []}
    issues = _schema_issues(document) if isinstance(document, dict) else ['list must be an object']
    if not issues and 'oap_revocation_list_version' not in document:
        issues = ['not a revocation list']
    if issues:
        result['issues'] = issues
        return result
    signer = document['signer']
    try:
        if calculate_key_id(signer['public_key']) != signer['key_id']:
            raise ValueError('signer key_id does not match its public_key')
    except (ValueError, TypeError) as exc:
        result['issues'] = [f'invalid list signer: {exc}']
        return result
    if not _signature_valid(LIST_DOMAIN, document, signer['public_key']):
        result['issues'] = ['revocation list signature invalid']
        return result
    issued = _parse_time(document['issued_at'])
    if issued > now + CLOCK_SKEW:
        result['issues'] = ['revocation list issued_at is in the future']
        return result
    if document['next_update'] is not None:
        expires = _parse_time(document['next_update'])
        if expires <= issued:
            result['issues'] = ['revocation list next_update must follow issued_at']
            return result
        result['expired'] = expires <= now
    signer_id = signer['key_id']
    signer_trusted = signer_id in trusted
    signer_distrusted = signer_id in distrusted
    accepted, dropped = [], 0
    for entry in document['entries']:
        form = _entry_form_issues(entry)
        if form:
            result['issues'] = form
            return result
        authorized, is_self, issue = _entry_authority(entry, trusted, distrusted)
        if not (signer_trusted or is_self or signer_distrusted):
            result['issues'] = [f'unknown revocation signer {signer_id}']
            return result
        if signer_distrusted and not is_self:
            dropped += 1
        elif authorized:
            accepted.append(entry)
        elif entry['revoked_by'] in distrusted:
            dropped += 1
        else:
            result['issues'] = [issue]
            return result
    # Dropping these silently could lose a real revocation, so fail closed until the
    # list is removed or reissued by a revoker that is still trusted.
    if dropped:
        result['issues'].append(
            f'revocation list {document["list_id"]} relies on a revoked revoker')
    result.update(valid=True, trusted=signer_trusted, entries=accepted)
    return result


def verify_revocation_list(revocation_list, trusted_revokers, *, now=None):
    """Report validity and trust separately; only `trusted` lists establish coverage."""
    found = _evaluate_list(revocation_list, _trust_index(trusted_revokers or [], 'known_revokers'),
                           set(), _clock(now))
    return {'ok': found['valid'] and not found['expired'], 'valid': found['valid'],
            'trusted': found['trusted'], 'expired': found['expired'],
            'entries': len(found['entries']), 'issues': found['issues']}


def build_revocation_state(revocation_lists, trusted_revokers, *, now=None):
    """Merge lists; revokers whose own key is revoked lose trust until a fixed point."""
    moment = _clock(now)
    trusted = dict(_trust_index(trusted_revokers or [], 'known_revokers'))
    distrusted = set()
    while True:
        state = {'revoked': {}, 'covered': False, 'expired': False, 'issues': [], 'warnings': []}
        for document in revocation_lists or []:
            found = _evaluate_list(document, trusted, distrusted, moment)
            state['issues'].extend(found['issues'])
            state['warnings'].extend(found['warnings'])
            if not found['valid']:
                continue
            if found['expired']:
                state['expired'] = True
            elif found['trusted']:
                state['covered'] = True
            for entry in found['entries']:
                slot = (entry['key_id'], entry['key_type'])
                current = state['revoked'].get(slot)
                if current is None or _entry_ranking(entry) > _entry_ranking(current):
                    state['revoked'][slot] = entry
        fallen = [key_id for key_id in trusted if (key_id, 'agent_signing') in state['revoked']]
        if not fallen:
            return state
        for key_id in fallen:
            distrusted.add(key_id)
            del trusted[key_id]


def check_key_revocation(key_id, key_type, revocation_state):
    """Return the winning entry, or None. Time is ignored: a stolen key can backdate."""
    return revocation_state['revoked'].get((key_id, key_type))


def evaluate_revocation(keys, revocation_lists, trusted_revokers, policy='strict', *, now=None,
                        announce_gaps=True):
    """Apply a receiver policy to (key_id, key_type) pairs."""
    if policy not in REVOCATION_POLICIES:
        raise ValueError('unknown revocation policy')
    outcome = {'revocation_ok': None, 'revoked_keys': [], 'issues': [], 'warnings': [],
               'state': None}
    if policy == 'ignore':
        return outcome
    state = build_revocation_state(revocation_lists, trusted_revokers, now=now)
    outcome['state'] = state
    outcome['warnings'].extend(state['warnings'])
    outcome['issues'].extend(state['issues'])
    for key_id, key_type in keys:
        entry = check_key_revocation(key_id, key_type, state)
        if entry is not None:
            outcome['revoked_keys'].append({'key_id': key_id, 'key_type': key_type,
                                            'reason': entry['reason'],
                                            'revoked_at': entry['revoked_at']})
            outcome['issues'].append(f'{key_type} key {key_id} is revoked ({entry["reason"]})')
    gaps = []
    if state['expired']:
        gaps.append('a revocation list has expired')
    if not state['covered']:
        gaps.append('no current revocation list from a trusted revoker')
    if policy == 'strict':
        outcome['issues'].extend(gaps)
    elif announce_gaps:
        outcome['warnings'].extend(gaps)
    if outcome['issues']:
        outcome['revocation_ok'] = False
    elif state['covered'] and not state['expired']:
        outcome['revocation_ok'] = True
    return outcome


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise urllib.error.URLError('revocation endpoint redirects are refused')


def _open_url(url):
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _RefuseRedirect())
    return opener.open(url, timeout=REMOTE_TIMEOUT)


def fetch_revocation_list(url):
    """Fetch one explicitly enabled list; the caller still verifies its signatures."""
    if not isinstance(url, str) or not url.startswith('https://'):
        raise ValueError('revocation endpoints must use https')
    with _open_url(url) as response:
        raw = response.read(MAX_REMOTE_DOCUMENT + 1)
    if len(raw) > MAX_REMOTE_DOCUMENT:
        raise ValueError('remote revocation list exceeds size limit')
    return _strict_json(raw)


# --------------------------------------------------------------------------- #
# Attestation
# --------------------------------------------------------------------------- #
def _private_material(value, path='claims'):
    found = []
    if isinstance(value, dict):
        for name, item in value.items():
            if _SECRET_NAME.search(str(name)):
                found.append(f'{path}.{name}')
            found.extend(_private_material(item, f'{path}.{name}'))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_private_material(item, f'{path}[{index}]'))
    return found


def _contains_text(value, needle):
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(_contains_text(item, needle) for item in [*value.keys(), *value.values()])
    if isinstance(value, list):
        return any(_contains_text(item, needle) for item in value)
    return False


def create_attestation(actor_id, claims, sign_key, *, issuer_name=None, package_hash=None,
                       agent_key_id=None, expires_at=None, attestation_id=None, issued_at=None):
    if not isinstance(claims, dict) or not claims:
        raise ValueError('claims must be a nonempty object')
    secrets = _private_material(claims)
    if secrets or _contains_text(claims, sign_key):
        raise ValueError('claims must not contain private key material')
    key, public = _signer(sign_key)
    issuer = {'name': issuer_name or '', 'key_id': calculate_key_id(public), 'public_key': public}
    document = {'oap_attestation_version': VERSION,
                'id': attestation_id or f'urn:oap:attestation:{uuid.uuid4()}',
                'issued_at': _timestamp(issued_at),
                'expires_at': None if expires_at is None else _timestamp(expires_at),
                'issuer': issuer,
                'subject': {'actor_id': actor_id, 'package_hash': package_hash,
                            'agent_key_id': agent_key_id},
                'claims': claims}
    issues = [issue for issue in _schema_issues({**document, 'signature': 'unsigned'})]
    if issues:
        raise ValueError('; '.join(issues))
    document['signature'] = _sign(ATTESTATION_DOMAIN, document, key)
    return document


def verify_attestation(attestation, issuers, package_hash=None, *, actor_id=None,
                       agent_key_id=None, allow_expired=False, revocation_state=None, now=None):
    """Bound attestations need a supplied hash before package_binding_checked is True."""
    result = {'ok': False, 'issues': [], 'package_bound': False,
              'package_binding_checked': False, 'issuer_key_id': None}
    issues = result['issues']
    if not isinstance(attestation, dict) or 'oap_attestation_version' not in attestation:
        issues.append('not an attestation')
        return result
    issues.extend(_schema_issues(attestation))
    if issues:
        return result
    moment = _clock(now)
    issuer, subject = attestation['issuer'], attestation['subject']
    result['issuer_key_id'] = issuer['key_id']
    try:
        if calculate_key_id(issuer['public_key']) != issuer['key_id']:
            issues.append('issuer key_id does not match its public_key')
            return result
    except (ValueError, TypeError) as exc:
        issues.append(f'invalid issuer key: {exc}')
        return result
    if not _signature_valid(ATTESTATION_DOMAIN, attestation, issuer['public_key']):
        issues.append('attestation signature invalid')
        return result
    secrets = _private_material(attestation['claims'])
    if secrets:
        issues.append('claims contain private key material: ' + ', '.join(secrets))
    trusted = _issuer_index(issuers or []).get(issuer['key_id'])
    if trusted is None:
        issues.append(f'unknown attestation issuer {issuer["key_id"]}')
    else:
        outside = sorted(set(attestation['claims']) - set(trusted['accepted_claim_types']))
        if outside:
            issues.append('issuer is not accepted for claims: ' + ', '.join(outside))
    if revocation_state is not None and check_key_revocation(
            issuer['key_id'], 'agent_signing', revocation_state) is not None:
        issues.append(f'attestation issuer {issuer["key_id"]} is revoked')
    issued = _parse_time(attestation['issued_at'])
    if issued > moment + CLOCK_SKEW:
        issues.append('attestation issued_at is in the future')
    if attestation['expires_at'] is not None:
        expires = _parse_time(attestation['expires_at'])
        if expires <= issued:
            issues.append('attestation expires_at must follow issued_at')
        elif expires <= moment and not allow_expired:
            issues.append('attestation has expired')
    if actor_id is not None and subject['actor_id'] != actor_id:
        issues.append('attestation subject actor does not match')
    if (agent_key_id is not None and subject.get('agent_key_id') is not None
            and subject['agent_key_id'] != agent_key_id):
        issues.append('attestation subject Agent key does not match')
    if subject.get('package_hash') is not None:
        result['package_bound'] = True
        if package_hash is not None:
            result['package_binding_checked'] = True
            if subject['package_hash'] != package_hash:
                issues.append('attestation is bound to a different package')
    result['ok'] = not issues
    return result


def package_content_hash(package):
    """Hash a manifest or package excluding only what attaching attestations changes.

    Member hashes are in the manifest, so this covers the archive's contents, while an
    attestation embedded in the package can still name the hash of that same package.
    """
    if isinstance(package, dict):
        manifest = package
    else:
        with zipfile.ZipFile(package) as archive:
            with archive.open('manifest.json') as stream:
                raw = stream.read(MAX_DOCUMENT + 1)
            if len(raw) > MAX_DOCUMENT:
                raise ValueError('manifest too large')
            manifest = _strict_json(raw)
    body = {key: value for key, value in manifest.items()
            if key not in ('signature', 'attestations')}
    bundle = dict(body.get('bundle') or {})
    bundle['members'] = [member for member in bundle.get('members', [])
                         if not member.startswith('attestations/')]
    body['bundle'] = bundle
    return 'sha256:' + hashlib.sha256(PACKAGE_DOMAIN + _json_bytes(body)).hexdigest()
