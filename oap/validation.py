"""Offline JSON Schema validation; unknown extension keys remain permitted."""
import json
import datetime
import re
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker

SCHEMAS = {
    'oap.actor.manifest': 'oap.actor.manifest.schema.json',
    'oap.casting_call': 'oap.casting_call.schema.json',
    'oap.role_agreement': 'oap.role_agreement.schema.json',
}


FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=ValueError)
def _date_time(value):
    if not isinstance(value, str):
        return True  # Type constraints belong to the schema.
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        return False
    datetime.datetime.fromisoformat(value.upper().replace('Z', '+00:00'))
    return True


def validate_document(document):
    """Return {ok, issues} with JSON paths; this does not establish trust/signatures."""
    if not isinstance(document, dict):
        return {'ok': False, 'issues': ['$: expected an object']}
    kind = document.get('kind')
    if not isinstance(kind, str) or kind not in SCHEMAS:
        return {'ok': False, 'issues': ['$.kind: unsupported document kind']}
    schema = json.loads(files('oap').joinpath('schemas').joinpath(SCHEMAS[kind]).read_text(encoding='utf-8'))
    validator = Draft202012Validator(schema, format_checker=FORMATS)
    issues = []
    for error in sorted(validator.iter_errors(document), key=lambda e: str(list(e.absolute_path))):
        path = '$' + ''.join(f'[{part}]' if isinstance(part, int) else f'.{part}'
                             for part in error.absolute_path)
        issues.append(f'{path}: {error.message}')
    if not issues and kind == 'oap.role_agreement' and document['agent_did'] == document['director_did']:
        issues.append('$.director_did: Agent and Director must use distinct keys')
    return {'ok': not issues, 'issues': issues}
