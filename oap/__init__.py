"""
Open Actor Protocol (OAP).

A program-agnostic protocol for casting and compensating AI actors, with signed identity and terms.
Any studio or builder can `import oap` and speak the standard.
"""

from .core import (
    OAP_VERSION,
    CONTENT_ENUMS,
    CLEARANCE_ORDER,
    TIER_MAX_CLEARANCE,
    generate_identity,
    new_manifest,
    sign_manifest,
    verify_signature,
    iter_asset_refs,
    package_actor,
    verify_package,
    load_known_agents,
    supports_version,
    import_actor,
    check_rider,
    check_call,
    studio_export_actor,
    oap_to_studio,
)

from .assets import clean_asset
from .validation import validate_document
from .agreements import document_sha256, new_role_agreement, sign_agreement, verify_agreement
from .v04 import (generate_recipient_identity, open_asset_buffer, migrate_legacy_package,
                  migrate_v04_package, attach_attestations)
from .trust import (
    canonical_json,
    calculate_key_id,
    load_revocation_lists,
    load_known_revokers,
    load_attestation_issuers,
    create_revocation_entry,
    create_revocation_list,
    verify_revocation_entry,
    verify_revocation_list,
    build_revocation_state,
    check_key_revocation,
    create_attestation,
    verify_attestation,
    package_content_hash,
)

__version__ = OAP_VERSION

__all__ = [
    "OAP_VERSION",
    "__version__",
    "CONTENT_ENUMS",
    "CLEARANCE_ORDER",
    "TIER_MAX_CLEARANCE",
    "generate_identity",
    "new_manifest",
    "sign_manifest",
    "verify_signature",
    "iter_asset_refs",
    "package_actor",
    "verify_package",
    "load_known_agents",
    "supports_version",
    "clean_asset",
    "import_actor",
    "check_rider",
    "check_call",
    "studio_export_actor",
    "oap_to_studio",
    "validate_document",
    "document_sha256",
    "new_role_agreement",
    "sign_agreement",
    "verify_agreement",
    "generate_recipient_identity",
    "open_asset_buffer",
    "migrate_legacy_package",
    "migrate_v04_package",
    "attach_attestations",
    "canonical_json",
    "calculate_key_id",
    "load_revocation_lists",
    "load_known_revokers",
    "load_attestation_issuers",
    "create_revocation_entry",
    "create_revocation_list",
    "verify_revocation_entry",
    "verify_revocation_list",
    "build_revocation_state",
    "check_key_revocation",
    "create_attestation",
    "verify_attestation",
    "package_content_hash",
]
