"""
Open Actor Protocol (OAP).

A program-agnostic protocol for casting, compensating, and protecting AI actors.
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
]
