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
    import_actor,
    check_rider,
    check_call,
    studio_export_actor,
    oap_to_studio,
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
    "import_actor",
    "check_rider",
    "check_call",
    "studio_export_actor",
    "oap_to_studio",
]