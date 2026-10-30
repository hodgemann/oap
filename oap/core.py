#!/usr/bin/env python3
"""
oap_core.py -- Open Actor Protocol (OAP) v0.4 reference implementation.

Program-agnostic: any studio can import oap and speak the standard.

Capabilities:
  - identity       Agent Ed25519 signing and Director X25519 decryption keys
  - package        build signed tiered .oap archives and encrypt cast assets
  - verify         check exact archive inventory, hashes, signature, and trust
  - import         install verified archive bytes without decrypting cast assets
  - check-call     compare a casting call against an actor's rider
  - studio-export  build an OAP manifest from a studio's actors/<id>/ folder
  - studio-import  deprecated; encrypted 0.4 packages need studio-owned adapters

CLI:
  python oap/core.py identity --private-out AGENT.private.json --public-out AGENT.public.json
  python oap/core.py recipient-key --private-out DIRECTOR.private.json --public-out DIRECTOR.public.json
  python oap/core.py package --source DIR --out FILE --tier full --sign-key-file AGENT.private.json --recipient-key DIRECTOR.public.json
  python oap/core.py verify --oap FILE --known-agents TRUST.json
  python oap/core.py import --oap FILE --target DIR --known-agents TRUST.json
  python oap_core.py check-call --manifest FILE --call FILE
  python oap_core.py studio-export --studio-root /path/to/studio-project --actor my_actor --out ./oap_src
  python oap_core.py studio-import --oap ./actor.oap --studio-root /path/to/studio-project
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import ntpath
import re
import tempfile
import warnings
import sys
import uuid
import zipfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OAP_VERSION = "0.4.0"

# --- Rider enums (ordered; a project level must not exceed the rider level) ---
CONTENT_ENUMS: Dict[str, List[str]] = {
    "nudity": ["none", "implied", "explicit"],
    "sexual_content": ["none", "implied", "explicit"],
    "blood_gore": ["none", "mild", "graphic"],
    "violence": ["none", "action", "graphic"],
}

# --- Clearance ordering for tiered packaging ---
CLEARANCE_ORDER = {"public": 0, "audition": 1, "cast": 2}
TIER_MAX_CLEARANCE = {"portfolio": "public", "audition": "audition", "full": "cast"}

# --- Optional ed25519 support ---
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    HAS_CRYPTO = True
except Exception:  # pragma: no cover
    HAS_CRYPTO = False


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    raw = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    if _b64e(raw) != s:
        raise ValueError("noncanonical base64url text")
    return raw


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------- #
# Identity (DID)
# --------------------------------------------------------------------------- #
def generate_identity() -> Dict[str, Optional[str]]:
    """Return {did, public_key, _private}. ed25519 if available, else UUID."""
    if not HAS_CRYPTO:
        uid = str(uuid.uuid4())
        return {"did": f"oap:uuid:{uid}", "public_key": None, "_private": None}
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {
        "did": "oap:ed25519:" + _b64e(pk_bytes),
        "public_key": _b64e(pk_bytes),
        "_private": _b64e(sk_bytes),
    }


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #
def new_manifest(actor_id: str, display_name: Optional[str] = None) -> Dict[str, Any]:
    return {
        "oap_version": OAP_VERSION,
        "kind": "oap.actor.manifest",
        "issued_at": now_iso(),
        "identity": {
            "actor_id": actor_id,
            "display_name": display_name or actor_id,
            "did": None,
            "species": "ai_actor",
            "born": now_iso(),
            "homepage": None,
        },
        "agent": {
            "name": None,
            "endpoint": None,
            "public_key": None,
            "payment": {"methods": [], "address": None},
            "rates": {
                "audition": "free",
                "per_scene": "",
                "per_production": "",
                "currency": "USD",
                "notes": "",
            },
        },
        "rider": {
            "content": {
                "nudity": "none",
                "sexual_content": "none",
                "blood_gore": "none",
                "violence": "action",
            },
            "commercial": {
                "political_ads": False,
                "excluded_categories": [],
                "excluded_brands": [],
            },
            "usage": {"voice_use": ["dialogue"]},
            "notes": "",
        },
        "visual": {
            "core_identity": "",
            "default_wardrobe": "",
            "wardrobe_is_identity": False,
            "visual_contract": "",
            "height": None,
            "contract": {"default_sheet": None, "sheets": {}},
            "demo_reel": {"file": None, "clearance": "public", "sha256": None},
            "sheets": [],
            "lora": {"file": None, "clearance": "cast", "sha256": None,
                     "recommended_strength": None},
        },
        "voice": {
            "status": "missing",
            "provider": None,
            "model": None,
            "model_checkpoint_sha256": None,
            "model_revision": None,
            "profile_source": None,
            "locked_seed": None,
            "locked_params": None,
            "anchor": {"file": None, "clearance": "cast", "sha256": None},
            "anchor_transcript": None,
            "profile": None,
            "demo": {"file": None, "clearance": "public", "sha256": None},
        },
        "assets": [],
        "protection": {"tier": 0, "mechanism": "plain",
                       "access_endpoint": None},
        "provenance": {
            "audio_watermark": {"scheme": "the_seal", "status": "reserved"},
            "visual_watermark": {"scheme": "c2pa", "status": "reserved"},
            "training_disclosure": "",
        },
        "bundle": {"tier": "portfolio", "members": []},
        "signature": {"algorithm": "ed25519", "value": None},
    }


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #
def _canonical(manifest: Dict[str, Any]) -> bytes:
    if isinstance(manifest.get("oap_version"), str) and supports_version(manifest["oap_version"]):
        from oap.v04 import manifest_payload
        return manifest_payload(manifest)
    m = dict(manifest)
    m.pop("signature", None)
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: Dict[str, Any], private_b64: str) -> Dict[str, Any]:
    if not HAS_CRYPTO:
        raise RuntimeError("Signing requires the `cryptography` package.")
    sk = Ed25519PrivateKey.from_private_bytes(_b64d(private_b64))
    if isinstance(manifest.get("oap_version"), str) and supports_version(manifest["oap_version"]):
        public = _b64e(sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        if (manifest.get("agent") or {}).get("public_key") != public:
            raise ValueError("Agent signing key does not match manifest public key")
    sig = sk.sign(_canonical(manifest))
    manifest["signature"] = ({"algorithm": "ed25519", "value": _b64e(sig)}
                             if supports_version(manifest.get("oap_version")) else
                             {"algorithm": "ed25519", "value": _b64e(sig), "signed_at": now_iso()})
    return manifest


def verify_signature(manifest: Dict[str, Any]) -> Tuple[bool, str]:
    sig = manifest.get("signature") or {}
    if not isinstance(sig, dict):
        return False, "invalid signature descriptor"
    pub = (manifest.get("agent") or {}).get("public_key")
    val = sig.get("value")
    if sig.get("algorithm", "ed25519") != "ed25519":
        return False, "unsupported signature algorithm"
    if supports_version(manifest.get("oap_version")) and set(sig) != {"algorithm", "value"}:
        return False, "invalid OAP 0.4 signature descriptor"
    if not val or not pub:
        return False, "no signature or public key present"
    if not HAS_CRYPTO:
        return False, "cryptography package not installed; cannot verify"
    try:
        pk = Ed25519PublicKey.from_public_bytes(_b64d(pub))
        pk.verify(_b64d(val), _canonical(manifest))
        return True, "signature valid"
    except Exception as e:
        return False, f"signature invalid: {e}"


# --------------------------------------------------------------------------- #
# Asset references
# --------------------------------------------------------------------------- #
def iter_asset_refs(manifest: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    """Yield every asset dict that carries file/clearance/sha256."""
    visual = manifest.get("visual", {})
    demo_reel = visual.get("demo_reel")
    if demo_reel and demo_reel.get("file"):
        yield demo_reel
    for sheet in visual.get("sheets", []):
        if sheet.get("file"):
            yield sheet
    lora = visual.get("lora")
    if lora and lora.get("file"):
        yield lora
    voice = manifest.get("voice", {})
    for key in ("anchor", "demo"):
        a = voice.get(key)
        if a and a.get("file"):
            yield a

    for asset in manifest.get("assets", []):
        if asset.get("file"):
            yield asset


# --------------------------------------------------------------------------- #
# Packaging
# --------------------------------------------------------------------------- #
def package_actor(source_dir: str, output_path: str, tier: str = "portfolio",
                  sign_key: Optional[str] = None,
                  recipient_public_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a signed OAP 0.4 archive; seal cast assets for named recipients."""
    from oap.v04 import package_actor as package_v04
    return package_v04(source_dir, output_path, tier, sign_key, recipient_public_keys)


def supports_version(version: str) -> bool:
    """Normal readers accept OAP 0.4.x; older formats use explicit legacy mode."""
    if not isinstance(version, str) or not re.fullmatch(r"0\.4\.[0-9]+", version):
        return False
    return True


def load_known_agents(path: str) -> List[str]:
    """Read an explicit local trust store: a JSON array of Agent public keys."""
    with open(path, encoding="utf-8") as stream:
        keys = json.load(stream)
    if not isinstance(keys, list) or any(not isinstance(key, str) or not key for key in keys):
        raise ValueError("known_agents must be a JSON array of nonempty public-key strings")
    return keys


def verify_package(oap_path: str, require_signature: bool = False, strict: bool = False,
                   known_agents: Optional[List[str]] = None, *,
                   allow_untrusted: bool = False, legacy: bool = False,
                   max_members: Optional[int] = None, max_member: Optional[int] = None,
                   max_total: Optional[int] = None) -> Dict[str, Any]:
    """Verify an OAP 0.4 package; old formats need explicit legacy=True."""
    if not legacy:
        from oap.v04 import (verify_package as verify_v04, MAX_MEMBERS, MAX_MEMBER, MAX_TOTAL)
        return verify_v04(oap_path, known_agents=known_agents,
                          allow_untrusted=allow_untrusted,
                          max_members=MAX_MEMBERS if max_members is None else max_members,
                          max_member=MAX_MEMBER if max_member is None else max_member,
                          max_total=MAX_TOTAL if max_total is None else max_total)
    try:
        return _verify_package(oap_path, require_signature, strict, known_agents)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, zipfile.BadZipFile) as exc:
        return {"ok": False, "issues": [f"invalid package: {exc}"], "checked": 0,
                "signature": "not verified", "signature_valid": False,
                "agent_known": None if known_agents is None else False}


def _verify_package(oap_path, require_signature, strict, known_agents):
    issues: List[str] = []
    checked = 0
    with zipfile.ZipFile(oap_path, "r") as zf:
        try:
            manifest = json.loads(zf.read("manifest.json"))
        except KeyError:
            return {"ok": False, "issues": ["manifest.json missing"], "checked": 0,
                    "signature": "manifest.json missing", "signature_valid": False,
                    "agent_known": None if known_agents is None else False}
        except Exception as e:
            return {"ok": False, "issues": [f"manifest.json corrupt: {e}"], "checked": 0,
                    "signature": "manifest.json corrupt", "signature_valid": False,
                    "agent_known": None if known_agents is None else False}

        if not isinstance(manifest.get("oap_version"), str) or not re.fullmatch(r"0\.(1|2|3)\.[0-9]+", manifest["oap_version"]):
            issues.append("unsupported oap_version")
        names = set(zf.namelist())
        if strict:
            allowed = {"manifest.json"} | {ref["file"] for ref in iter_asset_refs(manifest)}
            seen = set()
            for member in zf.infolist():
                name = member.filename
                if not _safe_member_name(name.rstrip("/") if member.is_dir() else name):
                    issues.append(f"unsafe member name: {name}")
                if name in seen:
                    issues.append(f"duplicate member: {name}")
                seen.add(name)
                if not member.is_dir() and name not in allowed and not name.startswith("signatures/"):
                    issues.append(f"unlisted member: {name}")
            for ref in iter_asset_refs(manifest):
                if not _safe_member_name(ref["file"]):
                    issues.append(f"unsafe asset path: {ref['file']}")
        for ref in iter_asset_refs(manifest):
            fn = ref["file"]
            norm_fn = fn.replace("\\", "/")
            zip_entry = fn if fn in names else (norm_fn if norm_fn in names else None)
            expected = ref.get("sha256")
            if not zip_entry:
                continue  # not present in this tier; verified on full handover
            if not expected:
                issues.append(f"{fn}: present but manifest has no sha256")
                continue
            actual = sha256_bytes(zf.read(zip_entry))
            checked += 1
            if actual != expected:
                issues.append(f"{fn}: hash mismatch")

    sig_ok, sig_msg = verify_signature(manifest)
    sig = manifest.get("signature") or {}
    has_sig = bool(sig.get("value"))
    if require_signature and not has_sig:
        issues.append("signature required")
    if has_sig and not sig_ok:
        issues.append(f"signature: {sig_msg}")

    return {
        "ok": len(issues) == 0 and (sig_ok if has_sig else True),
        "issues": issues,
        "checked": checked,
        "signature": sig_msg,
        "signature_valid": sig_ok,
        "agent_known": (None if known_agents is None else
                        (manifest.get("agent") or {}).get("public_key") in known_agents),
    }


def _safe_member_name(path: str) -> bool:
    return (isinstance(path, str) and bool(path) and "\\" not in path
            and "\x00" not in path and not path.startswith("/")
            and not ntpath.splitdrive(path)[0]
            and all(part not in ("", ".", "..") for part in path.split("/")))


def _is_safe_path(base_dir: str, path: str) -> bool:
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, path))
    return os.path.commonpath([base]) == os.path.commonpath([base, target])


def import_actor(oap_path: str, target_dir: str, verify: bool = True, *,
                 known_agents: Optional[List[str]] = None,
                 allow_untrusted: bool = False) -> Dict[str, Any]:
    """Install a verified 0.4 package without decrypting cast assets."""
    if not verify:
        return {"ok": False, "issues": ["OAP 0.4 import requires verification"], "extracted": False}
    from oap.v04 import import_actor as import_v04
    return import_v04(oap_path, target_dir, known_agents=known_agents,
                      allow_untrusted=allow_untrusted)


# --------------------------------------------------------------------------- #
# Rider compatibility
# --------------------------------------------------------------------------- #
def check_rider(rider: Dict[str, Any], project: Dict[str, Any]) -> List[str]:
    """Return a list of conflicts between a casting call's project and the rider."""
    conflicts: List[str] = []
    rc = rider.get("content", {})
    pc = project.get("content", {})
    for key, levels in CONTENT_ENUMS.items():
        r = str(rc.get(key, "none")).strip().lower()
        p = str(pc.get(key, "none")).strip().lower()
        if r not in levels:
            r = "none"
        if p not in levels:
            conflicts.append(
                f"content.{key}: project level '{p}' is not a recognized rating (allowed: {levels})"
            )
            continue
        if levels.index(p) > levels.index(r):
            conflicts.append(f"content.{key}: project '{p}' exceeds rider '{r}'")

    rcomm = rider.get("commercial", {})
    project_intent = str(project.get("intent", "")).strip().lower()
    if rcomm.get("political_ads") is False and project_intent in ("political_ad", "political_ads", "political"):
        conflicts.append("commercial: political ads are not permitted by this rider")

    cat = project.get("commercial_category")
    if cat:
        norm_cat = str(cat).strip().lower()
        ex_cats = [str(c).strip().lower() for c in rcomm.get("excluded_categories", [])]
        if norm_cat in ex_cats:
            conflicts.append(f"commercial: category '{cat}' is excluded by this rider")

    brand = project.get("brand")
    if brand:
        norm_brand = str(brand).strip().lower()
        ex_brands = [str(b).strip().lower() for b in rcomm.get("excluded_brands", [])]
        if norm_brand in ex_brands:
            conflicts.append(f"commercial: brand '{brand}' is excluded by this rider")

    return conflicts


def check_call(manifest: Dict[str, Any], casting_call: Dict[str, Any]) -> Dict[str, Any]:
    rider = manifest.get("rider", {})
    project = casting_call.get("project", {})
    conflicts = check_rider(rider, project)
    role = casting_call.get("role", {})
    if role.get("requires_wardrobe_change") and \
            manifest.get("visual", {}).get("wardrobe_is_identity"):
        conflicts.append("wardrobe: role requires a change but wardrobe_is_identity "
                         "is true; Agent approval required")
    return {"compatible": not conflicts, "conflicts": conflicts}


# --------------------------------------------------------------------------- #
# Deprecated generic studio bridge (legacy layout example)
# --------------------------------------------------------------------------- #
def studio_export_actor(studio_root: str, actor_id: str) -> Dict[str, Any]:
    """Build an OAP manifest from a studio's actors/<id>/ folder.

    Deprecated generic layout example. The emitted default
    rider must be replaced with the actor's actual restrictions by the caller.
    """
    warnings.warn("Generic example bridge is deprecated; studios should own their adapters.",
                  DeprecationWarning, stacklevel=2)
    if not _safe_member_name(actor_id) or "/" in actor_id:
        raise ValueError("actor_id must be a single safe path component")
    actor_dir = os.path.join(studio_root, "actors", actor_id)
    actor_json = os.path.join(actor_dir, "actor.json")
    with open(actor_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    manifest = new_manifest(actor_id, data.get("display_name") or actor_id)

    # Visual contract (tolerant key lookup; confirm on the box).
    vc = data.get("visual_contract") or data.get("visual") or data.get("contract") or ""
    manifest["visual"]["visual_contract"] = vc if isinstance(vc, str) else json.dumps(vc)

    # Reference sheets -> cast clearance (raw refs). Portfolio thumbs should be
    # added separately by the Director (watermarked).
    if os.path.isdir(actor_dir):
        for fn in sorted(os.listdir(actor_dir)):
            if fn.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                manifest["visual"]["sheets"].append({
                    "file": f"identity/{fn}", "clearance": "cast",
                    "sha256": None, "role": "reference_sheet",
                })

    # Voice block -> OAP voice provenance.
    vb = data.get("voice") or {}
    if vb:
        ref_status = vb.get("ref_status")
        manifest["voice"]["status"] = (
            "locked_in" if ref_status == "locked_in"
            else "provisional" if ref_status in ("provisional", "candidate")
            else "missing"
        )
        manifest["voice"]["provider"] = vb.get("provider")
        manifest["voice"]["profile"] = vb.get("profile")
        manifest["voice"]["locked_seed"] = vb.get("locked_seed")
        manifest["voice"]["locked_params"] = vb.get("locked_params")
        manifest["voice"]["anchor_transcript"] = vb.get("ref_text")
        anchor_rel = f"identity/{actor_id}.wav"
        manifest["voice"]["anchor"] = {
            "file": anchor_rel, "clearance": "cast", "sha256": None,
        }
    return manifest


def oap_to_studio(manifest: Dict[str, Any], extracted_dir: str,
                  studio_root: str, actor_id: Optional[str] = None) -> Dict[str, Any]:
    """Scaffold a studio actor from an imported (extracted) .oap."""
    actor_id = actor_id or manifest["identity"]["actor_id"]
    warnings.warn("Generic example bridge is deprecated; studios should own their adapters.",
                  DeprecationWarning, stacklevel=2)
    if not _safe_member_name(actor_id) or "/" in actor_id:
        raise ValueError("actor_id must be a single safe path component")
    actor_dir = os.path.join(studio_root, "actors", actor_id)
    refs_dir = os.path.join(actor_dir, "refs")
    os.makedirs(refs_dir, exist_ok=True)

    out_json = os.path.join(actor_dir, "actor.json")
    if os.path.exists(out_json):
        raise FileExistsError(out_json)

    # Copy identity assets into the studio actor folder.
    identity_dir = os.path.join(extracted_dir, "identity")
    copied = []
    if os.path.isdir(identity_dir):
        for fn in os.listdir(identity_dir):
            src = os.path.join(identity_dir, fn)
            if fn.endswith(".wav"):
                dst = os.path.join(refs_dir, fn)
            else:
                dst = os.path.join(actor_dir, fn)
            with open(src, "rb") as fs, open(dst, "wb") as fd:
                fd.write(fs.read())
            copied.append(dst)

    # Build a studio actor.json (visual contract + voice block).
    v = manifest.get("voice", {})
    actor_json = {
        "actor_id": actor_id,
        "display_name": manifest["identity"].get("display_name"),
        "visual_contract": manifest.get("visual", {}).get("visual_contract", ""),
        "voice": {
            "provider": v.get("provider"),
            "profile": v.get("profile"),
            "ref_status": "locked_in" if v.get("status") == "locked_in" else "none",
            "ref_source": "oap_import",
            "locked_seed": v.get("locked_seed"),
            "locked_params": v.get("locked_params"),
            "locked_at": now_iso() if v.get("status") == "locked_in" else None,
            "ref_text": v.get("anchor_transcript"),
            "ref_notes": "Imported via OAP.",
        },
    }
    out_json = os.path.join(actor_dir, "actor.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(actor_json, f, indent=2)
    return {"actor_dir": actor_dir, "actor_json": out_json, "copied": copied}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _private_key_file(path: str) -> str:
    with open(path, encoding="utf-8") as stream:
        value = stream.read().strip()
    if value.startswith("{"):
        value = json.loads(value)["_private"]
    if not isinstance(value, str) or not value:
        raise ValueError("private key file is empty or invalid")
    return value


def _public_key_file(path: str) -> str:
    with open(path, encoding="utf-8") as stream:
        value = stream.read().strip()
    if value.startswith("{"):
        document = json.loads(value)
        if "_private" in document:
            raise ValueError("recipient file contains a private key; share only the public identity file")
        value = document["public_key"]
    if not isinstance(value, str) or not value:
        raise ValueError("recipient public key file is empty or invalid")
    return value


def _write_identity_files(private_path: str, public_path: str,
                          identity: Dict[str, Any]) -> None:
    if os.path.abspath(private_path) == os.path.abspath(public_path):
        raise ValueError("private and public identity paths must differ")
    created = []
    try:
        for path, value, mode in (
                (private_path, identity, 0o600),
                (public_path, {k: v for k, v in identity.items() if k != "_private"}, 0o644)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, indent=2)
                stream.write("\n")
    except Exception:
        for path in created:
            os.unlink(path)
        raise


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="oap", description="OAP v0.4 reference tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("identity", help="generate an Agent signing keypair")
    p.add_argument("--private-out", required=True, help="new private identity JSON file (mode 0600)")
    p.add_argument("--public-out", required=True, help="new public identity JSON file")

    p = sub.add_parser("recipient-key", help="generate a Director decryption keypair")
    p.add_argument("--private-out", required=True, help="new private identity JSON file (mode 0600)")
    p.add_argument("--public-out", required=True, help="new public identity JSON file")

    p = sub.add_parser("package", help="build a .oap zip")
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tier", default="portfolio", choices=list(TIER_MAX_CLEARANCE))
    p.add_argument("--sign-key-file", required=True, help="Agent identity JSON or private-key file")
    p.add_argument("--recipient-key", action="append", default=[], help="Director public identity JSON or key file; repeatable")

    p = sub.add_parser("verify", help="verify a .oap zip")
    p.add_argument("--oap", required=True)
    p.add_argument("--allow-untrusted", action="store_true", help="inspect valid signatures without local trust")
    p.add_argument("--legacy", action="store_true", help="explicitly inspect a 0.1-0.3 package")
    p.add_argument("--known-agents", help="JSON file containing a list of trusted public keys")

    p = sub.add_parser("import", help="extract + verify a .oap into a target dir")
    p.add_argument("--oap", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--known-agents", help="JSON list of locally trusted Agent public keys")
    p.add_argument("--allow-untrusted", action="store_true", help="explicitly accept a valid but unknown Agent key")

    p = sub.add_parser("migrate", help="re-sign and seal a complete legacy package as OAP 0.4")
    p.add_argument("--oap", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--sign-key-file", required=True)
    p.add_argument("--recipient-key", action="append", default=[], required=True)
    p.add_argument("--known-agents", help="optional legacy Agent trust file")

    p = sub.add_parser("check-call", help="check a casting call against a rider")
    p.add_argument("--manifest", required=True)
    p.add_argument("--call", required=True)

    p = sub.add_parser("studio-export", help="build an OAP manifest from a studio actor")
    p.add_argument("--studio-root", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--out", required=True, help="output dir for manifest.json")

    p = sub.add_parser("studio-import", help="deprecated: unavailable for encrypted OAP 0.4")
    p.add_argument("--oap", required=True)
    p.add_argument("--studio-root", required=True)
    p.add_argument("--actor", default=None)

    p = sub.add_parser("validate", help="validate an OAP JSON document against its bundled schema")
    p.add_argument("--document", required=True)

    p = sub.add_parser("sign-agreement", help="sign or countersign a role agreement")
    p.add_argument("--agreement", required=True)
    p.add_argument("--role", required=True, choices=["agent", "director"])
    p.add_argument("--sign-key-file", required=True, help="private-key file or identity JSON")
    p.add_argument("--out", required=True)
    p.add_argument("--manifest", help="check source manifest before signing")
    p.add_argument("--call", help="check source casting call before signing")

    p = sub.add_parser("verify-agreement", help="require both role agreement signatures")
    p.add_argument("--agreement", required=True)
    p.add_argument("--manifest", help="optionally check the exact manifest binding")
    p.add_argument("--call", help="optionally check the exact casting call binding")

    args = ap.parse_args(argv)

    if args.cmd in ("validate", "sign-agreement", "verify-agreement"):
        # Keep module execution (python oap/core.py) and installed entry points usable.
        if __package__ in (None, ""):
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from oap.validation import validate_document
        from oap.agreements import sign_agreement, verify_agreement
        try:
            if args.cmd == "validate":
                result = validate_document(_read_json(args.document))
            elif args.cmd == "verify-agreement":
                result = verify_agreement(_read_json(args.agreement),
                    manifest=_read_json(args.manifest) if args.manifest else None,
                    casting_call=_read_json(args.call) if args.call else None)
            else:
                key = _private_key_file(args.sign_key_file)
                signed = sign_agreement(_read_json(args.agreement), args.role, key,
                    manifest=_read_json(args.manifest) if args.manifest else None,
                    casting_call=_read_json(args.call) if args.call else None)
                # Sign/validate before touching the output, including in-place signing.
                with open(args.out, "w", encoding="utf-8") as stream:
                    json.dump(signed, stream, indent=2)
                    stream.write("\n")
                result = {"ok": True, "output": args.out, "role": args.role}
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            result = {"ok": False, "issues": [str(exc)]}
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    if args.cmd in ("identity", "recipient-key"):
        if args.cmd == "identity":
            ident = generate_identity()
        else:
            from oap.v04 import generate_recipient_identity
            ident = generate_recipient_identity()
        if not ident.get("_private"):
            ap.error("cryptography is required for OAP 0.4 identities")
        try:
            _write_identity_files(args.private_out, args.public_out, ident)
        except (OSError, ValueError) as exc:
            ap.error(str(exc))
        print(json.dumps({"private_output": args.private_out,
                          "public_output": args.public_out,
                          "public_key": ident["public_key"]}, indent=2))
        return 0

    if args.cmd == "package":
        try:
            res = package_actor(args.source, args.out, args.tier,
                                _private_key_file(args.sign_key_file),
                                [_public_key_file(path) for path in args.recipient_key])
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(json.dumps({"ok": False, "issues": [str(exc)]}, indent=2))
            return 1
        print(json.dumps(res, indent=2))
        return 0

    if args.cmd == "verify":
        res = verify_package(args.oap, require_signature=True, strict=True,
                             known_agents=(load_known_agents(args.known_agents)
                             if args.known_agents else None),
                             allow_untrusted=args.allow_untrusted, legacy=args.legacy)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1

    if args.cmd == "import":
        res = import_actor(args.oap, args.target,
                           known_agents=(load_known_agents(args.known_agents)
                           if args.known_agents else None),
                           allow_untrusted=args.allow_untrusted)
        print(json.dumps({k: res[k] for k in ("ok", "issues", "extracted")}, indent=2))
        return 0 if res["ok"] else 1

    if args.cmd == "migrate":
        try:
            from oap.v04 import migrate_legacy_package
            res = migrate_legacy_package(
                args.oap, args.out, _private_key_file(args.sign_key_file),
                [_public_key_file(path) for path in args.recipient_key],
                known_agents=(load_known_agents(args.known_agents)
                              if args.known_agents else None))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(json.dumps({"ok": False, "issues": [str(exc)]}, indent=2))
            return 1
        print(json.dumps(res, indent=2))
        return 0

    if args.cmd == "check-call":
        manifest = _read_json(args.manifest)
        call = _read_json(args.call)
        res = check_call(manifest, call)
        print(json.dumps(res, indent=2))
        return 0 if res["compatible"] else 2

    if args.cmd == "studio-export":
        manifest = studio_export_actor(args.studio_root, args.actor)
        os.makedirs(args.out, exist_ok=True)
        out_path = os.path.join(args.out, "manifest.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(json.dumps({"manifest": out_path}, indent=2))
        return 0

    if args.cmd == "studio-import":
        print(json.dumps({"ok": False, "issues": [
            "studio-import cannot install encrypted OAP 0.4 assets; use a studio-owned adapter"
        ]}, indent=2))
        return 1

    ap.error("unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
