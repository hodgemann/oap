#!/usr/bin/env python3
"""
oap_core.py -- Open Actor Protocol (OAP) v0.1 reference implementation.

Program-agnostic: any studio can import oap and speak the standard.

Capabilities:
  - identity       ed25519 DID generation (falls back to UUID without `cryptography`)
  - package        build a tiered .oap zip, fill SHA-256 hashes, optional signing
  - verify         verify a .oap zip's hashes and signature without installing it
  - import         extract a .oap into a target dir and verify hashes
  - check-call     compare a casting call against an actor's rider
  - studio-export  build an OAP manifest from a studio's actors/<id>/ folder
  - studio-import  scaffold a studio actor from an imported .oap

CLI:
  python oap_core.py identity
  python oap_core.py package --source DIR --out FILE --tier portfolio|full [--sign PRIV_B64]
  python oap_core.py verify --oap FILE
  python oap_core.py import --oap FILE --target DIR
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
import sys
import uuid
import zipfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

OAP_VERSION = "0.1.0"

# --- Rider enums (ordered; a project level must not exceed the rider level) ---
CONTENT_ENUMS: Dict[str, List[str]] = {
    "nudity": ["none", "implied", "explicit"],
    "sexual_content": ["none", "implied", "explicit"],
    "blood_gore": ["none", "mild", "graphic"],
    "violence": ["none", "action", "graphic"],
}

# --- Clearance ordering for tiered packaging ---
CLEARANCE_ORDER = {"public": 0, "audition": 1, "cast": 2}
TIER_MAX_CLEARANCE = {"portfolio": "public", "full": "cast"}

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
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


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
            "locked_seed": None,
            "locked_params": None,
            "anchor": {"file": None, "clearance": "cast", "sha256": None},
            "anchor_transcript": None,
            "profile": None,
            "demo": {"file": None, "clearance": "public", "sha256": None},
        },
        "protection": {"tier": 1, "mechanism": "encrypted_at_rest",
                       "access_endpoint": None},
        "provenance": {
            "audio_watermark": {"scheme": "the_seal", "status": "reserved"},
            "visual_watermark": {"scheme": "c2pa", "status": "reserved"},
            "training_disclosure": "",
        },
        "signature": {"algorithm": "ed25519", "value": None, "signed_at": None},
    }


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #
def _canonical(manifest: Dict[str, Any]) -> bytes:
    m = dict(manifest)
    m.pop("signature", None)
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: Dict[str, Any], private_b64: str) -> Dict[str, Any]:
    if not HAS_CRYPTO:
        raise RuntimeError("Signing requires the `cryptography` package.")
    sk = Ed25519PrivateKey.from_private_bytes(_b64d(private_b64))
    sig = sk.sign(_canonical(manifest))
    manifest["signature"] = {
        "algorithm": "ed25519", "value": _b64e(sig), "signed_at": now_iso(),
    }
    return manifest


def verify_signature(manifest: Dict[str, Any]) -> Tuple[bool, str]:
    sig = manifest.get("signature") or {}
    pub = (manifest.get("agent") or {}).get("public_key")
    val = sig.get("value")
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


# --------------------------------------------------------------------------- #
# Packaging
# --------------------------------------------------------------------------- #
def package_actor(source_dir: str, output_path: str, tier: str = "portfolio",
                  sign_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a .oap zip from a source dir containing manifest.json plus the asset
    files it references. Fills SHA-256 hashes, filters by clearance vs tier.
    """
    if tier not in TIER_MAX_CLEARANCE:
        raise ValueError(f"tier must be one of {list(TIER_MAX_CLEARANCE)}")
    manifest_path = os.path.join(source_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    max_clearance = CLEARANCE_ORDER[TIER_MAX_CLEARANCE[tier]]

    # Fill hashes for listed assets that exist on disk.
    for ref in iter_asset_refs(manifest):
        src = os.path.join(source_dir, ref["file"])
        if os.path.isfile(src):
            ref["sha256"] = sha256_file(src)
        else:
            ref["sha256"] = None

    if sign_key:
        sign_manifest(manifest, sign_key)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    included = ["manifest.json"]
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json",
                    json.dumps(manifest, indent=2, sort_keys=False))
        for ref in iter_asset_refs(manifest):
            clearance = ref.get("clearance", "cast")
            if CLEARANCE_ORDER.get(clearance, 2) > max_clearance:
                continue
            src = os.path.join(source_dir, ref["file"])
            if os.path.isfile(src):
                zip_path = ref["file"].replace("\\", "/")
                zf.write(src, zip_path)
                included.append(zip_path)
    return {"output": output_path, "tier": tier, "included": included}


def verify_package(oap_path: str) -> Dict[str, Any]:
    """Verify hashes + signature of a .oap without installing it."""
    issues: List[str] = []
    checked = 0
    with zipfile.ZipFile(oap_path, "r") as zf:
        try:
            manifest = json.loads(zf.read("manifest.json"))
        except KeyError:
            return {"ok": False, "issues": ["manifest.json missing"], "checked": 0,
                    "signature": "manifest.json missing", "signature_valid": False}
        except Exception as e:
            return {"ok": False, "issues": [f"manifest.json corrupt: {e}"], "checked": 0,
                    "signature": "manifest.json corrupt", "signature_valid": False}

        names = set(zf.namelist())
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
    if has_sig and not sig_ok:
        issues.append(f"signature: {sig_msg}")

    return {
        "ok": len(issues) == 0 and (sig_ok if has_sig else True),
        "issues": issues,
        "checked": checked,
        "signature": sig_msg,
        "signature_valid": sig_ok,
    }


def _is_safe_path(base_dir: str, path: str) -> bool:
    base = os.path.abspath(base_dir)
    target = os.path.abspath(os.path.join(base_dir, path))
    return os.path.commonpath([base]) == os.path.commonpath([base, target])


def import_actor(oap_path: str, target_dir: str, verify: bool = True) -> Dict[str, Any]:
    """Extract a .oap into target_dir, preserving internal layout with traversal protection."""
    os.makedirs(target_dir, exist_ok=True)
    if verify:
        v = verify_package(oap_path)
        if not v["ok"]:
            return {"ok": False, "issues": v["issues"], "extracted": False}
    with zipfile.ZipFile(oap_path, "r") as zf:
        for member in zf.infolist():
            if not _is_safe_path(target_dir, member.filename):
                return {
                    "ok": False,
                    "issues": [f"unsafe path in zip: '{member.filename}' attempts directory traversal"],
                    "extracted": False,
                }
        zf.extractall(target_dir)
    with open(os.path.join(target_dir, "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)
    return {"ok": True, "issues": [], "extracted": True, "manifest": manifest}


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
# Studio bridge (pragmatic v0.1)
# --------------------------------------------------------------------------- #
def studio_export_actor(studio_root: str, actor_id: str) -> Dict[str, Any]:
    """Build an OAP manifest from a studio's actors/<id>/ folder.

    NOTE: the host studio stores the visual contract and voice block in actor.json.
    Content restrictions are run-level, not per-actor, so this emits a default
    rider for the Director to edit. Confirm exact actor.json keys on the box.
    """
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
    actor_dir = os.path.join(studio_root, "actors", actor_id)
    refs_dir = os.path.join(actor_dir, "refs")
    os.makedirs(refs_dir, exist_ok=True)

    # Copy identity assets into the studio actor folder.
    identity_dir = os.path.join(extracted_dir, "identity")
    copied = []
    if os.path.isdir(identity_dir):
        for fn in os.listdir(identity_dir):
            src = os.path.join(identity_dir, fn)
            if fn.endswith(".wav"):
                dst = os.path.join(refs_dir, f"{actor_id}.wav")
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


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="oap_core", description="OAP v0.1 reference tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("identity", help="generate a DID / keypair")

    p = sub.add_parser("package", help="build a .oap zip")
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tier", default="portfolio", choices=list(TIER_MAX_CLEARANCE))
    p.add_argument("--sign", default=None, help="base64 ed25519 private key")

    p = sub.add_parser("verify", help="verify a .oap zip")
    p.add_argument("--oap", required=True)

    p = sub.add_parser("import", help="extract + verify a .oap into a target dir")
    p.add_argument("--oap", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--no-verify", action="store_true")

    p = sub.add_parser("check-call", help="check a casting call against a rider")
    p.add_argument("--manifest", required=True)
    p.add_argument("--call", required=True)

    p = sub.add_parser("studio-export", help="build an OAP manifest from a studio actor")
    p.add_argument("--studio-root", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--out", required=True, help="output dir for manifest.json")

    p = sub.add_parser("studio-import", help="scaffold a studio actor from a .oap")
    p.add_argument("--oap", required=True)
    p.add_argument("--studio-root", required=True)
    p.add_argument("--actor", default=None)

    args = ap.parse_args(argv)

    if args.cmd == "identity":
        ident = generate_identity()
        print(json.dumps({k: v for k, v in ident.items() if k != "_private"}, indent=2))
        if ident.get("_private"):
            print("\nPRIVATE KEY (keep secret):", ident["_private"], file=sys.stderr)
        if not HAS_CRYPTO:
            print("note: `cryptography` not installed; used UUID DID, no signing.",
                  file=sys.stderr)
        return 0

    if args.cmd == "package":
        sign_key = args.sign
        if not sign_key and "OAP_PRIVATE_KEY" in os.environ:
            sign_key = os.environ["OAP_PRIVATE_KEY"]
        elif sign_key:
            if sign_key.startswith("env:"):
                var_name = sign_key[4:]
                sign_key = os.environ.get(var_name)
                if not sign_key:
                    ap.error(f"environment variable '{var_name}' not set")
            elif sign_key.startswith("@"):
                key_path = sign_key[1:]
                try:
                    with open(key_path, "r", encoding="utf-8") as f:
                        sign_key = f.read().strip()
                except Exception as e:
                    ap.error(f"failed to read key file '{key_path}': {e}")
        res = package_actor(args.source, args.out, args.tier, sign_key)
        print(json.dumps(res, indent=2))
        return 0

    if args.cmd == "verify":
        res = verify_package(args.oap)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1

    if args.cmd == "import":
        res = import_actor(args.oap, args.target, verify=not args.no_verify)
        print(json.dumps({k: res[k] for k in ("ok", "issues", "extracted")}, indent=2))
        return 0 if res["ok"] else 1

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
        imp = import_actor(args.oap, target_dir=os.path.join(args.studio_root, ".oap_tmp"),
                           verify=True)
        if not imp["ok"]:
            print(json.dumps({"ok": False, "issues": imp["issues"]}, indent=2))
            return 1
        res = oap_to_studio(imp["manifest"],
                            os.path.join(args.studio_root, ".oap_tmp"),
                            args.studio_root, args.actor)
        print(json.dumps(res, indent=2))
        return 0

    ap.error("unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())