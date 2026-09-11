import json
import os
import tempfile
import zipfile
import pytest

import oap
from oap.core import (
    _canonical,
    _is_safe_path,
    check_call,
    check_rider,
    generate_identity,
    import_actor,
    new_manifest,
    oap_to_studio,
    package_actor,
    sha256_bytes,
    sha256_file,
    sign_manifest,
    studio_export_actor,
    verify_package,
    verify_signature,
)


def test_identity_generation():
    ident = generate_identity()
    assert ident["did"].startswith("oap:ed25519:")
    assert ident["public_key"] is not None
    assert ident["_private"] is not None


def test_identity_fallback(monkeypatch):
    monkeypatch.setattr(oap.core, "HAS_CRYPTO", False)
    ident = generate_identity()
    assert ident["did"].startswith("oap:uuid:")
    assert ident["public_key"] is None
    assert ident["_private"] is None


def test_canonical_manifest():
    m = {
        "b": 2,
        "a": 1,
        "signature": {"value": "test_sig"},
    }
    canon = _canonical(m)
    assert b"signature" not in canon
    assert canon == b'{"a":1,"b":2}'


def test_sign_and_verify_signature():
    ident = generate_identity()
    manifest = new_manifest("test_actor", "Test Actor")
    manifest["agent"]["public_key"] = ident["public_key"]
    manifest["identity"]["did"] = ident["did"]

    # Before signing
    valid, msg = verify_signature(manifest)
    assert not valid
    assert "no signature" in msg

    # Sign manifest
    sign_manifest(manifest, ident["_private"])
    assert manifest["signature"]["value"] is not None

    valid, msg = verify_signature(manifest)
    assert valid
    assert msg == "signature valid"

    # Tamper with manifest
    manifest["identity"]["display_name"] = "Forged Actor"
    valid, msg = verify_signature(manifest)
    assert not valid
    assert "signature invalid" in msg


def test_packaging_portfolio_and_full_tier():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(os.path.join(src, "portfolio"), exist_ok=True)
        os.makedirs(os.path.join(src, "identity"), exist_ok=True)

        headshot_path = os.path.join(src, "portfolio", "headshot.png")
        ref_path = os.path.join(src, "identity", "ref.png")
        with open(headshot_path, "wb") as f:
            f.write(b"headshot-bytes")
        with open(ref_path, "wb") as f:
            f.write(b"raw-reference-bytes")

        ident = generate_identity()
        manifest = new_manifest("actor_x")
        manifest["agent"]["public_key"] = ident["public_key"]
        manifest["visual"]["sheets"] = [
            {"file": "portfolio/headshot.png", "clearance": "public", "sha256": None},
            {"file": "identity/ref.png", "clearance": "cast", "sha256": None},
        ]

        with open(os.path.join(src, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        # 1. Portfolio package
        portfolio_zip = os.path.join(td, "actor_portfolio.oap")
        res_port = package_actor(src, portfolio_zip, tier="portfolio", sign_key=ident["_private"])
        assert "portfolio/headshot.png" in res_port["included"]
        assert "identity/ref.png" not in res_port["included"]

        # Verification of portfolio zip
        v_port = verify_package(portfolio_zip)
        assert v_port["ok"] is True
        assert v_port["signature_valid"] is True
        assert v_port["checked"] == 1

        # 2. Full package
        full_zip = os.path.join(td, "actor_full.oap")
        res_full = package_actor(src, full_zip, tier="full", sign_key=ident["_private"])
        assert "portfolio/headshot.png" in res_full["included"]
        assert "identity/ref.png" in res_full["included"]

        # Verification of full zip
        v_full = verify_package(full_zip)
        assert v_full["ok"] is True
        assert v_full["signature_valid"] is True
        assert v_full["checked"] == 2


def test_verify_detects_tampered_signature():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src, exist_ok=True)
        img_path = os.path.join(src, "headshot.png")
        with open(img_path, "wb") as f:
            f.write(b"image")

        ident = generate_identity()
        manifest = new_manifest("actor_y")
        manifest["agent"]["public_key"] = ident["public_key"]
        manifest["visual"]["sheets"].append({
            "file": "headshot.png",
            "clearance": "public",
            "sha256": None,
        })
        with open(os.path.join(src, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        zip_path = os.path.join(td, "bundle.oap")
        package_actor(src, zip_path, tier="portfolio", sign_key=ident["_private"])

        # Corrupt manifest in zip
        bad_zip = os.path.join(td, "bad_bundle.oap")
        with zipfile.ZipFile(zip_path, "r") as zin, zipfile.ZipFile(bad_zip, "w") as zout:
            for item in zin.infolist():
                content = zin.read(item.filename)
                if item.filename == "manifest.json":
                    m_data = json.loads(content)
                    m_data["identity"]["actor_id"] = "tampered_actor"
                    content = json.dumps(m_data).encode("utf-8")
                zout.writestr(item, content)

        v = verify_package(bad_zip)
        assert v["ok"] is False
        assert v["signature_valid"] is False
        assert any("signature" in issue for issue in v["issues"])


def test_verify_detects_tampered_asset():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src, exist_ok=True)
        img_path = os.path.join(src, "headshot.png")
        with open(img_path, "wb") as f:
            f.write(b"original")

        manifest = new_manifest("actor_z")
        manifest["visual"]["sheets"].append({
            "file": "headshot.png",
            "clearance": "public",
            "sha256": None,
        })
        with open(os.path.join(src, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        zip_path = os.path.join(td, "bundle.oap")
        package_actor(src, zip_path, tier="portfolio")

        # Corrupt asset in zip
        bad_zip = os.path.join(td, "bad_asset.oap")
        with zipfile.ZipFile(zip_path, "r") as zin, zipfile.ZipFile(bad_zip, "w") as zout:
            for item in zin.infolist():
                content = zin.read(item.filename)
                if item.filename == "headshot.png":
                    content = b"tampered_bytes"
                zout.writestr(item, content)

        v = verify_package(bad_zip)
        assert v["ok"] is False
        assert any("hash mismatch" in issue for issue in v["issues"])


def test_safe_path_checker():
    base = os.path.abspath("target_dir")
    assert _is_safe_path(base, "normal.txt")
    assert _is_safe_path(base, "sub/dir/file.png")
    assert not _is_safe_path(base, "../evil.txt")
    assert not _is_safe_path(base, "../../root.txt")


def test_import_actor_rejects_zip_slip():
    with tempfile.TemporaryDirectory() as td:
        bad_zip = os.path.join(td, "malicious.oap")
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("manifest.json", json.dumps(new_manifest("actor_bad")))
            zf.writestr("../../escape.txt", "pwned")

        dest = os.path.join(td, "import_target")
        res = import_actor(bad_zip, dest, verify=False)
        assert res["ok"] is False
        assert any("attempts directory traversal" in issue for issue in res["issues"])
        assert not os.path.exists(os.path.join(td, "escape.txt"))


def test_check_rider_content_and_commercial():
    rider = {
        "content": {
            "nudity": "none",
            "sexual_content": "none",
            "blood_gore": "mild",
            "violence": "action",
        },
        "commercial": {
            "political_ads": False,
            "excluded_categories": ["gambling", "tobacco"],
            "excluded_brands": ["BrandX"],
        },
    }

    # 1. Valid matching project
    ok_proj = {
        "content": {"violence": "action", "blood_gore": "none"},
        "intent": "short_film",
    }
    assert check_rider(rider, ok_proj) == []

    # 2. Exceeding level
    bad_proj_1 = {
        "content": {"violence": "graphic"},
    }
    conflicts_1 = check_rider(rider, bad_proj_1)
    assert any("violence: project 'graphic' exceeds rider 'action'" in c for c in conflicts_1)

    # 3. Unknown rating level (fails closed!)
    bad_proj_unknown = {
        "content": {"violence": "extreme_gore"},
    }
    conflicts_unknown = check_rider(rider, bad_proj_unknown)
    assert any("is not a recognized rating" in c for c in conflicts_unknown)

    # 4. Political ad
    bad_proj_political = {
        "intent": "political_ad",
    }
    conflicts_pol = check_rider(rider, bad_proj_political)
    assert any("political ads are not permitted" in c for c in conflicts_pol)

    # 5. Excluded category and brand (case insensitive)
    bad_proj_comm = {
        "commercial_category": "GAMBLING",
        "brand": "brandx",
    }
    conflicts_comm = check_rider(rider, bad_proj_comm)
    assert any("category 'GAMBLING' is excluded" in c for c in conflicts_comm)
    assert any("brand 'brandx' is excluded" in c for c in conflicts_comm)


def test_check_call_wardrobe_conflict():
    manifest = new_manifest("actor_wardrobe")
    manifest["visual"]["wardrobe_is_identity"] = True

    call = {
        "project": {"content": {}},
        "role": {"requires_wardrobe_change": True},
    }
    res = check_call(manifest, call)
    assert res["compatible"] is False
    assert any("wardrobe_is_identity is true" in c for c in res["conflicts"])


def test_studio_export_and_import():
    with tempfile.TemporaryDirectory() as td:
        studio_root = os.path.join(td, "studio")
        actor_dir = os.path.join(studio_root, "actors", "lead_actor")
        os.makedirs(actor_dir, exist_ok=True)

        actor_json = {
            "actor_id": "lead_actor",
            "display_name": "Lead Actor",
            "visual_contract": "Cinematic 35mm grain",
            "voice": {
                "provider": "chub",
                "profile": "hero_voice",
                "ref_status": "locked_in",
                "locked_seed": 12345,
                "ref_text": "Sample speech transcript.",
            },
        }
        with open(os.path.join(actor_dir, "actor.json"), "w", encoding="utf-8") as f:
            json.dump(actor_json, f)

        with open(os.path.join(actor_dir, "ref1.png"), "wb") as f:
            f.write(b"ref1")

        # Export
        manifest = studio_export_actor(studio_root, "lead_actor")
        assert manifest["identity"]["actor_id"] == "lead_actor"
        assert manifest["visual"]["visual_contract"] == "Cinematic 35mm grain"
        assert manifest["voice"]["status"] == "locked_in"
        assert manifest["voice"]["locked_seed"] == 12345

        # Import into another studio root
        studio_root_2 = os.path.join(td, "studio2")
        extracted_dir = os.path.join(td, "extracted")
        os.makedirs(os.path.join(extracted_dir, "identity"), exist_ok=True)
        with open(os.path.join(extracted_dir, "identity", "lead_actor.wav"), "wb") as f:
            f.write(b"wav_bytes")

        oap_to_studio(manifest, extracted_dir, studio_root_2, "lead_actor")
        imported_actor_json = os.path.join(studio_root_2, "actors", "lead_actor", "actor.json")
        assert os.path.exists(imported_actor_json)
        with open(imported_actor_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["actor_id"] == "lead_actor"
        assert data["voice"]["locked_seed"] == 12345
        assert data["voice"]["ref_source"] == "oap_import"
