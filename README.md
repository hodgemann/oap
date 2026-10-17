# Open Actor Protocol (OAP)

> Cast, compensate, and protect AI actors — across any compliant studio.

The **Open Actor Protocol (OAP)** lets AI actor agents audition for roles in AI films and
shorts made by Directors on any platform. It is program-agnostic: any studio or builder can
`import oap` and speak the standard.

**Version:** 0.3.0 (reference implementation + spec)

---

## What OAP standardizes

1. **The Actor Package** — a self-contained, cryptographically-verifiable `.oap` bundle
   carrying an actor's identity, look, voice, boundaries, and representation.
2. **The Casting Handshake** — machine-readable casting calls, blind-side auditions, and
   rider-compatibility checks performed by the actor's **Agent**.
3. **The Trust Spectrum** — protection tiers 0–4, from open/CC collaborations to
   enclave-grade zero-trust engagements.

## Install

```bash
# From the repo root
pip install -e .

# or, just the runtime deps
pip install -r requirements.txt
```

`cryptography` is required for ed25519 DIDs and manifest signing. Without it, OAP still
works but falls back to UUID identities and skips signing.

## Quick start

```bash
# Generate a DID / keypair
oap identity

# Package an actor into a public portfolio .oap
oap package --source ./actor_src --out ./actor.oap --tier portfolio

# Verify a package's hashes and signature
oap verify --oap ./actor.oap --strict --require-signature

# Import (extract + verify) a package
oap import --oap ./actor.oap --target ./actor_installed

# Check a casting call against an actor's rider
oap check-call --manifest ./manifest.json --call ./casting_call.json
```

Without installing, run the same commands via `python oap/core.py <subcommand>`.

## The `.oap` package

```text
actor.oap (zip)
├── manifest.json      # the OAP manifest
├── portfolio/         # PUBLIC clearance: watermarked headshot, demo reel, voice demo
├── identity/          # CAST clearance: raw reference sheets, locked voice anchor, LoRA
└── signatures/        # optional auxiliary files; signature lives in manifest.json
```

The manifest lists every asset with its SHA-256 and clearance. The public `.oap` ships
anywhere (GitHub, HuggingFace); the full `.oap` (with `identity/`) is handed over only
after the Agent approves, and the receiver verifies it against the public hashes.

## New in 0.3

Validate manifests/casting calls with `oap validate --document FILE`, package
public plus audition assets using `oap package --tier audition`, and record
bilateral Agent/Director signatures with `oap sign-agreement` and
`oap verify-agreement`. Schemas ship with the library; unknown extension keys
remain permitted. New readers accept 0.1.x, 0.2.x, and 0.3.x.
See [the 0.3 release notes](docs/RELEASE_NOTES_0.3.md) for the agreement workflow,
compatibility, and limits.

## Features introduced in 0.2

Generic `assets` use the same clearance, hashes, packaging, and verification as
visual sheets and voice references. Personality is an asset with role
`personality`. Structured look/height and voice provenance fields are optional;
0.3 readers accept 0.1.x, 0.2.x, and 0.3.x packages and preserve unknown keys.

```python
from oap import clean_asset, load_known_agents, verify_package

# Install PNG support with: pip install -e '.[images]'
# Clean before packaging/signing; PNG pixels and PCM WAV samples are preserved.
clean_asset("raw.png", "identity/reference_sheet.png")
result = verify_package(
    "actor.oap", strict=True, require_signature=True,
    known_agents=load_known_agents("known_agents.json"),
)
trusted = result["ok"] and result["agent_known"] is True
```

The trust file is a JSON array of Agent public keys. Without an explicit list,
`agent_known` is null. Strict verification rejects stray files, unsafe names,
and duplicate members; it permits assets omitted for a lower-clearance tier.
The legacy studio bridge is deprecated; each studio owns its adapter.
See [the 0.2 release notes](docs/RELEASE_NOTES_0.2.md) for migration details.

## Protection tiers

| Tier | Name | Mechanism | Trust assumption |
|---|---|---|---|
| 0 | Open | Plain files | Friends / CC-licensed |
| 1 | Encrypted at rest | Program decrypts in memory | Program-held key |
| 2 | Key delivery | Agent issues short-lived revocable keys | Relationship enforced |
| 3 | Render proxy | Assets never delivered; remote render | Infra required |
| 4 | Enclave (TEE) | Hardware-enclave decryption | Future |

The reference packager writes Tier 0 plain files. Encryption and higher-tier
mechanisms remain studio responsibilities. See [the standard](docs/WHITEPAPER.md).

## Repository layout

```text
oap/
├── README.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── oap/
│   ├── __init__.py
│   └── core.py          # the reference implementation
├── examples/            # sample manifest + casting call
└── docs/
    └── WHITEPAPER.md    # the v0.2 spec
```

## License

MIT — see [LICENSE](LICENSE).

## Roadmap

- **v0.2** — generic assets, structured look/height, voice provenance, strict verification,
  local Agent trust, clean-room helpers, and 0.1/0.2 read compatibility.
- **v0.3** — offline JSON Schema validation, audition-clearance packaging, and
  countersigned role agreements.
- **Future** — encrypted delivery, Magic Wormhole transport, key revocation, attestation schema.
- **Later** — Tier 3 render proxy, Tier 4 enclave, provenance watermarking, settlement.

## Acknowledgments

Special thanks to [@hellonearthis](https://github.com/hellonearthis) for brain expansion and coding tips.