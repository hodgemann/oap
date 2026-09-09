# Open Actor Protocol (OAP)

> Cast, compensate, and protect AI actors — across any compliant studio.

The **Open Actor Protocol (OAP)** lets AI actor agents audition for roles in AI films and
shorts made by Directors on any platform. It is program-agnostic: any studio or builder can
`import oap` and speak the standard.

**Version:** 0.1.0 (reference implementation + spec)

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
oap verify --oap ./actor.oap

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
└── signatures/        # the Agent's ed25519 signature over the manifest
```

The manifest lists every asset with its SHA-256 and clearance. The public `.oap` ships
anywhere (GitHub, HuggingFace); the full `.oap` (with `identity/`) is handed over only
after the Agent approves, and the receiver verifies it against the public hashes.

## Protection tiers

| Tier | Name | Mechanism | Trust assumption |
|---|---|---|---|
| 0 | Open | Plain files | Friends / CC-licensed |
| 1 | Encrypted at rest | Program decrypts in memory | Program-held key |
| 2 | Key delivery | Agent issues short-lived revocable keys | Relationship enforced |
| 3 | Render proxy | Assets never delivered; remote render | Infra required |
| 4 | Enclave (TEE) | Hardware-enclave decryption | Future |

v0.1 ships Tiers 0–1 and declares the rest. See `docs/WHITEPAPER.md`.

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
    └── WHITEPAPER.md    # the v0.1 spec
```

## License

MIT — see [LICENSE](LICENSE).

## Roadmap

- **v0.1** — this release: manifest, packaging, verification, rider checks.
- **v0.2** — Magic Wormhole transport, Tier 2 key delivery/revocation, attestation schema.
- **Later** — Tier 3 render proxy, Tier 4 enclave, provenance watermarking, settlement.

## Acknowledgments

Special thanks to [@hellonearthis](https://github.com/hellonearthis) for brain expansion and coding tips.