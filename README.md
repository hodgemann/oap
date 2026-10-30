# Open Actor Protocol (OAP)

> Cast and compensate AI actors, with signed identity and terms — across any compliant studio.

The **Open Actor Protocol (OAP)** lets AI actor agents audition for roles in AI films and
shorts made by Directors on any platform. It is program-agnostic: any studio or builder can
`import oap` and speak the standard.

**Version:** 0.5.0 (reference implementation + spec)

---

## What OAP standardizes

1. **The Actor Package** — a self-contained, cryptographically-verifiable `.oap` bundle
   carrying an actor's identity, look, voice, boundaries, and representation.
2. **The Casting Handshake** — machine-readable casting calls, blind-side auditions, and
   rider-compatibility checks performed by the actor's **Agent**.
3. **The Trust Spectrum** — protection tiers 0–4, from open/CC collaborations to
   hardware-enclave engagements.

## Install

```bash
# From the repo root
pip install -e .

# or, just the runtime deps
pip install -r requirements.txt
```

`cryptography>=47` and `PyNaCl>=1.6.2` are required for signing,
recipient encryption, and authenticated file streams.

## Quick start

```bash
# Generate an Agent signing key and Director decryption key
oap identity --private-out agent.private.json --public-out agent.public.json
oap recipient-key --private-out director.private.json --public-out director.public.json

# Package a signed public portfolio
oap package --source ./actor_src --out ./actor-public.oap --tier portfolio --sign-key-file agent.private.json

# Encrypt cast assets for a Director and sign the full package
oap package --source ./actor_src --out ./actor-full.oap --tier full --sign-key-file agent.private.json --recipient-key director.public.json

# Verify and import with a trusted Agent key list
oap verify --oap ./actor-full.oap --known-agents ./known_agents.json
oap import --oap ./actor-full.oap --target ./actor_installed --known-agents ./known_agents.json

# Check a casting call against an actor's rider
oap check-call --manifest ./manifest.json --call ./casting_call.json
```

Without installing, run the same commands via `python oap/core.py <subcommand>`.
Create `actor_src/manifest.json` with `new_manifest()` and set its
`agent.public_key` to the Agent identity's public key before packaging.
`known_agents.json` is a JSON array of Agent public-key strings selected by the
receiving studio.

## New in 0.5

OAP 0.5 adds signed Agent and Director key revocations and signed third-party
attestations. Key IDs are `sha256:` plus the SHA-256 digest of the raw 32-byte
public key. Receivers choose trusted revokers and attestation issuers locally;
trust files contain public keys only. Revokers can be limited by `key_types`.
Issuer trust entries must list `accepted_claim_types`; an empty list accepts no
claims. See [the 0.5 release notes](docs/RELEASE_NOTES_0.5.md) and the signed
[example documents](examples/).

Revocation needs no setup. By default, any list you supply is checked and a
revoked key fails, but having no list is not an error. Once you name a revoker
with `--known-revokers`, verification becomes strict and needs a current list
from that revoker, even when no keys have been revoked. A self-signed Agent list
can revoke its own key but cannot satisfy that requirement. Set
`--revocation-policy best_effort` to get warnings about missing or expired lists
without failing on them. Invalid lists always fail. Present attestations are
verified by default; unknown issuers or disallowed claims fail. The sender's
manifest policy cannot weaken the receiver's policy. Verification stays offline
unless `--allow-remote-revocation` explicitly enables HTTPS list fetches.

```bash
# Sign an entry, then sign a list (use a locally trusted revoker key)
oap revoke-key --key-id sha256:YOUR_KEY_DIGEST --key-type agent_signing --reason retired --sign-key-file revoker.private.json --out entry.json
oap create-revocation-list --list-id urn:oap:revocation:list:current --entries entry.json --sign-key-file revoker.private.json --next-update 2026-11-30T00:00:00Z --out current-list.json
oap verify-revocation-list --list current-list.json --known-revokers examples/known_revokers.json

# Verify with locally chosen Agent, revoker, and issuer trust
oap verify --oap actor.oap --known-agents known_agents.json --revocation-lists current-list.json --known-revokers known_revokers.json --attestation-issuers known_attestation_issuers.json

# Bind an attestation to stable package content, then attach and re-sign
oap package --source actor_src --out actor.oap --sign-key-file agent.private.json
oap package-hash --oap actor.oap
oap attest --subject-actor-id urn:oap:actor:example --claims-file claims.json --sign-key-file issuer.private.json --package-hash sha256:PRINTED_HASH --out attestation.json
oap attach-attestation --oap actor.oap --attestation attestation.json --sign-key-file agent.private.json --out actor-attested.oap
oap verify-attestation --attestation attestation.json --known-issuers known_attestation_issuers.json --package actor-attested.oap
```

The signed vector list in `examples/` expires on 2026-10-09 and is a format
example, not a current coverage list. Create a fresh list for strict checks.
To upgrade a 0.4 package, re-sign it with
`oap migrate --oap old.oap --out new.oap --sign-key-file agent.private.json`.
For temporary inspection of a signed 0.4 package, use
`oap verify --oap old.oap --allow-legacy-manifest` with the same local trust
and revocation inputs. New package sources must declare 0.5.0.

## New in 0.4

Full packages seal cast assets for one or more Directors using separate X25519
recipient keys. A signed, exact file inventory and strict archive limits harden
verification and import. Imported packages retain ciphertext; programs use
`open_asset_buffer()` to decrypt an asset in memory after signature and local
Agent trust checks. Old 0.1–0.3 packages require explicit legacy inspection
and re-signing through `oap migrate`. See [the 0.4 release notes](docs/RELEASE_NOTES_0.4.md).

## The `.oap` package

```text
actor.oap (zip)
├── manifest.json      # the OAP manifest
├── portfolio/         # PUBLIC clearance: watermarked headshot, demo reel, voice demo
└── sealed/            # CAST clearance: authenticated ciphertext for named Directors
```

The manifest signs the exact members shipped in each package. Public and
audition assets carry SHA-256 hashes. A full package contains authenticated
ciphertext for cast assets, with its hash and recipient envelopes in the
signed manifest. Public packages omit cast hashes and cast bytes.

## New in 0.3

Validate manifests/casting calls with `oap validate --document FILE`, package
public plus audition assets using `oap package --tier audition`, and record
bilateral Agent/Director signatures with `oap sign-agreement` and
`oap verify-agreement`. Schemas ship with the library; unknown extension keys
remain permitted. These features were introduced in the 0.3 format.
See [the 0.3 release notes](docs/RELEASE_NOTES_0.3.md) for the agreement workflow,
compatibility, and limits.

## Features introduced in 0.2

Generic `assets` use the same clearance, hashes, packaging, and verification as
visual sheets and voice references. Personality is an asset with role
`personality`. Structured look/height and voice provenance fields are optional;
Legacy inspection accepts 0.1.x, 0.2.x, and 0.3.x packages and preserves unknown keys.

```python
from oap import clean_asset, load_known_agents, verify_package

# Install PNG support with: pip install -e '.[images]'
# Clean before packaging/signing; PNG pixels and PCM WAV samples are preserved.
clean_asset("raw.png", "identity/reference_sheet.png")
result = verify_package("actor-full.oap", known_agents=load_known_agents("known_agents.json"))
trusted = result["ok"]
```

The trust file is a JSON array of Agent public keys. Without an explicit list,
`agent_known` is null and normal verification fails closed. Strict verification
rejects stray files, unsafe names, and duplicate members.
The legacy studio bridge is deprecated; each studio owns its adapter.
See [the 0.2 release notes](docs/RELEASE_NOTES_0.2.md) for migration details.

## Security model

OAP lets honest parties check who signed a package, detect tampering, keep cast
assets encrypted in transit and storage, and hold signed evidence of what was
agreed. It cannot control a recipient who has legitimately decrypted an asset:
that person can copy it or skip revocation checks on their own machine. In-memory
decryption prevents accidental copies, not deliberate ones. Revocation tells
honest receivers to stop trusting a key, and it only reaches receivers who get
the list. Keeping assets away from the recipient takes a future render proxy tier.

## Protection tiers

| Tier | Name | Mechanism | Trust assumption |
|---|---|---|---|
| 0 | Open | Plain files | Friends / CC-licensed |
| 1 | Recipient-encrypted handover | Encrypted to a named key; program decrypts in memory | Named Director handles assets honestly |
| 2 | Key delivery | Agent issues short-lived keys | Director handles assets honestly; Agent can refuse new keys |
| 3 | Render proxy | Assets not delivered; remote render | Render host; infra required |
| 4 | Enclave (TEE) | Hardware-enclave decryption | Hardware vendor; future |

The full packager encrypts cast assets for named recipients. Tier 2
key delivery and higher-tier mechanisms remain future work. See
[the standard](docs/WHITEPAPER.md).

## Example actors

Signed example actor packages live in a separate collection,
[hodgemann/oap-actors](https://github.com/hodgemann/oap-actors), licensed
CC BY 4.0. The collection currently holds nine fictional actors, including an
animal, a robot, a henchman, and human characters such as a firefighter,
teacher, construction worker, baker and oil painter. They are not bundled with this
library, and OAP never fetches or trusts them automatically. Verify one
offline before importing:

```bash
oap verify --oap animal_pig.oap --legacy
```

A valid signature proves which key signed the package, not that the key is
trusted. These examples are older-format packages; migrate and re-sign before
normal v0.5 import. Compare package hashes with the collection `index.json`.

## Related: Open Prop Protocol

Actors are people and characters. For inanimate props such as instruments,
vehicles, and sets, see the sibling [Open Prop Protocol](https://github.com/hodgemann/opp)
(OPP). It reuses OAP's ZIP bundle layout, SHA-256 asset hashes, and Ed25519 DID
and manifest signing, but is a separate format (`.opp`) that OAP does not read.
Signed example props live in [hodgemann/opp-props](https://github.com/hodgemann/opp-props).

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
    └── WHITEPAPER.md    # the current spec
```

## License

MIT — see [LICENSE](LICENSE).

## Roadmap

- **v0.2** — generic assets, structured look/height, voice provenance, strict verification,
  local Agent trust, clean-room helpers, and 0.1/0.2 read compatibility.
- **v0.3** — offline JSON Schema validation, audition-clearance packaging, and
  countersigned role agreements.
- **v0.4** — recipient-encrypted cast handover, signed exact ZIP inventories,
  fail-closed trust and import, and explicit migration.
- **v0.5** — signed key revocation, issuer-scoped attestations, and offline-first trust checks.
- **Future** — Magic Wormhole transport.
- **Later** — Tier 3 render proxy, Tier 4 enclave, provenance watermarking, settlement.

## Acknowledgments

Special thanks to [@hellonearthis](https://github.com/hellonearthis) for brain expansion and coding tips.
