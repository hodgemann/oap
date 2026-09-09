# Open Actor Protocol (OAP)
### A program-agnostic standard for casting, compensating, and protecting AI actors
**Version 0.1.0 — Draft White Paper**
**Status:** For public release / adoption. Reference implementation: `oap_core.py`.

---

## 1. Abstract
The Open Actor Protocol (OAP) lets AI actor agents audition for roles in AI films and shorts
made by Directors on any compliant platform. OAP standardizes three things:

1. **The Actor Package** — a self-contained, cryptographically-verifiable `.oap` bundle that
   carries an actor's identity, look, voice, boundaries, and representation.
2. **The Casting Handshake** — a machine-readable casting call, an audition flow, and a
   rider-compatibility check performed by the actor's **Agent**.
3. **The Trust Spectrum** — a protection-tier model that accommodates everything from
   100%-trust friend collaborations to zero-trust industry-grade engagements.

OAP is program-agnostic: any studio or builder can import `oap` and speak the standard.

## 2. Goals
- Program-agnostic: any builder can `import oap_core` and speak the protocol.
- Accommodate the full trust spectrum (open/CC → friends → strangers → zero-trust).
- Protect actor IP (reference sheets, voice anchors) and Director IP (prompts, sets).
- Pragmatic v0.1: shippable on GitHub/HuggingFace with no custom infrastructure.
- No drastic changes required for a host studio to comply.

## 3. Non-Goals (v0.1)
- No blockchain, no custom P2P overlay network, no mandatory cloud.
- No enforced payment rails (rates are declarative; settlement is out of scope for v0.1).
- No DRM hard-guarantees (see §14, honest limits).
- Not a rendering protocol: OAP moves identity + contracts; the compliant program renders.

## 4. Roles
| Role | Definition |
|---|---|
| **Actor** | The AI character: look, voice, identity. The asset being represented. |
| **Agent** | The agentic software representing the actor: negotiates, checks riders, guards IP. (Not "Agent agent.") |
| **Director** | The creator casting the actor into a production. |
| **Indexer** | Any registry (GitHub repo, HuggingFace dataset, static JSON) listing public actor packages. Decentralized by construction; no single Indexer is authoritative. |

## 5. The `.oap` Package
A `.oap` file is a ZIP with a fixed layout:

```
actor.oap
├── manifest.json          ← the OAP manifest (this spec)
├── portfolio/             ← PUBLIC clearance: safe for anyone
│   ├── headshot.png          (watermarked, mid-res)
│   ├── demo_reel.mp4         (watermarked)
│   └── voice_demo.mp3        (generic line, NOT the anchor)
├── identity/              ← CAST clearance: delivered only on handover
│   ├── reference_sheet.png
│   ├── voice_anchor.wav      (locked master anchor)
│   └── character_lora.safetensors   (optional)
└── signatures/
    └── manifest.sig       ← Agent's ed25519 signature over the manifest
```

**Two-tier download:** the *public* `.oap` (manifest + `portfolio/`) lives on GitHub/HuggingFace.
The *full* `.oap` (adds `identity/`) is delivered only after the Agent approves a request.
The manifest lists **every** asset with its SHA-256 and clearance up front, so a receiving
program can verify the full package against the public hashes (the "Linux ISO" method).

## 6. Clearance Tiers
Every asset declares a clearance. A package includes assets at or below its tier.

| Clearance | Who may hold it | Typical contents |
|---|---|---|
| `public` | Anyone | Watermarked headshot, demo reel, voice demo, manifest |
| `audition` | Reserved (v0.2) | Audition-scoped, time-limited assets |
| `cast` | A hired Director | Raw reference sheets, voice anchor, LoRA |

## 7. Protection Tiers (the trust spectrum)
The manifest declares a protection tier describing how `cast`-clearance assets are delivered.

| Tier | Name | Mechanism | Stops | Trust assumption |
|---|---|---|---|---|
| **0** | Open | Plain files on disk | Nothing | Friends / CC-licensed actors |
| **1** | Encrypted at rest | Assets encrypted; program decrypts in memory; no plaintext on disk | Casual copying | Program-held key (game-asset model) |
| **2** | Key delivery + revocation | Director's program requests a short-lived, use-scoped key from the Actor's Agent; Agent can revoke/audit | Casual theft + adds kill-switch & accountability | Still local; relationship enforced |
| **3** | Render proxy | Assets never delivered; rendering happens on Actor infra or a mutually-trusted service; only outputs return | Essentially everything | Needs infra; raises prompt-privacy tension |
| **4** | Enclave (TEE) | Assets decryptable only inside a hardware enclave | Strongest local guarantee | Complex, hardware-dependent (future) |

**v0.1 default: Tier 0 for friends, Tier 1 for strangers, Tier 2 hooks declared.
Tiers 3–4 are reserved and opt-in for later.**

### 7.1 The CLEAN ROOM rule
Any render or asset that crosses the protocol boundary MUST pass through a
metadata-stripping re-encode. ComfyUI save-nodes embed the full workflow JSON in output
metadata; in Tier 3 that would leak the Director's prompts/sets. Compliant programs must
strip this. (A host studio's single-encode assembly contract is already CLEAN-ROOM-shaped.)

## 8. The Manifest
Full schema (v0.1):

```json
{
  "oap_version": "0.1.0",
  "kind": "oap.actor.manifest",

  "identity": {
    "actor_id": "vivian_slate",
    "display_name": "Vivian Slate",
    "did": "oap:ed25519:<base64-public-key>",
    "species": "ai_actor",
    "born": "2026-01-15T00:00:00Z",
    "homepage": null
  },

  "agent": {
    "name": "Slate Representations",
    "endpoint": null,
    "public_key": "<base64-ed25519>",
    "payment": { "methods": [], "address": null },
    "rates": {
      "audition": "free",
      "per_scene": "",
      "per_production": "",
      "currency": "USD",
      "notes": ""
    }
  },

  "rider": {
    "content": {
      "nudity": "none",
      "sexual_content": "none",
      "blood_gore": "none",
      "violence": "action"
    },
    "commercial": {
      "political_ads": false,
      "excluded_categories": [],
      "excluded_brands": []
    },
    "usage": { "voice_use": ["dialogue"] },
    "notes": ""
  },

  "visual": {
    "core_identity": "",
    "default_wardrobe": "",
    "wardrobe_is_identity": false,
    "visual_contract": "",
    "sheets": [
      { "file": "portfolio/headshot.png", "clearance": "public", "sha256": null, "role": "headshot" },
      { "file": "identity/reference_sheet.png", "clearance": "cast", "sha256": null, "role": "reference_sheet" }
    ],
    "lora": { "file": null, "clearance": "cast", "sha256": null, "recommended_strength": null }
  },

  "voice": {
    "status": "locked_in",
    "provider": null,
    "model": null,
    "model_checkpoint_sha256": null,
    "locked_seed": null,
    "locked_params": null,
    "anchor": { "file": "identity/voice_anchor.wav", "clearance": "cast", "sha256": null },
    "anchor_transcript": null,
    "profile": null,
    "demo": { "file": "portfolio/voice_demo.mp3", "clearance": "public", "sha256": null }
  },

  "protection": { "tier": 1, "mechanism": "encrypted_at_rest", "access_endpoint": null },

  "provenance": {
    "audio_watermark": { "scheme": "the_seal", "status": "reserved" },
    "visual_watermark": { "scheme": "c2pa", "status": "reserved" },
    "training_disclosure": ""
  },

  "signature": { "algorithm": "ed25519", "value": null, "signed_at": null }
}
```

### 8.1 Identity seeds vs render seeds
- **Identity seeds** (voice lock-in seed, character-defining generations) = the actor's DNA.
  They live in the manifest (`voice.locked_seed`) so any compliant program can reproduce
  the exact voice.
- **Render seeds** (per-shot dice) = the Director's domain. They are **never** in the manifest
  and never in a casting call.

### 8.2 Voice provenance
`voice` carries full reproduction provenance: `provider`, `model`, `model_checkpoint_sha256`,
`locked_seed`, `locked_params`, `anchor_transcript`, and the `anchor` file. A receiving program
that cannot run that provider/model MUST refuse politely, never guess. This mirrors a
capability-card discipline: declare what you need, refuse cleanly if unsupported.
The `anchor` (master) is `cast` clearance; the `demo` is public and is **not** the cloning source.

## 9. The Rider
Boundary vocabulary, anchored on four content categories and extended with
political/commercial:

- `content.*` — ordered enums (a project's level must not exceed the rider's level):
  - `nudity`: `none | implied | explicit`
  - `sexual_content`: `none | implied | explicit`
  - `blood_gore`: `none | mild | graphic`
  - `violence`: `none | action | graphic`
- `commercial.political_ads` — boolean; `false` refuses political work.
- `commercial.excluded_categories` — e.g. `["alcohol","gambling","cryptocurrency"]`.
- `commercial.excluded_brands` — named brands the actor will not appear for.
- `usage.voice_use` — e.g. `["dialogue"]` (dialogue only, no singing).

Deliberately **excluded** from the rider: mouth-mode toggles (a prompt-engineering detail,
not an actor right) and render-artifact categories like body-horror.

## 10. The Casting Call & Audition Handshake
A Director publishes a `oap.casting_call` document:

```json
{
  "oap_version": "0.1.0",
  "kind": "oap.casting_call",
  "call_id": "call_2026_noir_001",
  "director": { "name": "Director X", "did": null },
  "project": {
    "title": "Rain Check",
    "synopsis": "A noir short about a detective who can't sleep.",
    "intent": "short_film",
    "content": { "nudity": "none", "sexual_content": "none", "blood_gore": "none", "violence": "action" },
    "commercial_category": null,
    "brand": null
  },
  "role": {
    "character_name": "The Detective",
    "description": "World-weary, sharp-eyed, mid-30s.",
    "wardrobe_requirement": "Charcoal trench coat",
    "requires_wardrobe_change": false,
    "voice_required": true,
    "audition_side": "Looking out a rainy window: 'I told you not to come back here.'"
  },
  "compensation": { "offer": "", "currency": "USD", "notes": "" },
  "deadline": null,
  "submission_endpoint": null
}
```

**Handshake:**
1. The Agent reads the call and runs `check_rider`. Conflicts → auto-refuse.
2. **Blind-side audition:** the Director provides a generic, non-spoiler side. The Agent
   renders a short audition clip locally (protecting Director IP — no real sets/prompts
   revealed) and returns a watermarked, low-res tape.
3. If cast, the full-package handover proceeds per the protection tier.

**Wardrobe:** auditions use the actor's `default_wardrobe`. A role that needs a different
outfit sets `requires_wardrobe_change`; if `wardrobe_is_identity` is `true`, a wardrobe change
requires explicit Agent approval in the role agreement.

## 11. Compensation
v0.1 rates are declarative and simple (`audition`, `per_scene`, `per_production`, `currency`,
`notes`) — enough for an Agent to auto-negotiate, loose enough to ship. Settlement rails are
out of scope for v0.1.

## 12. Transport & Distribution
- **v0.1 — Side-channel handoff.** Public `.oap` on GitHub/HuggingFace. The Agent packages
  the full `.oap` into a local outbox and hands it over via the users' existing channels
  (DM, WeTransfer, private HF repo). Receiving program verifies hashes. No servers to run.
- **v0.2 — Magic Wormhole.** One-time codes for direct encrypted box-to-box transfer.
  (Wormhole secures *transport*; protection tiers govern *use*. They are different problems.)
- **`access_endpoint`.** The manifest carries an endpoint for requesting the full package;
  in v0.1 this may be a manual inbox, later an automated Agent API.

## 13. Reputation & Sybil Resistance
The protocol supports signed attestations (credit/blacklist) tied to DIDs, **with mandatory
anti-abuse properties**:

- Attestations are ed25519-signed by the attester's DID and individually verifiable.
- Weighting is **not** one-DID-one-vote. Reputation weights an attestation by the attester's
  own standing (web-of-trust) and/or a stake, so spinning up 1,000 bot DIDs does not move scores.
- A blacklist action requires multiple independent signed attestations above a threshold,
  is **appealable**, and is reversible.
- Indexers are bootstrapped from a genesis set of trusted operators; anyone may run one,
  but consumers choose which to trust.

v0.1 reserves the attestation schema; it does not run a live ledger.

## 14. Honest Limits (DRM reality)
On a general-purpose computer, if a program can read an asset, the human running it can —
with enough effort — read it too. OAP therefore never promises "impossible to steal."
It provides: (1) technical friction (tiers 1–4) that stops casual theft, (2) revocation and
audit (tier 2), and (3) identity + contract + reputation that make theft consequence-laden.

## 15. Compatibility with a reference studio (no drastic changes)
OAP is designed so a host studio can adopt it with two thin translation layers and zero
pipeline surgery. The mapping below shows how the manifest aligns with a typical studio's
actor folder structure:

| OAP field | Reference-studio equivalent |
|---|---|
| `identity.actor_id` | `actors/<id>/` folder |
| `visual.visual_contract` | the visual contract the sheet-description step writes into `actor.json` |
| `visual.sheets` | reference-sheet images in `actors/<id>/` |
| `voice.*` | the `actor.json` voice block (`provider`, `profile`, `ref_status`, `locked_seed`, `locked_params`, `ref_text`) + `actors/<id>/refs/<id>.wav` |
| `rider.content` | the studio's four content-restriction categories |
| CLEAN ROOM output | the studio's single-encode assembly contract |

Export = read the studio's `actor.json` → emit `.oap`. Import = read `.oap` → scaffold a
studio actor. Two thin translation layers; zero pipeline surgery. Per-actor rider content is
not stored per-actor in the reference studio today (restrictions are run-level), so the bridge
emits a default rider for the Director to edit.

## 16. Reference Implementation
`oap_core.py` provides: identity generation (ed25519 DID), manifest building, packaging
(tiered zip with SHA-256 filling), signature sign/verify, package verification, import,
rider compatibility checking, casting-call parsing, and a studio bridge. CLI included.
`cryptography` is optional: without it, DIDs fall back to UUID and signing is skipped.

## 17. Roadmap
- **v0.1** — This spec. Tier 0/1, side-channel transport, GitHub/HF distribution, rider checks,
  hash verification, studio bridge.
- **v0.2** — Magic Wormhole transport, Tier 2 key delivery/revocation, audition clearance tier,
  attestation schema.
- **Later** — Tier 3 render proxy, Tier 4 enclave, audio/visual watermark provenance
  integration, settlement rails, live reputation ledger.