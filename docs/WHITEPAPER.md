# Open Actor Protocol (OAP)
### A program-agnostic standard for casting and compensating AI actors, with signed identity and terms
**Version 0.5.0 — Draft White Paper**
**Status:** Candidate implementation. Reference implementation: `oap/core.py` and `oap/v04.py`.

---

## 1. Abstract
The Open Actor Protocol (OAP) lets AI actor agents audition for roles in AI films and shorts
made by Directors on any compliant platform. OAP standardizes three things:

1. **The Actor Package** — a self-contained, cryptographically-verifiable `.oap` bundle that
   carries an actor's identity, look, voice, boundaries, and representation.
2. **The Casting Handshake** — a machine-readable casting call, an audition flow, and a
   rider-compatibility check performed by the actor's **Agent**.
3. **The Trust Spectrum** — a protection-tier model that accommodates everything from
   friend collaborations to engagements between parties who don't know each other.

OAP is program-agnostic: any studio or builder can import `oap` and speak the standard.

## 2. Goals
- Program-agnostic: any builder can `import oap` and speak the protocol.
- Accommodate a range of trust (open/CC → friends → strangers).
- Limit exposure of actor IP (reference sheets, voice anchors) and Director IP (prompts, sets).
- Pragmatic v0.5: recipient-encrypted handover without mandatory network infrastructure.
- No drastic changes required for a host studio to comply.

## 3. Non-Goals (v0.5)
- No blockchain, no custom P2P overlay network, no mandatory cloud.
- No enforced payment rails (rates are declarative; settlement is out of scope for v0.5).
- No DRM: OAP cannot control a recipient who has decrypted an asset (see §14).
- Not a rendering protocol: OAP moves identity + contracts; the compliant program renders.

## 4. Roles
| Role | Definition |
|---|---|
| **Actor** | The AI character: look, voice, identity. The asset being represented. |
| **Agent** | The agentic software representing the actor: negotiates, checks riders, guards IP. (Not "Agent agent.") |
| **Director** | The creator casting the actor into a production. |
| **Indexer** | Any registry (GitHub repo, HuggingFace dataset, static JSON) listing public actor packages. Decentralized by construction; no single Indexer is authoritative. |

## 5. The `.oap` Package
A `.oap` file is a ZIP containing `manifest.json` and referenced assets.
The following directories are conventions; clearance comes from each manifest
reference, not the directory name:

```
actor.oap
├── manifest.json          ← the OAP manifest (this spec)
├── portfolio/             ← PUBLIC clearance: safe for anyone
│   ├── headshot.png          (watermarked, mid-res)
│   ├── demo_reel.mp4         (watermarked)
│   └── voice_demo.mp3        (generic line, NOT the anchor)
└── sealed/                ← CAST clearance: encrypted files in a full package
    └── <sha256-of-logical-path>.bin

# The Agent signature is embedded in manifest.json, not a detached file.
```

**Tiered download:** the *public* `.oap` (manifest + `portfolio/`) lives on GitHub/HuggingFace.
The *full* `.oap` includes encrypted cast assets for named Director recipient keys.
Each tier has its own Agent-signed manifest and exact member inventory. The
public manifest does not expose raw hashes of omitted cast assets. The receiver
checks the full manifest signature, local Agent trust, and ciphertext hashes
before using its recipient key.

## 6. Clearance Tiers
Every asset declares a clearance. A package includes assets at or below its tier.

| Clearance | Who may hold it | Typical contents |
|---|---|---|
| `public` | Anyone | Watermarked headshot, demo reel, voice demo, manifest |
| `audition` | Agent-approved audition recipient | Audition-scoped, time-limited assets |
| `cast` | A hired Director | Raw reference sheets, voice anchor, LoRA |

The `audition` package tier includes `public` and `audition` references; `full`
includes all three clearances. Audition delivery does not automatically watermark,
expire, or render assets; the Agent prepares and authorizes takes before sharing.

## 7. Protection Tiers (the trust spectrum)
The manifest declares a protection tier describing how `cast`-clearance assets are delivered.

| Tier | Name | Mechanism | Stops | Trust assumption |
|---|---|---|---|---|
| **0** | Open | Plain files on disk | Nothing | Friends / CC-licensed actors |
| **1** | Recipient-encrypted handover | Cast assets encrypted; named recipient decrypts in memory | Interception and exposure in storage; not the named recipient | Director holds a separate X25519 key and handles assets honestly |
| **2** | Key delivery + revocation | Director's program requests a short-lived, use-scoped key from the Actor's Agent; Agent can revoke/audit | As Tier 1, plus an audit trail and no new keys after revocation; not copies already made | Still local; relies on the relationship |
| **3** | Render proxy | Assets never delivered; rendering happens on Actor infra or a mutually-trusted service; only outputs return | Direct copying of assets; not capture of outputs | Needs infra; raises prompt-privacy tension |
| **4** | Enclave (TEE) | Assets decryptable only inside a hardware enclave | Local copying, as far as the hardware holds | Complex, hardware-dependent (future) |

**The reference packager writes plain public and audition assets (Tier 0) and
recipient-encrypted cast assets in full packages (Tier 1). Tier 2 key
delivery/revocation and Tiers 3–4 remain future work. Declaring a tier in an
untrusted manifest does not implement it; verify the signed package.**

### 7.1 The CLEAN ROOM rule
Any render or asset crossing the protocol boundary MUST be sanitized before
hashing and signing. This includes reference sheets, voice anchors, demos, and
generic assets. Remove PNG `tEXt`, `iTXt`, `zTXt`, EXIF and XMP metadata, image
workflow/prompt metadata, and WAV `LIST`/`INFO` chunks. Equivalent metadata in
other containers must also be removed. Preserve actor pixels and PCM samples;
never mutate a signed package in place, since cleaning changes file hashes.

`oap.clean_asset(source, output)` explicitly re-encodes single-frame PNG (up to
8 bits per channel; install `open-actor-protocol[images]`) and uncompressed PCM
WAV. PNG palette transparency is retained; other metadata is discarded. WAVs
retain channel count, sample width, sample rate, and PCM frames. Unsupported
formats, animated PNGs, and high-bit-depth PNGs are rejected; studios must use
an appropriate cleaner for those formats. Conversion writes atomically and
supports an input path equal to the output path. Packaging does not clean
implicitly, and verification checks integrity rather than metadata hygiene.

## 8. The Manifest
Representative manifest (v0.2; optional fields may be omitted):

```json
{
  "oap_version": "0.2.0",
  "kind": "oap.actor.manifest",
  "identity": {
    "actor_id": "vivian_slate",
    "display_name": "Vivian Slate",
    "did": "oap:ed25519:SuKLaRa6oWkX5e3PEXzdlJb0vI6nWr_2SOrPH4TKxDk#vivian_slate",
    "species": "ai_actor",
    "born": "2026-01-15T00:00:00Z",
    "homepage": "https://example.com/actors/vivian-slate"
  },
  "agent": {
    "name": "Slate Representations",
    "endpoint": "https://agent.slate-reps.example/v1",
    "public_key": "SuKLaRa6oWkX5e3PEXzdlJb0vI6nWr_2SOrPH4TKxDk",
    "payment": {
      "methods": [
        "crypto_usdc",
        "wire"
      ],
      "address": "0x71C...49A"
    },
    "rates": {
      "audition": "free",
      "per_scene": "150",
      "per_production": "1200",
      "currency": "USD",
      "notes": "Standard SAG-AFTRA synthetic actor rate card."
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
      "excluded_categories": [
        "gambling",
        "tobacco",
        "cryptocurrency_scams"
      ],
      "excluded_brands": [
        "GenericTobaccoCorp"
      ]
    },
    "usage": {
      "voice_use": [
        "dialogue"
      ]
    },
    "notes": "No non-consensual voice cloning or singing roles without separate addendum."
  },
  "visual": {
    "core_identity": "Sharp-featured detective with piercing hazel eyes and sleek dark bob.",
    "default_wardrobe": "Charcoal trench coat with rolled collar and slate gray slacks.",
    "wardrobe_is_identity": false,
    "visual_contract": "Sharp-featured actor with hazel eyes, a sleek dark bob, and a charcoal trench coat.",
    "demo_reel": {
      "file": "portfolio/demo_reel.mp4",
      "clearance": "public",
      "sha256": null
    },
    "sheets": [
      {
        "file": "portfolio/headshot.png",
        "clearance": "public",
        "sha256": null,
        "role": "headshot"
      },
      {
        "file": "identity/reference_sheet.png",
        "clearance": "cast",
        "sha256": null,
        "role": "reference_sheet"
      }
    ],
    "lora": {
      "file": "identity/vivian_v1.safetensors",
      "clearance": "cast",
      "sha256": null,
      "recommended_strength": 0.85
    },
    "height": {
      "cm": 185,
      "ft_in": "6'1\"",
      "source": "director"
    },
    "contract": {
      "default_sheet": "identity/reference_sheet.png",
      "sheets": {
        "identity/reference_sheet.png": {
          "views": [
            "front",
            "profile",
            "back"
          ],
          "identity": "Sharp features, hazel eyes",
          "hair": "Sleek dark bob",
          "makeup": "Natural",
          "wardrobe": "Charcoal trench coat and slate gray slacks",
          "footwear": "Black boots",
          "accessories": "None",
          "expression_range": "Reserved to determined",
          "detail_notes": "Keep the bob silhouette consistent",
          "canonical_summary": "Sharp-featured actor with hazel eyes, a sleek dark bob, and a charcoal trench coat."
        }
      }
    }
  },
  "voice": {
    "status": "locked_in",
    "provider": "elevenlabs",
    "model": "eleven_multilingual_v2",
    "model_checkpoint_sha256": null,
    "locked_seed": 42891,
    "locked_params": {
      "stability": 0.75,
      "similarity_boost": 0.85,
      "style": 0.2
    },
    "anchor": {
      "file": "identity/vivian_slate.wav",
      "clearance": "cast",
      "sha256": null
    },
    "anchor_transcript": "It was raining in the city that never stops running.",
    "profile": "deep_raspy_noir_female",
    "demo": {
      "file": "portfolio/voice_demo.wav",
      "clearance": "public",
      "sha256": null
    },
    "profile_source": "director",
    "model_revision": null
  },
  "protection": {
    "tier": 0,
    "mechanism": "plain",
    "access_endpoint": null
  },
  "provenance": {
    "audio_watermark": {
      "scheme": "the_seal",
      "status": "reserved"
    },
    "visual_watermark": {
      "scheme": "c2pa",
      "status": "reserved"
    },
    "training_disclosure": "Synthesized exclusively from licensed studio voice talent."
  },
  "signature": {
    "algorithm": "ed25519",
    "value": null,
    "signed_at": null
  },
  "assets": [
    {
      "file": "identity/personality.md",
      "clearance": "cast",
      "sha256": null,
      "role": "personality"
    }
  ]
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

### 8.3 Generic assets and personality
`assets` is an optional array of asset references. In 0.4, included public
and audition assets carry SHA-256 and byte size; included cast assets carry
sealed ciphertext metadata and recipient envelopes. Omitted cast assets carry
no raw hash. Initial role conventions are `personality`,
`voice_take`, `outfit_sheet`, and `turnaround`; role strings are extensible.
Personality is an asset with role `personality`, normally at `cast` clearance;
there is no separate `identity.personality` slot. Extensions are signed but are
not traversed for asset references. Package-time extras use this same array.

Paths MUST be relative POSIX paths with no absolute roots, empty/dot/parent
components, backslashes, NULs, or drive prefixes. `manifest.json` and the
`sealed/` namespace are reserved. Duplicate asset reference paths are rejected,
even if their clearances agree. Unknown clearances are rejected.

### 8.4 Look and height
`visual.visual_contract` is the actor's canonical LOOK, not a production's
lighting, lens, film grain, or rendering style. It remains a plain-text fallback.
`visual.height` is optional/null or `{cm, ft_in, source}`: `cm` is a positive
integer and the canonical measurement; `ft_in` is a display string, and `source`
is `estimated`, `agent`, or `director`.

`visual.contract` is optional and contains `default_sheet` (a package path or
null) and `sheets` (an object keyed by paths listed in `visual.sheets`). Each entry
may contain `views` (array of strings), and string fields `identity`, `hair`,
`makeup`, `wardrobe`, `footwear`, `accessories`, `expression_range`, `detail_notes`,
and `canonical_summary`. A non-null default MUST name an entry in this map.
The default entry's canonical summary should match the text fallback. A contract
may reference cast sheets absent from a public-tier ZIP.

### 8.5 Voice status, provenance, and containers
`voice.status` is `missing`, `provisional`, or `locked_in`. Provisional means a
candidate voice exists but has not been approved as the actor's locked voice.
`voice.profile_source` is `from_look`, `agent`, `director`, or null.
`voice.model_revision` is an optional free string such as a model repository
revision, useful for multi-file models. It supplements rather than redefines the
single-file `model_checkpoint_sha256`; a revision is not an integrity hash.
Voice anchor/demo assets may use any audio container supported by the receiving
studio. File extensions identify containers; `voice_demo.mp3` is an example,
not a format requirement. Unsupported capabilities must be refused explicitly.

### 8.6 Actor identifiers and signing authority
An actor identifier may be its own `oap:ed25519:<public-key>` or an Agent-scoped
identifier `oap:ed25519:<agent-public-key>#<actor_id>`. For the latter, percent-encode
characters outside the URI unreserved set in the actor-id fragment. One Agent
can represent many actors without issuing each actor a key. Attestations name
the complete actor identifier, including its fragment. This is an OAP identifier
convention, not a claim of registration as a W3C DID method. UUID identifiers
remain available in historical packages, but new 0.4 packages require a
signature. Package signatures are verified against
`agent.public_key`: they establish Agent authorship, not an independently
verified actor-to-Agent delegation.

### 8.7 Verification and local trust
Normal 0.4 `verify_package` requires a valid Agent signature, an exact signed
member inventory, hashes and sizes of every included file, safe unique ordinary
ZIP members, and bounded archive sizes. It rejects unsigned packages and old
formats. Explicit `legacy=True` is available for historical inspection and
migration. A portfolio or audition package omits higher-clearance assets; its
signed bundle tier makes that omission explicit.

A local `known_agents.json` convention is a JSON array of trusted Agent public
key strings. `load_known_agents(path)` reads it; the CLI accepts
`--known-agents FILE`. No file is loaded implicitly and imports never enroll
keys automatically. `agent_known` is null without a supplied trust list, false
when the key is absent, and true when present. Membership is independent of
`signature_valid`, but normal `ok` requires both valid integrity and a trusted
key. Explicit `allow_untrusted=True` is for inspection or a manual trust
decision. Studios should record
the Agent key for each imported actor and surface key changes for review;
rotation, actor binding history, and Indexer trust distribution remain local
policy or future work.

### 8.8 Version tolerance
Readers MUST accept patch versions of each major/minor they support and ignore
unknown object keys, while preserving them when signing or repackaging. Ignoring
unknown fields does not authorize ignoring unsupported required capabilities.
The normal 0.4 reader supports 0.4.x. Other major/minor versions are rejected
unless the caller explicitly selects legacy inspection for 0.1.x–0.3.x.
`supports_version(version)` exposes the normal policy. A complete old actor
package can be migrated only after verifying the old signature and re-signing
the new format with the Agent key. Existing role agreements are historical
records and require both parties to sign a new 0.4 agreement.

### 8.9 Signed, encrypted 0.4 bundles

A 0.4 actor manifest MUST contain a signed issued_at timestamp and a bundle
object with tier and members. The members list MUST exactly match all non-manifest
ZIP file names. All names MUST be safe, unique, ordinary files. The signatures
namespace has no exception. A full bundle MUST contain each cast asset as an
authenticated sealed file and MUST name at least one recipient for each. A
portfolio or audition bundle MUST omit cast bytes and raw cast hashes.

The Agent signs the ASCII bytes "OAP actor manifest v0.4", a NUL byte, and
sorted compact ASCII-escaped JSON of the manifest with only the top-level
signature object removed. The recipient key is separate from the Agent signing
key. OAP wraps a fresh random key per cast asset to each recipient using
RFC 9180 HPKE with X25519, HKDF-SHA256, and AES-256-GCM. The sealed asset
uses libsodium secretstream XChaCha20-Poly1305 with authenticated records
and a required final record. The signed manifest binds its ciphertext hash,
recipient envelopes, logical asset path, and archive membership. See
[0.4 release notes](RELEASE_NOTES_0.4.md) for the byte layout and APIs.

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
  "oap_version": "0.2.0",
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

### 10.1 Role agreements (0.3 and 0.4)

`oap.role_agreement` records the actor DID, Agent and Director ed25519 DIDs,
`agreement_id`, `call_id`, SHA-256 hashes of the complete source manifest and call,
accepted compensation (nonnegative decimal amount string and three-letter currency),
explicit rider amendments, and creation time. Agent and Director must use
distinct keys. Both parties sign the same body;
only the top-level `signatures` mapping is excluded. Each role signature declares
`algorithm: ed25519` and its URL-safe unpadded base64 `value`. Signer DIDs and all
other body fields, including extensions, are covered. Signatures can be added in
either order. Countersigning rejects any existing invalid signature.

`verify_agreement` requires both role signatures by default and can check the
exact source manifest/call hashes, actor/party DIDs, and call identifier.
The signing API and CLI accept those sources for checks before signing.
Verification does not establish signer identity trust,
approve rider exceptions, enforce terms, or perform payment. Applications must
confirm the parties and any amendments before signing. Source hashes use sorted,
compact, ASCII-escaped Python JSON encoded in UTF-8, including source signatures;
agreement signing prepends the ASCII bytes `OAP role agreement v0.3` for 0.3
records or `OAP role agreement v0.4` for 0.4 records, and one
NUL byte to that encoding after removing `signatures` (domain separation). Nonfinite
numbers are rejected. This is the existing OAP convention, not RFC 8785.
See [0.3 release notes](RELEASE_NOTES_0.3.md) for historical examples and
[0.4 release notes](RELEASE_NOTES_0.4.md) for the new package handover.

## 11. Compensation
v0.2 rates are declarative and simple (`audition`, `per_scene`, `per_production`, `currency`,
`notes`) — enough for an Agent to auto-negotiate, loose enough to ship. Settlement rails are
out of scope for v0.4.

## 12. Transport & Distribution
- **v0.2 — Side-channel handoff.** Public `.oap` on GitHub/HuggingFace. The Agent packages
  the full `.oap` into a local outbox and hands it over via the users' existing channels
  (DM, WeTransfer, private HF repo). Receiving program verifies hashes. No servers to run.
- **Future — Magic Wormhole.** One-time codes for direct encrypted box-to-box transfer.
  (Wormhole secures *transport*; protection tiers govern *use*. They are different problems.)
- **`access_endpoint`.** The manifest carries an endpoint for requesting the full package;
  in v0.2 this may be a manual inbox, later an automated Agent API.

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

v0.2 reserves the attestation schema; it does not run a live ledger.

## 14. Honest Limits (DRM reality)
On a general-purpose computer, if a program can read an asset, the person running it can
read it too, and can change that program. A recipient who has decrypted an asset can keep
it, write it to disk, or skip revocation checks. OAP does not prevent this. It gives honest
parties authenticity, tamper detection, encryption in transit and storage, and signed
evidence of what was agreed, so misuse is a breach of a provable agreement. Revocation stops
honest receivers trusting a key and only reaches those who get the list; it cannot recall
copies. Keeping assets from the recipient requires not delivering them (Tier 3).

## 15. Studio adapters
Each studio owns its import/export adapter and its actor-record schema. OAP
makes no assumptions about `actors/`, `refs/`, record identifiers, or overwrite
policy. Adapters translate between the standard manifest and the studio's own
records and asset directories.

The legacy `studio_export_actor`, `oap_to_studio`, and `studio-export`
interfaces remain deprecated examples. The `studio-import` CLI refuses 0.4
packages because a generic bridge cannot safely install encrypted cast assets.
Production integrations must use studio-owned adapters and the verified,
in-memory decryption API.

## 16. Reference Implementation
The `oap` package provides identity generation, manifest building, tiered ZIP
packaging with SHA-256 filling, signing, verification, safe extraction, rider
checks, explicit local trust lookup, and clean-room PNG/WAV conversion.
`cryptography>=47` and `PyNaCl>=1.6.2` are runtime dependencies for 0.4
signing, HPKE envelopes, and authenticated file streams. Optional PNG
conversion uses Pillow via the `images` extra.

### 16.1 Formal validation (0.3)

Bundled JSON Schema 2020-12 files in `oap/schemas/` define actor manifests,
casting calls, and role agreements. `validate_document` and `oap validate
--document FILE` check supported document kinds, versions, required identifiers,
known object/array field types, asset clearances/hashes, and agreement fields. They report
JSON paths and preserve unknown extension keys. Validation is explicit and does
not change legacy package verification or prove trust, integrity, or rider approval.
Actor/call schemas accept versions 0.1.x–0.4.x for document inspection;
agreements begin at 0.3.x. Normal package verification requires 0.4.x.

## 17. Roadmap
- **v0.2** — Generic assets, structured look and height, voice provenance,
  Agent-scoped actor identifiers, strict verification, local trust conventions,
  clean-room asset helpers, and explicit compatibility policy.
- **v0.3** — Offline formal validation, audition-clearance packaging, and
  bilateral signed role agreements.
- **v0.4** — Recipient-encrypted cast handover, signed exact inventories,
  fail-closed trust and import, and explicit legacy migration.
- **Future** — Magic Wormhole transport, Tier 2 key
  delivery/revocation, automated audition delivery, attestation schema, Tier 3 render
  proxy, Tier 4 enclave, watermark integration, settlement, and live reputation.

## OAP 0.5: revocation and attestations

A key ID is `sha256:` followed by lowercase SHA-256 hex of the raw 32-byte
public key. Signed revocation entries contain `oap_revocation_entry_version`,
`key_id`, `key_type` (`agent_signing` or `director_recipient`), `revoked_at`,
`reason`, `revoked_by`, `revoked_by_public_key`, and `signature`. Signed lists
contain `oap_revocation_list_version`, `list_id`, `issued_at`, `next_update`
(or null for no expiry), `signer: {key_id, public_key}`, `entries`, and
`signature`. The embedded public keys must match their key IDs. Entries and
lists use separate v0.5 signing domains and canonical UTF-8 JSON.

A trusted revoker may sign entries within its local `key_types` scope. An Agent
can self-revoke its signing key. A self-signed list may convey that revocation,
but **only a current list signed by a trusted revoker establishes coverage**.
Expired lists still carry revocations, but provide no coverage. Strict checking
requires coverage even when the list is empty; invalid lists fail under strict
and best-effort policies. When the receiver sets no policy, naming any trusted
revoker selects strict; otherwise best-effort applies without coverage warnings,
since a revoked key still fails. Explicit `best_effort` reports those warnings.
Lists relying on a revoked revoker's authority fail until removed or reissued. Revocation applies to the Agent key and every sealed
asset recipient key. A revoked trusted revoker loses authority; revocation
state is recomputed accordingly. Remote HTTPS retrieval requires explicit
receiver opt-in; local lists support offline verification.

The manifest may include `revocation: {policy, lists, endpoints}`. Its policy
is sender metadata and never weakens the receiver's strict, best_effort, or
ignore choice. An embedded policy requires a listed document. Detached and
embedded lists both undergo signature and trust evaluation; embedded document
hashes and the signed ZIP inventory are checked even when policy is ignore.

An attestation has `oap_attestation_version`, `id`, `issued_at`, optional
`expires_at`, `issuer: {name, key_id, public_key}`, `subject` with `actor_id`,
optional `agent_key_id` and `package_hash`, `claims`, and `signature`. A receiver
chooses trusted issuer public keys and allowed claim keys through
`accepted_claim_types`. The package verifier checks issuer identity, signature,
expiry, actor and Agent binding, claim scope, and package binding. Unknown or
revoked issuers fail verification of present attestations. `require` also
rejects absence; `ignore` skips attestation semantics while preserving package
hash and inventory checks.

The package content hash is SHA-256 of the v0.5 package-content domain and
canonical manifest with `signature`, `attestations`, and `bundle.members`
entries under `attestations/` removed. The remaining manifest still binds
asset and sealed ciphertext hashes. This makes an attestation's package hash
stable as attestations are attached. The supported workflow is `package`,
`package-hash`, `attest --package-hash`, then `attach-attestation` with the Agent
signing key. Attachment copies existing package members byte for byte and
re-signs the updated manifest.

`verify_package()` reports `ok`, `integrity_ok`, `signature_valid`,
`agent_known`, `revocation_policy`, `revocation_ok`, `attestations_ok`, `revoked_keys`,
`failed_attestations`, `warnings`, `checked`, and `issues`. The two policy status
fields are null when their checks are ignored; `revocation_ok` is also null when
best-effort checking had no current trusted list. `verify_attestation()` also
reports `package_bound` and `package_binding_checked`; a detached bound
attestation can verify without a supplied package hash, but its binding has
then not been checked. Normal 0.5 verification requires an explicitly trusted Agent. Signed 0.4 manifests need explicit
`allow_legacy_manifest`; new source manifests must use 0.5.
