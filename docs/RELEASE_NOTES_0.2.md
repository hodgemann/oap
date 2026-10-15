# OAP 0.2.0

OAP 0.2 carries arbitrary actor assets and structured look/voice provenance,
with optional stricter package checks and explicit local Agent trust.

## Changes

| Feature | Behavior |
|---|---|
| Generic asset list | Top-level `assets`, traversed, hashed, packed, and verified |
| Strict verification | `strict` and `require_signature` API/CLI options; duplicate ZIP entries also rejected in strict mode |
| Height | Optional `visual.height` |
| Structured look | Optional `visual.contract`; text fallback explicitly describes actor look |
| Voice provenance/status | `profile_source`, official `provisional` status |
| Personality | Generic asset with role `personality` |
| Actor DID | Agent identifier plus actor fragment documented |
| Trust anchoring | Explicit local key list, loader, CLI option, nullable `agent_known`; per-actor key-change history stays with studios |
| Clean room | Assets explicitly covered; atomic PNG/PCM-WAV helper |
| Studio bridge | Deprecated generic example; overwrite protection, distinct WAV names, temporary directory cleanup |
| Folder model provenance | Optional `voice.model_revision`; no new folder hashing convention |
| Demo format | Audio containers are studio capabilities, not fixed to MP3 |
| Extras | Covered by generic assets; no redundant `extra_assets` parameter |
| Version tolerance | Patch acceptance and unknown-key tolerance; explicit 0.1.x/0.2.x support, no promise that old readers accept 0.2 |

## Migration

- Existing 0.1.x manifests remain readable. New manifests declare 0.2.0.
- Move asset references from private extensions into top-level `assets` before
  packaging. The standard packager includes them directly; no post-pack ZIP
  append is needed. Extension migration is explicit; OAP never guesses
  application-specific fields.
- Move height to `visual.height`, per-sheet look to `visual.contract`, and voice
  profile source to `voice.profile_source`. Keep the default canonical look in
  `visual.visual_contract` for text-only consumers.
- Clean images/audio before packaging. Install `pip install -e '.[images]'` for
  PNG conversion. Unsupported media require a studio-specific cleaner.
- Use `verify_package(..., strict=True, require_signature=True)` when required
  by your receiving policy. These flags remain opt-in. A missing asset is not
  an integrity failure because portfolio packages omit cast assets.
- Pass an explicit trusted-key list or CLI `--known-agents known_agents.json`.
  Trust is separate from signature validity; no keys are enrolled implicitly.
- Replace legacy generic studio bridge use with a studio-owned adapter. Existing
  actor records now cause `FileExistsError` rather than being overwritten.
- New manifest protection defaults describe Tier 0 plain files, matching what
  the reference packager actually produces. Encryption is not implemented here.
- Packaging clears any old signature before optionally re-signing the hashed
  manifest. It rejects unsafe/reserved paths, unknown clearances, and conflicting
  clearances for the same file, and emits shared references only once.
- The example manifest is intentionally unsigned; its illustrative paths do not
  ship accompanying assets. Sign actual packages with your own Agent key.

Consuming applications should update their OAP dependency, migrate their
adapters, and run their own integration tests before adopting the release.

## Validation and publication

Install development tools with `pip install -e '.[dev]'`, then run `pytest -q`.
The suite covers old behavior, full and portfolio generic-asset handovers,
signatures/tampering, unsafe and duplicate ZIP entries, trust lookup, version
compatibility, clean-room preservation, and deprecated bridge safeguards.

The protocol document is [WHITEPAPER.md](WHITEPAPER.md). Review the repository
diff, commit the release, and publish/tag `v0.2.0` through the project's normal
GitHub release process. Transport, encryption, and attestations remain future
work; prior roadmap dates were aspirations, not shipped capabilities.
