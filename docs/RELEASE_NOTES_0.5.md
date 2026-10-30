# OAP 0.5.0

OAP 0.5 adds signed key revocation and signed third-party attestations. It
keeps recipient-encrypted cast assets and the exact signed inventory introduced
in 0.4. Verification remains offline unless HTTPS revocation retrieval is
explicitly enabled.

## Changes

- Ed25519 revocation entries and lists use SHA-256 key IDs. Trusted revokers
  establish current coverage; an Agent may self-revoke but cannot establish
  coverage with its own list. Expired lists still convey revocations.
  A revoker whose own key is revoked loses trust, and any list relying on its
  authority fails verification until it is removed or reissued.
- Attestations are signed by locally trusted issuers, whose trust entries limit
  accepted claim types. Optional package and Agent bindings are verified.
- `package-hash` and `attach-attestation` support package-bound attestations
  without changing existing asset bytes. Embedded attestations and revocation
  lists are hashed and named in the signed inventory.
- Verification results expose revocation, attestation, warning, and failure
  fields. See the white paper for their definitions.

## Breaking changes for API callers

- Present attestations default to `attestation_policy='verify_present'` and
  need locally configured `attestation_issuers`; `require` also requires at
  least one. Unknown issuers and disallowed claim keys fail verification.
- `package_actor()` source manifests must be 0.5.x. Signed 0.4 packages are
  rejected by normal verification unless `allow_legacy_manifest=True` (CLI
  `--allow-legacy-manifest`). Existing 0.4 packages cannot carry 0.5 trust
  fields. Older 0.1–0.3 packages still need explicit legacy inspection.

## Revocation defaults

`verify_package()`, `import_actor()`, and `open_asset_buffer()` need no revocation
setup. With no policy set, any supplied list is checked and a revoked key fails, but
a missing list is not an error and produces no warning. Passing `known_revokers`
selects `strict`, which requires a current list from a trusted revoker even when
nothing is revoked. Explicit `best_effort` reports missing or expired lists as
warnings. Sender manifest policy cannot change any of this.

## Migration

1. Keep the original 0.4 package and Agent private signing key. Run
   `oap migrate --oap old.oap --out new.oap --sign-key-file agent.private.json`.
   The 0.4 path verifies and re-signs while preserving sealed members byte for
   byte; it does not decrypt cast assets. Supply `--known-agents` if the old
   Agent must be locally trusted during migration.
2. Configure receiver Agent trust, and issuer trust if attestations are present.
   Verify the migrated package. Add revoker trust and a current list if you use a
   revoker.
3. For an interim read of the old package, use `--allow-legacy-manifest` or
   `allow_legacy_manifest=True`.
   Migration of 0.1–0.3 packages uses `--recipient-key` and may stage plaintext
   temporarily, as described in the 0.4 release notes.
