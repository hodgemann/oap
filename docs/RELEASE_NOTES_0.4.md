# OAP 0.4.0

OAP 0.4 introduces recipient-encrypted cast handover and a signed, exact
package inventory. This is a breaking document and package release. The
reference library is versioned as 0.4.0.

## Package format

Every new package uses an OAP 0.4.x actor manifest. Its top-level issued_at
timestamp and bundle object are signed. The bundle tier is portfolio,
audition, or full; its members list names every non-manifest ZIP member.
Only files named there may appear. The manifest.json member is implicit.

The Agent signs the ASCII bytes "OAP actor manifest v0.4", one NUL byte, then
UTF-8 sorted, compact, ASCII-escaped JSON of the manifest with the entire
top-level signature object removed. Nonfinite JSON values and duplicate JSON
object keys are rejected. The signature uses the Agent Ed25519 key in
agent.public_key; issued_at is inside the signed body. The wire signature
object has algorithm "ed25519" and a base64url value.

Public and audition assets included in a package retain file, clearance,
sha256, and size references. A full package replaces each cast asset with
sealed/<sha256-of-logical-path>.bin. The cast reference keeps its logical file
path and has sha256 null plus sealed metadata containing the ciphertext path,
SHA-256, size, and recipient envelopes. A portfolio or audition package
omits cast bytes and raw cast hashes. The Agent signs each tier-specific
manifest separately.

For each cast asset, the packager generates a random 32-byte key and uses
libsodium crypto_secretstream_xchacha20poly1305 with 1 MiB plaintext records.
The stream starts with its 24-byte header, followed by four-byte big-endian
ciphertext lengths and ciphertext records; the last record carries TAG_FINAL.
Associated data binds the actor ID and logical asset path. Each recipient
envelope wraps that asset key with RFC 9180 HPKE, DHKEM(X25519, HKDF-SHA256)
and AES-256-GCM. HPKE info binds the same actor ID and logical path. Each
envelope records the X25519 public key, its SHA-256 key ID, and HPKE ciphertext.
Recipient encryption keys are separate from Ed25519 signing keys. The manifest
signature binds the envelopes and ciphertext hashes.

## API and CLI

- generate_recipient_identity() creates a Director X25519 keypair.
- package_actor() requires an Agent signing key. A full package with cast
  assets also requires at least one recipient public key. The package CLI
  accepts --sign-key-file and repeatable --recipient-key files.
- verify_package() enforces strict ZIP structure, the exact signed inventory,
  hashes, and a valid Agent signature. Its ok result also requires an
  explicitly trusted Agent key unless allow_untrusted=True is chosen for
  inspection. integrity_ok, signature_valid, and agent_known are distinct.
- open_asset_buffer() verifies the full package before unwrapping and
  decrypting one cast asset. It returns authenticated plaintext bytes in
  memory, with a default 512 MiB plaintext cap. It writes no plaintext file.
- import_actor() verifies, then installs public assets and sealed ciphertext
  only. It refuses an existing target and does not decrypt cast assets.
- The identity and recipient-key CLI commands create separate private and
  public JSON files. Private files have mode 0600; both files refuse overwrite.
  Agents receive only a Director public file. The CLI no longer accepts raw
  private keys as arguments.
- The migrate CLI command verifies a complete signed 0.1–0.3 package,
  repackages it as an encrypted 0.4 full package, and requires the Agent to
  re-sign. Old formats are inspectable only with verify --legacy.

## Security and limits

ZIP members must be ordinary files with safe, unique paths. The verifier
defaults to a 2 MiB manifest, 2,048 members, 8 GiB per member, and 16 GiB
total expanded bytes; actual read sizes are checked in addition to ZIP
metadata. Imported packages are snapshotted before verification and
extraction, so the verified bytes are the bytes installed.

The Agent signature establishes authorship by a key, not authority over an
actor. Local trust remains an explicit application decision. A recipient who
can decrypt cast content can still copy it. This release does not implement
revocation, expiration, key rotation, watermarking, or payment.

Existing OAP 0.2/0.3 actors need migration and a fresh Agent signature for
normal 0.4 import. Existing bilateral agreements remain historical signed
records; a new 0.4 agreement uses its own v0.4 signing domain and requires
both parties to sign again. Studio adapters must use the new trust and
decryption APIs. Migration temporarily stages plaintext from the old package
in a private temporary directory before sealing it; use a trusted machine
for migration.
