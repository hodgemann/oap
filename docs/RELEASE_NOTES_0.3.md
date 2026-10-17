# OAP 0.3.0

OAP 0.3 adds the missing steps between sharing an actor portfolio and recording
an agreed role: document validation, audition-clearance packaging, and bilateral
Agent/Director signatures.

## Changes

- `oap validate --document FILE` and `validate_document()` validate actor
  manifests, casting calls, and role agreements with bundled, offline JSON
  Schema 2020-12 documents. Errors include JSON paths. Unknown extension keys
  remain permitted. Validation checks structure; it does not verify asset
  contents, signatures, trust, or rider approval. Existing package verification
  retains its opt-in flags and does not implicitly apply schemas to old files.
- `oap package --tier audition` includes public and audition assets and excludes
  cast assets. Clearance comes from references, not directory names. It uses the
  existing hashing/signing pipeline. Prepare cleaned, appropriately watermarked
  takes yourself; packaging does not render, watermark, expire, or grant access
  automatically. Every clearance still appears in the manifest with its hash.
- `new_role_agreement()` creates a draft bound to the exact actor manifest and
  casting call. `sign_agreement()` and `sign-agreement` sign either party's role;
  `verify_agreement()` and `verify-agreement` require both signatures by default.
  Agent and Director must use distinct keys. Both sign the same immutable body,
  including signer DIDs, compensation, rider
  amendments, timestamps, hashes, and extension keys. Adding the second signature
  preserves the first. A stale/forged existing signature prevents countersigning.
- Readers accept 0.1.x, 0.2.x, and 0.3.x. New manifests declare 0.3.0. Older
  readers may reject 0.3 packages; update studio adapters before exchanging them.
- `jsonschema>=4.18` is now a runtime dependency. Schemas ship inside the wheel.

## Agreement workflow

Create a draft using your real keys and final documents (prefer the final
package's manifest after hash filling/signing):

```python
import json
from oap import new_role_agreement

with open("manifest.json") as stream:
    manifest = json.load(stream)
with open("casting_call.json") as stream:
    call = json.load(stream)
agreement = new_role_agreement(
    manifest, call, {"amount": "150.00", "currency": "USD"}, "agree_001",
)
# Negotiate any rider_amendments before either party signs.
with open("agreement.json", "w") as stream:
    json.dump(agreement, stream, indent=2)
```

```bash
oap validate --document agreement.json
oap sign-agreement --agreement agreement.json --role agent --sign @agent.key --out agent-signed.json --manifest manifest.json --call casting_call.json
oap sign-agreement --agreement agent-signed.json --role director --sign @director.key --out agreement-signed.json --manifest manifest.json --call casting_call.json
oap verify-agreement --agreement agreement-signed.json --manifest manifest.json --call casting_call.json
```

Key files contain the URL-safe base64 private key returned by identity creation.
`--sign env:VARIABLE` is also supported. Share the signed draft with the other
party for countersigning; each party retains its own private key. The verifier
checks both signatures against the DIDs in the agreement. When source documents
are supplied to signing or verification, hashes and the actor/party DIDs and call
identifier must match those documents. Applications must
independently confirm those DIDs represent the intended parties. This does not
approve rider exceptions, enforce terms, execute payment, or establish signer
reputation. A partial draft fails complete verification; the Python API's
`require_both=False` is only for intermediate workflow inspection.

Hashes use SHA-256 of the complete source JSON serialized with Python
`json.dumps(sort_keys=True, separators=(",", ":"), allow_nan=False)`, UTF-8 and
its default ASCII escaping. Source signatures are included in source hashes.
Agreement signature bytes prepend ASCII `OAP role agreement v0.3` followed
by a single NUL byte to that encoding after removing only the top-level
`signatures` member. This follows OAP's existing JSON convention,
not a general cross-language JSON canonicalization standard. Use JSON values
that round-trip under this convention when implementing another language.

## Deferred

Tier 1 encryption needs a separate package format/key-handling design and
migration review. Attestations need evidence, appeal, and trust-policy semantics
before they can support reputation safely. Both remain on the roadmap, along
with transport, key revocation, automatic audition generation, and studio nodes.

## Validation

Run `.venv/bin/python -m pytest -q` after installing `.[dev]`. New tests cover
schema errors and unknown keys, all three clearance tiers, old-version reading,
two signing orders, source hashes, wrong keys, signature stripping, tampering,
stale countersigning, and CLI workflows.

Validated on Python 3.12: 78 tests passed, with two existing deprecated-bridge
warnings. The built wheel was installed outside the checkout and its bundled
schemas and agreement workflow checked. Python 3.9 and cross-language signature
interoperability have not been exercised.
