# RFC-0001 — Receipt Format

| Field | Value |
| --- | --- |
| **Status** | Draft |
| **Author** | Uniclaw Contributors |
| **Created** | 2026-04-26 |
| **Last updated** | 2026-05-08 (v2: RFC 8785 canonicalization) |
| **Schema version** | 2 |

## 0. Canonicalization (v2 +)

**Receipts at `schema_version >= 2` use [RFC 8785 JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785).** The canonical encoding is deterministic across implementations and languages — Rust, TypeScript, Go, Python verifiers running JCS over the same logical body produce byte-identical bytes. That property is what makes "verify a Uniclaw receipt with a small binary in any language" actually work in practice.

JCS rules (summary):

- **Object keys sorted by UTF-16 code unit order** (RFC 8785 §3.2.3).
- **Number formatting per ECMA-262 §7.1.12.1.** Integers emit as decimal with no leading zeros, no `+` sign, no exponent. Uniclaw's schema has no floats; the encoder panics on any non-integer Number as a load-bearing assertion against future drift.
- **Standard string escapes** (RFC 8785 §3.2.2): `"` → `\"`, `\\` → `\\\\`, controls (U+0000..U+001F) → `\uXXXX` lowercase, `\b` `\f` `\n` `\r` `\t` use named escapes, everything else UTF-8 verbatim. The slash `/` is **not** escaped.
- **No whitespace.** No spaces, no newlines, no indentation.

**Backwards compatibility**: Receipts with `schema_version <= 1` use the pre-step-19 `serde_json` default encoding (struct-declaration field order). Verifiers dispatch on `body.schema_version`. v1 receipts in the wild continue to verify under v1 rules; new receipts go out as v2.

**Test vectors** live at [`crates/uniclaw-receipt/tests/vectors/canonical-v2.json`](../crates/uniclaw-receipt/tests/vectors/canonical-v2.json) — five representative receipt bodies with their expected canonical bytes (hex) and BLAKE3 hashes. Cross-language verifiers should pass these vectors as their conformance test; see [`tests/vectors/conformance-smoke.mjs`](../crates/uniclaw-receipt/tests/vectors/conformance-smoke.mjs) for a Node.js example proving the JS canonicalizer in `verify.html` matches the Rust output byte-for-byte (the same JCS implementation that `crates/uniclaw-host/src/verify.html` ships in the browser verifier).

## 1. Summary

This RFC defines the **Uniclaw receipt format** — the signed, content-addressed
record that a Uniclaw runtime produces for every consequential agent action.
A receipt is the canonical artifact a third party (auditor, regulator,
customer, judge) consults to verify what an agent did, **without trusting the
runtime that produced it**.

A standalone verifier, [`uniclaw-verify`](../crates/uniclaw-verify), checks
receipt validity in ≤ 200 LOC and ~720 KiB stripped. Anyone can install and
audit it; that is the entire point.

## 2. Motivation

Every other agent runtime in the *claw* ecosystem (`openclaw`, `zeroclaw`,
`nanoclaw`, `openfang`, `nemoclaw`, `picoclaw`, `nullclaw`, `ironclaw`) emits
**logs**: useful for the operator, opaque to outsiders, easy to tamper with,
trivial to drop. Logs are not evidence.

Uniclaw bets that the next decade of agent regulation (EU AI Act Article 12,
SOC2 expansion, healthcare and finance compliance regimes) will demand
*verifiable* records. A receipt is what an auditor accepts.

This RFC fixes the wire format so:

1. The kernel and the verifier can be implemented independently and stay
   compatible.
2. Receipt URLs (`uniclaw://receipt/<hash>`) remain stable across kernel
   upgrades.
3. Compliance teams can build tooling against a stable spec.

## 3. Goals

- **Cold-verifiable** by anyone with the standalone verifier binary, no
  Uniclaw kernel install.
- **Content-addressable**: receipt id = `BLAKE3(canonical body)`.
- **Cryptographically bound** to the issuer: Ed25519 signature over the
  canonical encoding of the body.
- **Compact**: typical receipt < 1 KiB JSON.
- **Forward-friendly**: wrapper version separate from body schema version, so
  optional metadata can be added without breaking existing receipt URLs.
- **Tamper-evident**: any field mutation breaks the signature *and* the
  content id.

## 4. Non-goals

- This RFC does **not** define a registry, a public-URL hosting scheme, or a
  network discovery protocol. Those are the subject of future RFCs.
- This RFC does **not** specify Constitution rule semantics, capability budget
  algebra, or Merkle audit-chain construction. Receipts only *reference* those
  artifacts; the artifacts are normative elsewhere.
- This RFC does **not** make claims about the **truth** of any field. A
  receipt proves: *the issuer signed this body at this point in time.* It does
  not prove the agent's reasoning was correct, that the action was wise, or
  that the operator intended it.

## 5. Cryptographic primitives

| Purpose | Primitive | Rationale |
| --- | --- | --- |
| Content addressing | BLAKE3 | Fast, simple, modern, stable. |
| Issuer signing | Ed25519 (RFC 8032) | Small keys (32B) and signatures (64B); widely audited; deterministic. |
| Canonical encoding | JSON via `serde_json` | Human-readable; ubiquitous tooling. (See §6 for caveats.) |

A future RFC may add:

- **CBOR** encoding for embedded targets (mobile-sovereign, edge).
- **post-quantum** signature suite as a parallel path.

These will be additive — JSON + Ed25519 is the canonical baseline.

## 6. Wire format

### 6.1 Top-level shape

```json
{
  "version": 1,
  "body": { ... },
  "issuer": "<64 hex chars = 32 bytes>",
  "signature": "<128 hex chars = 64 bytes>"
}
```

| Field | Type | Description |
| --- | --- | --- |
| `version` | `u32` | Wire-format version. This RFC defines version `1`. |
| `body` | object | The signed portion (§6.2). |
| `issuer` | hex(32) | Ed25519 public key of the signer. |
| `signature` | hex(64) | Ed25519 signature over the canonical encoding of `body`. |

### 6.2 Body shape

```json
{
  "schema_version": 1,
  "issued_at": "2026-04-26T12:00:00Z",
  "action": {
    "kind": "http.fetch",
    "target": "https://example.com/",
    "input_hash": "<64 hex chars = 32 bytes>"
  },
  "decision": "allowed",
  "constitution_rules": [
    {
      "id": "solo-dev/no-shell-without-approval",
      "matched": false
    }
  ],
  "provenance": [
    {
      "from": "user",
      "to": "model",
      "kind": "request"
    }
  ],
  "redactor_stack_hash": null,
  "key_id": "prod-2026",
  "merkle_leaf": {
    "sequence": 0,
    "leaf_hash": "<64 hex chars = 32 bytes>",
    "prev_hash": "<64 hex chars = 32 bytes>"
  }
}
```

| Body field | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | `u32` | yes | Body schema version. This RFC defines `1`. |
| `issued_at` | RFC 3339 string | yes | UTC timestamp of issuance. |
| `action.kind` | string | yes | Stable identifier for the action type, e.g. `http.fetch`, `shell.exec`, `file.write`. |
| `action.target` | string | yes | What the action was directed at (URL, path, command). |
| `action.input_hash` | hex(32) | yes | BLAKE3 of the canonicalized action input. |
| `decision` | enum | yes | `"allowed"` \| `"denied"` \| `"approved"` \| `"pending"`. |
| `constitution_rules[]` | array | yes (may be empty) | Constitution rules consulted, with `matched` flags. |
| `provenance[]` | array | yes (may be empty) | Typed edges (§7). |
| `redactor_stack_hash` | hex(32) \| null | yes | BLAKE3 of the ordered list of redactor identifiers, when redaction ran. |
| `key_id` | string | **no** (additive in rev 2.1) | Opaque operator-chosen identifier for the signing key — e.g. `"prod-2026"`, `"hsm-3"`, a UUID. The kernel embeds it when the signer was configured with one (`--key-id` on `uniclaw-host`). **Omitted entirely** from the canonical bytes when the signer has no `key_id` set, so pre-rev-2.1 receipts and post-rev-2.1 receipts from signers without a `key_id` remain byte-identical. The wire `schema_version` does **not** change (additive optional field). Auditors use `key_id` to correlate a receipt with an external **key directory** entry (rotation start/end, revocation, expiry). The trust anchor for signature verification remains the *bytes* of the issuer public key; `key_id` is audit-only metadata. |
| `merkle_leaf` | object | yes | Position in the Merkle audit chain (§8). |

### 6.3 Hex encoding

All fixed-size byte arrays (`Digest`, `PublicKey`, `Signature`) are encoded as
**lowercase hexadecimal** with no `0x` prefix. Decoders MAY accept uppercase
hex; encoders MUST emit lowercase.

### 6.4 Canonical encoding for signing and content addressing

The signature covers, and the content id is computed over, the JSON serialization
of the **body** as produced by `serde_json::to_vec`:

- Field order: declaration order from the [Rust type definitions](../crates/uniclaw-receipt/src/lib.rs).
- No whitespace, no pretty-printing.
- Numeric values: integers as JSON numbers; no scientific notation.
- Strings: minimal escaping per RFC 8259.
- Arrays preserve their declared element order.

This is intentionally a **schema-driven** canonicalization rather than a
content-driven one (à la RFC 8785). The trade-off:

- **Pro**: trivial to implement; no dependency on a JCS library.
- **Con**: an alternative library that re-orders keys alphabetically would
  produce a different byte string and break verification.

Implementations of the kernel and the verifier MUST round-trip through the
same Rust types or produce equivalent bytes. A future RFC may switch to
RFC 8785 JCS once a stable Rust dependency exists.

## 7. Provenance edges

Each entry in `body.provenance` is a typed edge in the provenance graph
(see master plan §6.3, §11.2). The edge format:

```json
{ "from": "<node>", "to": "<node>", "kind": "<edge-kind>" }
```

Reserved node identifiers:

| Node | Meaning |
| --- | --- |
| `user` | The human or external system that originated the request. |
| `model` | The LLM that produced the proposal. |
| `tool:<name>` | A specific tool invocation. |
| `output` | The final output emitted to a channel. |

Reserved edge kinds:

| Kind | From → To |
| --- | --- |
| `request` | `user` → `model` |
| `propose` | `model` → `tool:*` |
| `produce` | `tool:*` → `output` |
| `delegate` | `tool:*` → `tool:*` |
| `approval` | `user` → `model` (after gate) |

This list is **non-exhaustive**. Implementations MAY emit additional kinds.

## 8. Merkle audit chain reference

```json
"merkle_leaf": {
  "sequence": 0,
  "leaf_hash": "<32-byte hex>",
  "prev_hash": "<32-byte hex>"
}
```

| Field | Description |
| --- | --- |
| `sequence` | Monotonic position of this action in the kernel's audit chain (zero-indexed). |
| `leaf_hash` | `BLAKE3(sequence ‖ issued_at ‖ action ‖ decision ‖ prev_hash)`. |
| `prev_hash` | The `leaf_hash` of the immediately preceding receipt (zeros for sequence 0). |

The verifier checks the signature over the body, but **does not** by itself
walk the chain — that is the kernel's responsibility, recorded in the Deep
Sleep integrity-walk receipt (master plan §16.3.3). A receipt's
`merkle_leaf.prev_hash` is the anchor that lets a third party reconstruct the
chain offline if the kernel publishes them.

## 9. Content addressing and URL form

```text
uniclaw://receipt/<hex-id>
```

- `<hex-id>` is the lowercase-hex BLAKE3 of the canonical body (§6.4).
- Two receipts with identical bodies but different signatures share the same
  id (signature is part of the wrapper, not the body). This is by design — it
  lets multiple issuers co-sign a body as evidence.
- An optional public-URL form is `https://uniclaw.dev/r/<hex-id>` once
  hosting is operational.

## 10. Verification algorithm

A conforming verifier MUST perform, in order:

1. **Decode** the wrapper as JSON.
2. **Reject** if `version` is not understood by this build.
3. **Re-encode** `body` to its canonical bytes (§6.4).
4. **Parse** `issuer` as an Ed25519 public key. Reject on parse failure.
5. **Verify** the Ed25519 `signature` over the canonical body bytes against
   the issuer key. Reject on failure.
6. **Optionally** recompute the content id (`BLAKE3(canonical body)`) and
   confirm it matches a caller-supplied id.
7. **Return** success.

Steps 1–5 are mandatory. Steps 6+ are caller-driven.

## 11. Security considerations

| Concern | Position |
| --- | --- |
| **Key compromise** | A leaked issuer key invalidates all receipts signed with it. Operators rotate keys; old receipts remain verifiable but flagged "issuer compromised at time T" out-of-band. |
| **Replay** | Receipts are not nonces. The same body can legitimately be re-signed. Replay protection lives at the action layer, not in receipts. |
| **Truncation** | A truncated audit chain is an absence of receipts, which is itself a signal. Operators who want positive proof of completeness publish a Deep Sleep integrity-walk receipt periodically. |
| **JSON canonicalization edge cases** | We rely on `serde_json` round-tripping the same Rust types. A re-ordering or schema-aware re-encoding would break verification. Documented in §6.4. |
| **Field omission** | All body fields listed in §6.2 are required. A receipt missing any required field is malformed and MUST be rejected. |
| **Hex case sensitivity** | Decoders accept upper/lowercase; encoders emit lowercase. Signature-over-body is over the produced bytes, so an encoder change that flips case would invalidate previously signed receipts. |
| **Quantum** | Ed25519 is not post-quantum-secure. A PQ signature is on the long-term roadmap. |

## 12. Versioning

- **`version`** (top-level wrapper) — bumped on incompatible wrapper-shape
  changes, e.g. adding new top-level fields the verifier must understand.
- **`schema_version`** (body) — bumped on incompatible body-shape changes,
  e.g. removing a required field.
- A verifier that encounters an unknown version MUST refuse with a clear
  error (`UnsupportedVersion`).
- A new RFC accompanies any version bump; old RFCs are not retracted.

## 13. Reference implementation

- **Types**: [`crates/uniclaw-receipt/src/lib.rs`](../crates/uniclaw-receipt/src/lib.rs)
- **Sign + verify (`crypto` feature)**: same crate, `crypto` module.
- **Standalone verifier binary**: [`crates/uniclaw-verify`](../crates/uniclaw-verify)
- **Sample mint**: [`crates/uniclaw-verify/examples/mint-sample.rs`](../crates/uniclaw-verify/examples/mint-sample.rs)
- **Round-trip integration tests**: [`crates/uniclaw-verify/tests/round_trip.rs`](../crates/uniclaw-verify/tests/round_trip.rs)

## 14. Open questions

1. Should the canonical encoding move to RFC 8785 JSON Canonicalization
   Scheme once a maintained Rust crate exists? (Today it's schema-driven.)
2. Should we add a `schema_url` field that points to the RFC version,
   freeing verifiers from hard-coding the version table?
3. Should issuer keys carry a `key_id` and an optional `revocation_note`
   so audit tooling can mark old receipts as issued under a now-rotated key?
4. CBOR alternative — same body, different envelope — for embedded /
   mobile-sovereign profiles?
5. Co-signing: should the wrapper allow `signatures: [{issuer, signature}]`
   rather than a single `issuer/signature` pair?

## 15. Acceptance criteria

This RFC is considered "Implemented" when:

- [x] Receipt types ship in `uniclaw-receipt`.
- [x] Standalone verifier binary verifies a hand-crafted receipt cold.
- [x] Round-trip integration test passes (sign with a fresh key, serialize,
      verify via subprocess).
- [x] Tamper tests fail (bad signature, mutated body, wrong issuer,
      unsupported version).
- [ ] Public website hosts a paste-and-verify playground at `uniclaw.dev`.
- [ ] An external security researcher verifies a receipt cold with the
      standalone binary and reports the experience.

The first four boxes are checked as of the commit landing this RFC.
The last two close out Phase 0 of the master plan.

## 16. Change history

| Date | Change |
| --- | --- |
| 2026-04-26 | Initial draft. |
