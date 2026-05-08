# Phase 3.5 / Step 19 — Receipt Canonicalization (v2)

> **Phase:** 3.5 — Receipt-format hardening (between Phase 3 and Phase 4)
> **PR:** _this PR_
> **Crates touched:** `uniclaw-receipt` (canonicalizer module + content_id/sign/verify dispatch), `uniclaw-host` (browser verifier JCS port)
> **New artefacts:** `tests/vectors/canonical-v2.json` (5 conformance vectors) + `tests/vectors/conformance-smoke.mjs` (Node.js cross-language harness)

## What is this step?

The war analysis (`/home/uni/Documents/GPT/claw/UNICLAW_CLAW_WAR_ANALYSIS.md`) lists making the receipt format "boringly interoperable" as the **highest-leverage** work for Uniclaw's wedge. Quote:

> "If verification is not universal, Uniclaw stays a Rust project. If verification is universal, Uniclaw becomes a protocol."

Step 19 closes the foundational gap: **adopt RFC 8785 JCS as the canonical encoding for receipt bodies at `schema_version >= 2`.** Today, receipt body bytes are deterministic in Rust (serde_json's default encoder uses struct-declaration field order), but they aren't *canonical* across languages. A TypeScript, Go, or Python verifier reproducing the bytes from a parsed receipt body has to do exactly the same field-order tricks Rust does — fragile.

JCS fixes this permanently. After step 19, every JCS-compliant verifier in any language produces identical bytes for the same logical receipt body. That's the property that turns receipts from "Uniclaw-format" into "portable trust artifact."

This step is **not** on the master plan's numbered roadmap. The master plan calls Phase 4 (federated memory) next; the war analysis (which I wrote separately, after the master plan's Phase 3 was nearly complete) argues for this hardening sprint first. The case: every Phase 4 receipt type lands on the receipt format. If we add memory-sync receipts with a non-canonical encoding, every memory-receipt-issuing system has to migrate when canonicalization eventually lands. Doing canonicalization first means Phase 4 builds on a stable wire format other languages can already verify.

## Where does this fit in the whole Uniclaw?

The receipt format is the trust artifact every other layer eventually crosses. Step 19 hardens it:

```
                                 ┌─────────────────────────────┐
                                 │  Receipt body — schema_v2   │
                                 │  (logical structure          │
                                 │   identical to v1)           │
                                 └─────────────┬────────────────┘
                                               │
                                               ▼
                                  ┌──────────────────────────┐
                                  │  uniclaw-receipt::canonical
                                  │  RFC 8785 JCS encoder    │
                                  │                          │
                                  │  Lexicographic key sort  │
                                  │  Integer-only numbers    │
                                  │  Standard string escapes │
                                  │  No whitespace           │
                                  └─────────────┬────────────┘
                                                │ canonical bytes
                                                ▼
                ┌────────────────────┬──────────┴─────────┬────────────────────┐
                ▼                    ▼                    ▼                    ▼
        BLAKE3 hash          Ed25519 sign         Ed25519 verify       Browser verifier
        (content_id)         (kernel)             (uniclaw-verify)     (verify.html)
                                                                       JS port of canonical
                                                                       — byte-identical bytes
                                                                       (proven by
                                                                        canonical-v2.json
                                                                        + Node smoke test)
```

The schema-version dispatch keeps **backwards compatibility**: receipts with `schema_version <= 1` use the legacy `serde_json` default encoding. Pre-step-19 receipts in the wild verify under their original rules. New receipts go out as v2.

## What problem does it solve technically?

Three problems.

### 1. "Why does my TypeScript verifier sometimes disagree with the Rust verifier?"

Because pre-step-19 canonicalization wasn't actually canonical. `serde_json::to_vec(&body)` emits keys in struct declaration order. `JSON.stringify(body)` (after `JSON.parse`) emits keys in insertion order (which matches for receipts fetched from `/receipts/<hash>`, but not necessarily after the body has been round-tripped through any JS that reorders keys). For ASCII-only string content with no edge cases, the bytes happened to match. For anything else, they could drift.

JCS removes the dependency on serializer behaviour entirely. Every JCS-compliant encoder emits the same bytes from the same logical input. The Rust → JS conformance test (`conformance-smoke.mjs`) loads the 5 reference vectors and verifies the JS canonicalizer produces byte-identical output. **5 of 5 vectors pass.** That's the cross-language guarantee.

### 2. "How do I add a Go (or Python, or Swift) verifier without regenerating fixtures?"

The fixture file (`canonical-v2.json`) is the lingua franca. New verifier implementations:

1. Implement RFC 8785 JCS (or use a vetted JCS library in their language).
2. Load `canonical-v2.json`.
3. For each vector, canonicalize `body` and compare bytes to `canonical_hex`. If they match, the implementation is conformant.
4. Hash with BLAKE3 and compare to `blake3_hex`. If they match, the hash side is correct too.

That's the conformance contract. Anyone shipping a verifier in any language can self-test against this fixture and ship with confidence.

### 3. "How do I roll out the canonicalization change without breaking existing receipts?"

Schema-version dispatch. The `Receipt::content_id()` / `crypto::sign` / `crypto::verify` paths read `body.schema_version` and route to the right canonicalizer:

```rust
fn canonicalize_for_schema(body: &ReceiptBody) -> Vec<u8> {
    if body.schema_version <= 1 {
        serde_json::to_vec(body).expect("legacy canonicalization must encode")
    } else {
        canonical::to_vec(body).expect("v2 JCS canonicalization must encode")
    }
}
```

Pre-step-19 receipts (`schema_version: 1`) verify under the legacy rules — the bytes the kernel signed are still reproducible. Step 19+ receipts (`schema_version: 2`) use JCS. Both paths run in the same binary; the verifier knows which to use based on the version field in the signed body.

`RECEIPT_FORMAT_VERSION` is bumped from 1 → 2. The kernel mints v2 receipts going forward; the receipt body it produces records `schema_version: 2`. v1 verification still works for older receipts.

## How does it work in plain words?

The JCS algorithm (~100 LOC of Rust):

1. Serialize the receipt body to a `serde_json::Value` (keeps the algorithm decoupled from the specific Rust types).
2. Walk the Value tree:
   - `null` → `null`, `true` → `true`, `false` → `false`.
   - Numbers: emit as decimal. **Floats panic** — Uniclaw's schema has no floats, so a float here would be a bug.
   - Strings: standard JSON escapes (`"` → `\"`, `\\` → `\\\\`, controls → `\uXXXX` lowercase, `\b\f\n\r\t` named escapes, everything else UTF-8 verbatim, **no `\/` escape**).
   - Arrays: `[v1,v2,...]` (no whitespace).
   - Objects: sort keys by UTF-16 code unit order, emit as `{"k1":v1,"k2":v2,...}`.

The output is JCS-canonical bytes. Hash with BLAKE3 → content_id. Sign with Ed25519 → receipt signature. Re-canonicalize on verify → check signature.

The JS port in `crates/uniclaw-host/src/verify.html` is ~30 LOC. Same algorithm; same output. The Node smoke test proves byte-identity over the 5 reference fixtures.

## Why this design choice and not another?

- **Why JCS rather than canonical CBOR or our own scheme?** JCS is a published RFC with reference implementations in many languages. Auditors who know "this is JCS bytes" know how to recompute them. CBOR is a fine alternative but our existing receipts are JSON; switching encoding format AND adding canonicalization at once would be two breaking changes. JCS preserves JSON shape.
- **Why bump `RECEIPT_FORMAT_VERSION` rather than canonicalize all receipts (including old ones)?** Old receipts in the wild were signed over the legacy bytes. If we recanonicalize them now, the signature breaks. The v1 path stays around so existing receipts continue to verify.
- **Why implement JCS ourselves (~100 LOC) rather than depend on `serde_jcs` or `json-canon`?** The algorithm is small enough we can audit our own implementation cell by cell. External crates introduce a new dep with its own quality/size implications, and the canonicalization correctness is *load-bearing* for the entire receipt format — better to own the implementation than to trust a transitive.
- **Why `serde_json::to_value` as the intermediate representation?** Keeps the canonicalizer decoupled from our specific Rust types. Anything that implements `Serialize` can canonicalize. The cost is a Value-tree allocation per call (~30 µs/receipt; see the bench). A direct serializer (no Value-tree round-trip) would be 3-5× faster — that's a future-step optimisation, listed below.
- **Why panic on floats rather than silently format them?** RFC 8785 §3.2.2.4 specifies ECMA-262 §7.1.12.1 minimal float representation, which is non-trivial to implement correctly. Uniclaw's schema has no floats. If a future field adds one, the panic is a load-bearing assertion that someone has to update the canonicalizer (and verify the new behaviour against test vectors) before the format ships.
- **Why didn't we add `key_id` in this PR?** The war analysis lists it as part of the same "highest-leverage" work, but each piece (canonicalization, key_id, witness signatures, transparency log) deserves its own design conversation. Canonicalization is the foundation: every later piece builds on top of it. `key_id` lands as a follow-up PR (or a Phase 6 governance step) once the canonicalizer is shipped and stable.

## What you can do with this step today

- Mint a v2 receipt — every kernel call now produces them automatically (`RECEIPT_FORMAT_VERSION = 2`).
- Verify a v2 receipt with `uniclaw-verify` — same binary, recognises the new schema_version and dispatches to JCS.
- Verify a v2 receipt in the browser — the `verify.html` page ships a JS JCS implementation. Save the page offline; verify any v2 receipt without trusting any server.
- Add a verifier in another language: implement JCS (or use a library), load `canonical-v2.json`, check conformance. The `conformance-smoke.mjs` Node test is the reference shape.
- Trust that pre-step-19 receipts continue to verify — backwards compatibility is preserved.
- Trust that any change to `canonical.rs` that alters byte-level output for the same logical body fails the snapshot test (`vectors_match_expected_canonical_and_hash`).

## Performance baseline (release, x86_64 Linux)

| Operation | Per receipt |
|---|---|
| `canonical::to_vec` (JCS, v2) | **~36 µs** (22.5 MiB/s) |
| `serde_json::to_vec` (default, v1) | ~5.3 µs (151.4 MiB/s) |
| Full content_id (JCS + BLAKE3) | ~26 µs |
| JCS overhead vs serde_json | +30 µs (+572%) |

JCS is ~7× slower than the default encoder — the cost is one `serde_json::to_value` allocation + one Value-tree walk per receipt. At any realistic receipt volume (100/sec is high) this is 0.36% of CPU. Not a hot-path bottleneck.

A future-step optimisation: a direct serde Serializer that emits canonical bytes without the Value-tree round-trip — 3-5× speedup possible. Not on the v0 critical path. See [`bench-results/18-receipt-canonicalization.txt`](../../bench-results/18-receipt-canonicalization.txt).

## What this step does **not** ship

- **`key_id` field.** Lands as a follow-up. Needs design conversation about format (UUID vs operator-string), where it lives in the body (signed vs not), and how key rotation works.
- **Witness / co-signing.** Adds non-omission evidence on top of receipt validity. Phase 6 governance.
- **Chain checkpoint receipts** (`$kernel/chain/checkpointed`). Periodic anchors over the chain head. Phase 6.
- **Transparency log integration.** Optional witness service that publishes chain heads. Phase 6.
- **Multi-language verifiers.** This PR proves Rust and JavaScript byte-identity. Go, Python, Swift verifiers are downstream work — the conformance fixture (`canonical-v2.json`) is the contract.
- **CBOR canonicalization as an alternative.** v0 commits to JCS; CBOR can land additively as a v3 schema if a use case demands it.
- **Canonicalization for receipts inside other systems (e.g. signed memory rows).** Phase 4 will use the same canonicalizer for any receipt-shaped object. Out of scope here.
- **Direct serde Serializer (the 3-5× faster path).** Future-step optimisation; the Value-tree round-trip path is correct and acceptable for v0.

## Adopt-don't-copy

- **RFC 8785 (Cyberphone)** is the canonical reference for the JCS algorithm. Implementation is small enough we wrote our own (~100 LOC) rather than pull a transitive crate; see `crates/uniclaw-receipt/src/canonical.rs` for the cell-by-cell implementation. Test vectors derived from RFC 8785's published examples (Appendix B) inform our test cases.

No source borrowed.

## In summary

Step 19 closes the foundational gap that's been blocking Uniclaw from being a real protocol: receipt bytes are now deterministic *across languages*, not just deterministic *in Rust*. The browser verifier already produces byte-identical output to the Rust canonicalizer for every reference vector. New verifier implementations in Go, Python, Swift, etc. can self-test against the published fixture. Schema-version dispatch keeps backwards compatibility for v1 receipts in the wild.

After step 19, Phase 4 (federated memory) becomes the right next major phase — and every receipt it produces lands on a wire format that the rest of the world can already verify. Each Phase 4 receipt type adds to the same canonical foundation rather than each one re-deciding its own canonicalization story.

The receipt is now portable. That's the wedge.
