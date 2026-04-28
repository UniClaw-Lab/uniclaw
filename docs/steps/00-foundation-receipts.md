# Step 0 (Foundation) — The Receipt Format

> **Phase:** 0 — Receipt-First Foundation
> **Crates introduced:** `uniclaw-receipt`, `uniclaw-verify`
> **Spec:** `RFCS/0001-receipt-format.md`

## What is this step?

This is the very first thing built in Uniclaw. Before any agent, any kernel, any tool — we defined **what a receipt looks like** and **how to verify one**.

A receipt is the smallest unit of evidence in Uniclaw. Every later step has to fit into this shape, which is why we designed it first.

## Where does this fit in the whole Uniclaw?

Receipts are the **output** of every kernel action. The kernel produces them. The Constitution rules produce them. The budget engine produces them. The approval engine produces them. The Light Sleep cleanup produces them. They are the common currency of the entire runtime.

```
+---------------------+        +-----------------+
| The kernel and all  |  -->   | Signed Receipt  |  -->  Stored, verified, served, audited
| its subsystems      |        | (this step)     |
+---------------------+        +-----------------+
```

If you removed receipts from Uniclaw, you'd have a generic agent runtime. Receipts are what make Uniclaw, *Uniclaw*.

## What problem does it solve technically?

Three problems, all at once:

### 1. "How do I prove an action happened?"

Without a receipt, you have a log line. Log lines can be deleted. Log lines have no identity tied to a specific signing key. A signed receipt with a public key can be verified by anyone, anywhere, without contacting the original system.

### 2. "How do I prove an action happened *in this order*?"

Logs can be reordered. Receipts cannot — each one carries a `prev_hash` that points back to the previous receipt's content hash. If you reorder them, the chain breaks. We call this the **Merkle leaf chain**.

### 3. "How do I make this small enough that anyone can verify?"

The verifier must be tiny. If only big servers can verify receipts, then "anyone can verify" is a lie. So the receipt format was designed to be:

- **JSON** for human-readability and tool interop.
- **Canonically encoded** so the same body always produces the same hash and the same signature.
- **Self-contained** — every field needed for verification is in the receipt itself; no external lookup.
- **Crypto-light** — Ed25519 signatures (32-byte public key, 64-byte signature) and BLAKE3 hashes (32 bytes). Both are fast and standardized.

The result: a verifier binary that fits in 722 KB stripped, with no internet and no database.

## How does it work in plain words?

A receipt is a JSON object that looks like this (simplified):

```json
{
  "version": 1,
  "body": {
    "schema_version": 1,
    "issued_at": "2026-04-27T12:00:00Z",
    "action": {
      "kind": "http.fetch",
      "target": "https://example.com/",
      "input_hash": "0000...0000"
    },
    "decision": "Allowed",
    "constitution_rules": [],
    "provenance": [],
    "redactor_stack_hash": null,
    "merkle_leaf": {
      "sequence": 0,
      "leaf_hash": "abc1...",
      "prev_hash": "0000...0000"
    }
  },
  "issuer":    "<32-byte Ed25519 public key, hex>",
  "signature": "<64-byte Ed25519 signature, hex>"
}
```

The `body` is the part that gets signed. It contains:

- **`action`** — what was attempted (`kind`, `target`, and a hash of any input).
- **`decision`** — `Allowed`, `Denied`, `Approved`, or `Pending`.
- **`constitution_rules`** — which rules fired and matched.
- **`provenance`** — typed edges (e.g., `user → model`, `model → tool`).
- **`merkle_leaf`** — the chain link: a sequence number, this leaf's hash, and the previous leaf's hash.

The `issuer` is the public key of whoever signed it. The `signature` is the Ed25519 signature over the canonical JSON encoding of `body`.

## How verification works

To verify a receipt:

1. Canonically encode the `body`.
2. Hash it with BLAKE3 (this is the leaf hash; check it matches `body.merkle_leaf.leaf_hash`).
3. Verify the Ed25519 `signature` over the canonical body using the `issuer` public key.

Done. No internet, no database, no API calls. **Cold verification.**

The standalone tool `uniclaw-verify` is exactly this, packaged as a CLI:

```sh
uniclaw-verify --receipt path/to/receipt.json --pubkey <hex>
```

It returns 0 on success, non-zero on failure.

## Why this design choice and not another?

A few decisions worth calling out:

- **Why JSON, not Protobuf or CBOR?** JSON loses bytes but wins on auditability. A regulator can open a receipt in any text editor and read it. Protobuf would need tooling. The size cost is small for our use case.
- **Why Ed25519, not RSA or ECDSA?** Small keys, small signatures, fast verification, no nonce gotchas, well-supported on mobile hardware.
- **Why BLAKE3, not SHA-256?** BLAKE3 is faster on modern hardware (SIMD-accelerated) and arguably has a cleaner design. Both are 256-bit. Either would work; BLAKE3 was the lower-overhead choice.
- **Why a Merkle leaf chain and not a Merkle tree?** Trees are for batch verification. We want each receipt to be independently verifiable *without* the whole tree. A leaf chain gives us tampering detection across the chain while keeping each leaf self-verifying.

## What you can do with this step today

- Construct a receipt manually and sign it with the `crypto::sign` helper.
- Verify a receipt cold with the `uniclaw-verify` binary.
- Use the `uniclaw-receipt` types in any Rust program that needs to produce or consume receipts.

## In summary

Step 0 is the floor. It defines a simple, human-readable, individually-verifiable, chain-aware receipt format. Everything in Phase 1 fits inside this shape. Everything in Phase 2 (public-URL hosting) serves files in this shape. The whole project is a receipt-shaped object.
