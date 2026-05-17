# `@boardproof/verifier`

Standalone TypeScript verifier for [BoardProof](https://github.com/UniClaw-Lab/boardproof) receipts.

Recomputes the canonical body bytes (RFC 8785 JCS), the BLAKE3 `content_id`, and verifies the Ed25519 signature against the receipt's embedded issuer key. Browser + Node 20+. No native deps.

## Why this exists

BoardProof's wedge is *"everyone trusts a BoardProof-compatible receipt."* For that to be real, a verifier has to exist outside the Rust kernel — in the language teams actually use for backend integrations, CI/CD pipelines, and compliance tooling.

This package is the canonical TypeScript reference. It produces byte-identical canonical output to:

- The Rust canonicalizer in `crates/boardproof-receipt/src/canonical.rs`.
- The browser verifier embedded in `crates/boardproof-host/src/verify.html`.
- The Node conformance smoke at `crates/boardproof-receipt/tests/vectors/conformance-smoke.mjs`.

Cross-language byte-identity is enforced by a conformance test that loads the same fixture (`canonical-v2.json`) the Rust snapshot test loads.

## Install

```bash
npm install @boardproof/verifier
```

## Usage

```ts
import { verifyReceiptUrl, verifyReceiptJson, verifyReceipt } from "@boardproof/verifier";

// Fetch + verify in one call.
const result = await verifyReceiptUrl("http://localhost:3000/receipts/abc...");
if (result.ok) {
  console.log("verified", result.contentIdHex, result.decision);
} else {
  console.error("failed:", result.error);
}

// Or, if you already have the JSON text:
const result2 = await verifyReceiptJson(rawJson);

// Or, if you already have a parsed receipt (note: v1 receipts
// require parse-preserved key order — see the doc on verifyReceipt
// in src/verify.ts).
const result3 = await verifyReceipt(receiptObject);
```

The result is a `VerifyResult`:

```ts
interface VerifyResult {
  ok: boolean;            // true iff signature verifies under embedded issuer key
  contentIdHex: string;   // BLAKE3 of canonical body bytes (32-byte hex)
  issuerHex: string;      // 32-byte Ed25519 public key (hex)
  schemaVersion: number;  // body.schema_version
  decision: string;       // body.decision ("allowed" | "denied" | ...)
  error?: string;         // populated when ok === false
}
```

## CLI

A tiny CLI ships with the package:

```bash
npx boardproof-verify-ts http://localhost:3000/receipts/abc...
# ✓ verified | issuer=2a... decision=allowed schema_v=2 content_id=30136578...

npx boardproof-verify-ts ./local-receipt.json
# same shape; exits 0 on verify, 1 on failure, 2 on bad input
```

Pairs with the BoardProof end-to-end demo (`cargo run --release --example end-to-end-demo -p boardproof-host`) — copy any printed receipt URL into the CLI and watch the trust property work.

## Trust model

Everything runs locally. The package does not delegate any verification step to a remote server. In particular:

- `canonicalizeBody` reconstructs the exact bytes the kernel signed.
- `computeContentIdHex` recomputes the BLAKE3 hash from those bytes — the URL's claimed hash is *never trusted*; you should compare it yourself if you fetched by URL.
- `verifyReceipt` checks the Ed25519 signature against the receipt's embedded issuer public key, using `@noble/curves` (audited, browser+Node, no native deps).

If you want to pin trust to a specific issuer key, compare `result.issuerHex` against your trusted set after verification.

## Receipt format

This package targets [RFC-0001 Schema v2](https://github.com/UniClaw-Lab/boardproof/blob/main/RFCS/0001-receipt-format.md). It also accepts v1 (legacy) receipts via the same fallback path the browser verifier uses (`JSON.stringify(body)` over the parsed body).

## Building

```bash
npm install
npm run typecheck
npm run test
npm run build  # emits dist/ (ESM)
```

## License

MIT OR Apache-2.0, matching the BoardProof monorepo.
