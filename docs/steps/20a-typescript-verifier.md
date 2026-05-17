# Phase 3.5 Step 20a — TypeScript verifier npm package

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **New top-level dir:** `packages/verifier-ts/` (first JS/TS package in the repo)
> **Workspace:** still 17 of 20 Rust crates — the npm package doesn't count toward the cap

## What is this step?

Step 19 made receipt bytes deterministic across languages (RFC 8785 JCS). Step 20 made the wedge **visible** by shipping a single-command demo that produces 6 verifiable receipt URLs. Step 20a closes the last threshold-1 gap: **a TypeScript developer can `npm install` a verifier and validate a BoardProof receipt minted on a Rust kernel, with bytes matching, on any platform that runs Node 20+ or a modern browser.**

That's it. One sentence, one package, one shipped artifact. After this PR, the success-threshold-1 test from the deep-strategy memory is literally true: hand any of step 20's printed URLs to anyone with `npm`, and they run

```bash
npx boardproof-verify-ts http://localhost:PORT/receipts/HASH
# ✓ verified | issuer=197f6b23... decision=allowed schema_v=2 content_id=a957e6e6...
```

— no Rust toolchain, no BoardProof clone, no trust in the host.

## Where does this fit in the whole BoardProof?

The package is a sibling to `boardproof-verify` (the Rust CLI) and `verify.html` (the browser page). Three implementations of the same verification algorithm, kept honest by sharing a single conformance fixture:

```
                  ┌──────────────────────────────┐
                  │ canonical-v2.json (5 vectors)│
                  │   body → canonical_hex       │
                  │   body → blake3_hex          │
                  └────────────────┬─────────────┘
                                   │ asserted by
              ┌────────────────────┼──────────────────────┐
              ▼                    ▼                      ▼
    ┌─────────────────┐  ┌───────────────────┐  ┌────────────────────┐
    │ Rust            │  │ verify.html       │  │ @boardproof/verifier  │
    │ boardproof-receipt │  │ (inlined JS port) │  │ (npm, this PR)     │
    │ canonical.rs    │  │                   │  │ src/canonical.ts   │
    └─────────────────┘  └───────────────────┘  └────────────────────┘
              │                    │                      │
              ▼                    ▼                      ▼
       cargo test         conformance-smoke.mjs        vitest run
       (snapshot)         (manual node smoke)          (3 test files)
```

If any one diverges, the conformance vectors fail in that implementation and the divergence is visible immediately. The TS package is the canonical TypeScript reference — `verify.html` could one day import from a bundled build of it; that's a future-step refactor.

## What problem does it solve technically?

Three problems.

### 1. "I want to verify a BoardProof receipt from Node / Deno / Bun / a browser, without installing Rust."

Before this step, the only published verifier was `boardproof-verify` (a ~720 KB Rust binary) or `verify.html` (a static HTML page). Neither is a programmatic API. A Node service that wants to *act on* the verified-or-not result — log it to an audit DB, fail a CI step, gate a downstream call — had no clean way to do it.

The npm package exports:

```ts
verifyReceiptUrl(url: string): Promise<VerifyResult>;
verifyReceiptJson(json: string): Promise<VerifyResult>;
verifyReceipt(receipt: Receipt): Promise<VerifyResult>;
canonicalizeBody(body: ReceiptBody): Uint8Array;
computeContentIdHex(body: ReceiptBody): string;
```

That's the whole surface. Five functions, two types, no class hierarchies. A CI script can verify a chain of receipts in five lines. An auditor's notebook can poke at the canonical bytes directly.

### 2. "How do I know the TypeScript verifier doesn't drift from the Rust one over time?"

The package's tests load the SAME `canonical-v2.json` fixture the Rust snapshot test loads. Adding a new vector adds it to both. Changing the canonicalizer changes the bytes; the snapshot fails in Rust, the conformance test fails in TS — both PRs get caught at review.

```ts
// tests/conformance.test.ts
const fixturePath = resolve(
  here,
  "../../../crates/boardproof-receipt/tests/vectors/canonical-v2.json",
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

it.each(fixture.vectors.map((v) => [v.name, v]))(
  "vector %s — canonical bytes match",
  (_name, v) => {
    const str = canonicalizeJcs(v.body);
    const bytes = new TextEncoder().encode(str);
    expect(bytesToHex(bytes)).toBe(v.canonical_hex);
  },
);
```

5 vectors × 2 assertions (canonical bytes + BLAKE3 content_id) = **10 cross-language conformance checks** that must hold on every commit.

### 3. "How do I trust the verifier itself?"

Auditable, minimal surface:
- **Two dependencies, both from the same well-known author (Paul Miller):** `@noble/hashes` (BLAKE3) and `@noble/curves` (Ed25519). Both ship audited, browser+Node, no native modules, no postinstall scripts. Anyone reading the package can read the deps in 10 minutes.
- **~250 LOC of source** (canonical.ts + content-id.ts + verify.ts + hex.ts + types.ts + index.ts).
- **ESM-only**, Node 20+ floor. No transpilation back to legacy CommonJS — modern targets, modern code.
- **Bundle-friendly**: no Node-only APIs in the verify path. The same file imports in a browser without rewrites; `fetch` is global, `TextEncoder` is global, `crypto.subtle` is *not* used (we use `@noble/curves` for portability — Node 20's `crypto.subtle.verify("Ed25519", ...)` works too, but we don't depend on it).

## How does it work in plain words?

`verifyReceipt(receipt)` does the same three things the Rust verifier does:

1. Reconstruct the canonical body bytes. Dispatch on `body.schema_version`:
   - `<= 1`: use `JSON.stringify(body)` over the parsed body. ES2015 preserves insertion order, so a receipt fetched as JSON keeps Rust's struct-declaration order through the round-trip.
   - `>= 2`: use the JCS canonicalizer (lexicographic key sort, integer-only numbers, standard string escapes).
2. Recompute the BLAKE3 hash over those bytes. That's the `content_id` — compare it to the URL claim yourself if you want hash-bound trust.
3. Verify the Ed25519 signature against the receipt's embedded issuer public key.

The result is a plain object:

```ts
{
  ok: true,
  contentIdHex: "a957e6e6cfdbca7c88031e1a7cec787437c3c2782cc5439e224f9286b1ca0869",
  issuerHex:    "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61",
  schemaVersion: 2,
  decision: "allowed",
}
```

Failures populate `error: string` and set `ok: false` — no exceptions thrown for valid-but-invalid receipts, only for catastrophically malformed input.

## What you can do with this step today

- **Verify a demo receipt in Node:**
  ```bash
  cargo run --release --example end-to-end-demo -p boardproof-host
  # ...copy one of the printed URLs...
  npx boardproof-verify-ts http://127.0.0.1:PORT/receipts/HASH
  ```
- **Use it in a CI step:**
  ```ts
  import { verifyReceiptUrl } from "@boardproof/verifier";
  const r = await verifyReceiptUrl(process.env.RECEIPT_URL);
  if (!r.ok) { console.error(r.error); process.exit(1); }
  ```
- **Pin trust to a specific key** by comparing `result.issuerHex` against an allow-list after verification.
- **Inspect the canonical bytes** for debugging: `Buffer.from(canonicalizeBody(body)).toString("utf8")` shows exactly what was signed.

## Verified during this PR

- **34 unit + conformance tests pass.** `npm run test` runs `tests/canonical.test.ts` (10), `tests/conformance.test.ts` (11), `tests/verify.test.ts` (13).
- **Cross-language byte-identity proven.** All 5 vectors in `canonical-v2.json` produce byte-identical canonical output and byte-identical BLAKE3 content_ids in the TS port. Same fixture, same assertions, same bytes as Rust.
- **End-to-end against the live demo.** All 6 receipts produced by `cargo run --release --example end-to-end-demo` verify under the TS CLI. Tamper test (flip `decision` field) correctly rejected.
- **TypeScript typecheck clean.** `strict` + `noUncheckedIndexedAccess` + `exactOptionalPropertyTypes`. No `any`, no `@ts-ignore`.
- **All 4 Rust gates still clean.** fmt, build, test 382/382, clippy.

## Adopt-don't-copy

- The JCS algorithm is RFC 8785; no source borrowed from any reference implementation. The TS port mirrors the Rust port (which mirrors the spec).
- `@noble/curves` and `@noble/hashes` are external dependencies, not vendored. We use their public APIs only. They are widely deployed in TypeScript security tooling (Ethereum, Solana, Bitcoin client libraries); they are appropriate for a verifier package.
- Other claw verifiers were not consulted (OpenClaw / NemoClaw / etc. don't ship verifier packages — the verifier-as-protocol is BoardProof's lane per the war analysis).

## What this step does **not** ship

- **A bundled `verify.html` that imports from the package.** Keeping `verify.html` self-contained is a feature (save it offline, verify any receipt anywhere). The two implementations are kept in lockstep by the shared conformance fixture, not by code sharing. A future PR could introduce a build step that injects the package's bundled JS into the HTML; that's a refactor, not new functionality.
- **An `npm publish`.** Publishing is an operations task — credentials, release process, semver discipline. The PR ships the package code, tests, README, and proves it works end-to-end. Publishing it to npm under `@boardproof/verifier` is one command (`npm publish --access=public`) once the namespace is reserved.
- **Other languages.** Go, Python, Swift verifiers are separate future steps (each conforms to the same `canonical-v2.json` fixture).
- **CI integration.** The conformance smoke (`conformance-smoke.mjs`) and the vitest suite are run manually. A future step wires both into GitHub Actions on PRs touching `canonical.rs`, `verify.html`, or `packages/verifier-ts/`.
- **A `key_id` field.** Schema-additive; queued as step 19a. The TS package's `Receipt` type uses index signatures (`[k: string]: unknown`) on each shape so future schema fields don't break older verifiers at compile time.

## Performance / size

Not perf-sensitive (verifier latency is dominated by network for `verifyReceiptUrl`). Indicative numbers from `vitest run` on Linux x86_64 / Node 22:

- Whole suite: 34 tests, ~3.4 s end-to-end (most of which is vitest setup).
- Per-vector canonicalize + BLAKE3: < 1 ms.
- Per-receipt sign + verify (synthetic test): ~50 ms (Ed25519 is the dominant cost).

`npm pack` of the built `dist/` (ESM only, six modules + maps + .d.ts): ~12 KB unpacked source; transitive install size including `@noble/*` is ~250 KB.

No bench file — it's a verifier, not a perf-sensitive component. The CLI overhead (Node startup + dynamic import) dominates anything we'd measure.

## In summary

Step 20a turns the receipt-as-protocol claim into a deliverable any TypeScript developer can use:

- ✅ Threshold 1 (portability) — **closed by this PR.** Same bytes, same signatures, same answers across Rust and TS.
- ✅ Threshold 2 (visibility) — already closed by step 20; this PR makes that visibility *programmable*.
- 🔜 Threshold 3 (adoption) — next on the stack: a first cross-claw adapter (OpenClaw or ZeroClaw) lands on a foundation that holds up.

The receipt was portable in theory after step 19. The receipt is demonstrable after step 20. **The receipt is now portable in practice.**
