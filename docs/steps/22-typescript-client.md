# Phase 3.5 Step 22 — `@uniclaw/client` TypeScript SDK

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **New top-level dir:** `packages/client-ts/` (second JS/TS package; first was `@uniclaw/verifier` in step 20a)
> **Workspace:** still 17 of 20 Rust crates — the npm package doesn't count toward the cap

## What is this step?

Step 21 shipped the HTTP proposal API — the *protocol* lever for threshold 3 (adoption). Step 22 ships the *adapter* — the TypeScript on-ramp that turns the protocol into a one-line integration for any TS-based runtime (OpenClaw, NemoClaw bridges, custom agent stacks).

The contract is dead-simple:

```ts
import { UniclawClient } from "@uniclaw/client";

const client = new UniclawClient({ baseUrl: "http://127.0.0.1:8787" });

const d = await client.evaluate({
  kind: "http.fetch",
  target: "https://api.example.com/data",
  inputHash: "00".repeat(32),
});

switch (d.kind) {
  case "allowed":  run(d.receiptUrl); break;
  case "denied":   block(); break;
  case "pending":  await d.approve("ops@example.com"); break;
}
```

Every mint is verified locally before the caller sees it. The client never trusts the server's claim about what was signed.

## Where does this fit in the whole Uniclaw?

```
┌─────────────────────────────┐    POST /v1/proposals
│  TypeScript runtime         │ ───────────────────────►  ┌─────────────────────┐
│  (OpenClaw / NemoClaw / …)  │                            │ uniclaw-host        │
│                             │ ◄───────────────────────   │ --constitution=…    │
│  @uniclaw/client            │       signed receipt       │ (step 21)           │
│       │                     │                            └──────────┬──────────┘
│       │ verify-by-default   │                                       │
│       ▼                     │      GET /receipts/<hash>             │
│  @uniclaw/verifier          │ ───────────────────────────────────►  │
│  (JCS + BLAKE3 + Ed25519,   │ ◄───────────────────────────────────  │
│   step 20a)                 │      full Receipt JSON                │
└─────────────────────────────┘                                        ▼
                                                              kernel mints + appends
```

The three packages compose: `uniclaw-host` mints over HTTP, `@uniclaw/verifier` does the cryptographic check, `@uniclaw/client` orchestrates both and gives callers a clean idiomatic API. Together they close threshold 3's first concrete deliverable — *a real adapter that an OpenClaw-style runtime would install*.

## What problem does it solve technically?

Three problems.

### 1. "How do I integrate Uniclaw into my TS runtime?"

Before step 22, the answer was *"call `POST /v1/proposals` yourself, parse the JSON, look up `@uniclaw/verifier`, etc."* That's twelve lines of glue every integrator has to write — and the failure modes (forgetting to verify, mixing snake_case/camelCase, not handling pending) are silent.

After step 22, the answer is one `npm install` and one `await client.evaluate(action)`. The discriminated union forces every caller to handle each decision class. Pending receipts carry the approve/deny callbacks directly — no need to re-route the content_id through the operator UI's plumbing.

### 2. "How do I make sure the server can't trick me?"

The client recomputes everything locally. Specifically, for each mint:

1. `POST` the proposal, parse the JSON response.
2. Reverse the relative `receipt_url` against the configured `baseUrl`.
3. **Fetch the full receipt** via `GET /receipts/<hash>`.
4. **Reconstruct canonical body bytes** via `@uniclaw/verifier`'s JCS port.
5. **Recompute the BLAKE3 content_id** and compare it to (a) the server's claimed `content_id` in the propose response AND (b) the hash in the URL.
6. **Verify the Ed25519 signature** against the embedded issuer key.

If any check fails, `UniclawVerifyError` is thrown before the caller sees the decision. The integration test exercises this: it intercepts the GET response, mutates one byte of the body, and confirms the client rejects it (`verify-by-default catches a tampered receipt`).

### 3. "How do I bridge sync-vs-async kernel calls?"

The kernel's `ResolveApproval` flow needs both the original proposal AND the pending receipt. In a real adapter, the operator approval comes back from a separate channel — Slack, email, dashboard — possibly minutes or hours later. The caller's hot path is long gone by then.

`@uniclaw/client` handles this two ways:

- **Synchronous path:** the `PendingDecision` returned from `evaluate()` carries `.approve()` and `.deny()` callbacks that close over the content_id. Use them when the approval happens inline (auto-approval, immediate operator click).
- **Asynchronous path:** call `client.resolveApproval(contentId, { principal, outcome })` directly when the response arrives via another channel. The content_id is the only state the operator UI needs to persist between mint and resolve.

Both paths re-verify the resolution receipt before returning.

## How does it work in plain words?

The whole client is ~210 lines of TypeScript across three files:

- **`src/types.ts`** — Action and Decision shapes. `Decision` is a discriminated union (`allowed | denied | approved | pending`) with `kind` as the discriminator.
- **`src/client.ts`** — `UniclawClient`. Wraps fetch, converts camelCase ↔ snake_case at the boundary, builds the Decision union, and runs the verifier when `verify` is true. Three private mutex'd methods (`#postProposal`, `#postResolve`, `#parseError`), three public methods, one constructor.
- **`src/error.ts`** — `UniclawError` (HTTP-status-mapped) and `UniclawVerifyError` (signature/hash failures). Both are simple `Error` subclasses with typed fields.

The default `fetch` is whatever the runtime exposes (`globalThis.fetch`). Node 20+ has it built in; browsers have it built in; Cloudflare Workers and Deno have it built in. No `node-fetch` polyfill needed.

## What you can do with this step today

- **Integrate from any TS runtime:**
  ```bash
  npm install @uniclaw/client
  ```
  ```ts
  import { UniclawClient } from "@uniclaw/client";
  const c = new UniclawClient({ baseUrl: process.env.UNICLAW_HOST! });
  const d = await c.evaluate({ kind: "http.fetch", target: "...", inputHash: "..." });
  ```
- **Skip verification** (faster) when you trust the network path completely: `new UniclawClient({ baseUrl, verifyByDefault: false })`.
- **Inject a custom fetch** for auth headers / mTLS / custom user agents:
  ```ts
  new UniclawClient({ baseUrl, fetch: (url, init) =>
    fetch(url, { ...init, headers: { ...init?.headers, "x-tenant": "t1" } }) });
  ```
- **Build a Slack/Discord approval handler** that calls `resolveApproval` when the operator clicks.

## Verified during this PR

- **24 tests pass** across two files:
  - `tests/client.test.ts` (17 unit tests, mocked fetch) — wire shape, decision narrowing, pending callbacks, error mapping (400/404/409/500), verify opt-out, `getReceipt`.
  - `tests/integration.test.ts` (7 tests, skipped without `UNICLAW_INTEGRATION=1`) — drives a live `uniclaw-host` subprocess through allowed/denied/pending→approved/pending→denied. Includes a **tamper test** that intercepts the GET response, mutates the `decision` field, and confirms `verify-by-default` rejects it.
- **TypeScript typecheck clean** (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`).
- **Cargo gates clean** (no Rust changes; 398/398 tests, fmt + clippy + build all green).
- **End-to-end bench** (`bench-results/22-typescript-client.txt`, gitignored):
  - `client.evaluate verify=true`: 19.3 ms/req
  - `client.evaluate verify=false`: 3.75 ms/req
  - raw fetch baseline: 3.48 ms/req
  - **Client overhead vs raw fetch: 0.27 ms/req** (~8%) — essentially free.
  - **Verify overhead: 15.6 ms/req** — one extra HTTP round-trip + JCS/BLAKE3/Ed25519 work. Acceptable for a "trust property guaranteed" default; a future PR could extend the step-21 wire format to return the full Receipt in the propose response, eliminating the extra round-trip and bringing verify=true to ~10 ms/req.

## Adopt-don't-copy

- No source borrowed from any other claw. The discriminated-union Decision shape and verify-by-default discipline are original Uniclaw idioms.
- `@noble/curves` + `@noble/hashes` are external dependencies (audited, no native modules) — already vetted in step 20a's verifier package.

## What this step does **not** ship

- **`POST /v1/tool-executions` / `/v1/secret-uses` / `/v1/redactions` support.** The server doesn't expose these yet (queued as a step-21 extension). When they land, this client will add `recordToolExecution(...)`, `recordSecretUse(...)`, `recordRedaction(...)` — same idiomatic shape.
- **Authentication.** The wire format accepts no auth headers today. When `uniclaw-host` adds bearer-token / mTLS, callers will inject auth via the `fetch` option without any client change.
- **Streaming / long-polling for approvals.** Today the caller polls or routes via an external channel (Slack, email). A future PR could add a server-side `GET /v1/approvals/{id}/wait` SSE/WebSocket endpoint and a client `.waitForResolution(id)` helper.
- **`npm publish`.** Operations task — credentials, release process. The package code, tests, and README are in this PR; publishing is one command (`npm publish --access=public`) once the org reserves `@uniclaw` on npm.
- **First-party Python / Go / Swift clients.** Each will conform to the same wire format. The step-22a–c queue.
- **A worked OpenClaw / NemoClaw demo.** That goes in a follow-up step under `examples/openclaw-adapter-demo/` and exercises this client against a representative agent flow.

## Performance / size

- Whole vitest suite (17 unit + 7 integration): ~6 s total, dominated by spawning the Rust subprocess.
- `dist/` after `npm run build`: 6 modules + maps + .d.ts; transitive install with `@uniclaw/verifier` is ~250 KB.
- See the bench file above for the latency breakdown.

## In summary

Step 22 makes "integrate Uniclaw into a TypeScript runtime" a one-line operation. Combined with step 21 (server) and step 20a (verifier), the receipt-as-protocol claim now has an end-to-end TypeScript story:

- ✅ Threshold 1 (portability) — closed by step 20a.
- ✅ Threshold 2 (visibility) — closed by step 20.
- 🟢 Threshold 3 (adoption) — **first cross-claw adapter ships.** Next: a worked OpenClaw or NemoClaw integration demo using this client, plus a Python sibling for compliance tooling.

The receipt was portable. The receipt was demonstrable. The receipt was integrable. **The receipt is now installable** — `npm install @uniclaw/client`.
