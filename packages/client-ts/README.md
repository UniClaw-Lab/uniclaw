# `@uniclaw/client`

TypeScript client for [Uniclaw](https://github.com/BoardClaw-Labs/uniclaw)'s HTTP proposal API. The on-ramp for any non-Rust runtime that wants to anchor agent actions into Uniclaw receipts.

One class, three operations, verify-by-default. Browser + Node 20+.

## Why this exists

Step 21 shipped a sidecar API that lets any HTTP-speaking language mint Uniclaw receipts. This package is the **TypeScript adapter** that turns that API into a one-line integration for OpenClaw, NemoClaw, NanoClaw, or any TS-based runtime. Combined with [`@uniclaw/verifier`](../verifier-ts), every receipt the client returns has been re-verified locally before the caller sees it — the client never trusts the server's claim about what was signed.

## Install

```bash
npm install @uniclaw/client
```

The package depends on `@uniclaw/verifier`; npm pulls it in automatically.

## Usage

```ts
import { UniclawClient } from "@uniclaw/client";

const client = new UniclawClient({ baseUrl: "http://127.0.0.1:8787" });

const decision = await client.evaluate({
  kind: "http.fetch",
  target: "https://api.example.com/data",
  inputHash: "00".repeat(32),  // BLAKE3 of your input bytes, hex
});

switch (decision.kind) {
  case "allowed":
    runTool(decision.receiptUrl);
    break;
  case "denied":
    logBlocked(decision.contentId);
    break;
  case "pending":
    // Operator gate. Ask whoever's on call, then call back.
    const final = await decision.approve("operator@example.com");
    // or: await decision.deny("operator@example.com");
    break;
  case "approved":
    // Returned by .approve() — won't appear here on the first call.
    break;
}
```

The `decision` is a discriminated union: switch on `kind` and TypeScript narrows the rest.

## Verify-by-default

By default, every mint is verified locally before being returned. If the server returns a receipt whose signature does not validate, `UniclawVerifyError` is thrown:

```ts
try {
  const d = await client.evaluate({ ... });
} catch (e) {
  if (e instanceof UniclawVerifyError) {
    console.error("server returned a tampered receipt:", e.detail);
  }
}
```

To skip verification (faster, trusts the server), pass `verify: false`:

```ts
// per-call:
await client.evaluate({ ... }, { verify: false });

// or globally:
new UniclawClient({ baseUrl, verifyByDefault: false });
```

The latency cost of `verify: true` is one extra `GET /receipts/<hash>` round-trip plus JCS canonicalize + BLAKE3 + Ed25519 verify locally — about 15 ms on a loopback connection. See `bench-results/22-typescript-client.txt` in the parent repo for details.

## API surface

```ts
class UniclawClient {
  constructor(opts: {
    baseUrl: string;
    fetch?: typeof fetch;       // override for tests / custom fetch
    verifyByDefault?: boolean;  // default: true
  });

  evaluate(action: Action, opts?: { verify?: boolean }): Promise<Decision>;
  resolveApproval(
    contentId: string,
    body: { principal: string; outcome: "approved" | "denied" },
    opts?: { verify?: boolean },
  ): Promise<ApprovedDecision | DeniedDecision>;
  verifyReceiptUrl(url: string): Promise<VerifyResult>;
  getReceipt(contentId: string): Promise<unknown>;
}

class UniclawError extends Error {
  readonly status: number;       // HTTP status (400, 404, 409, 500, ...)
  readonly code: string;          // "bad_request" | "not_found" | "conflict" | ...
  readonly detail: string;        // Human-readable explanation
}

class UniclawVerifyError extends Error {
  readonly contentId: string;
  readonly detail: string;
}
```

## Trust model

- **Verify locally, not on the server.** The verifier code runs in the caller's process. The server never gets a vote on whether a receipt is valid.
- **Re-verification covers content_id, too.** The recomputed BLAKE3 hash is compared against the server's claimed `content_id`. If they differ, the server lied about what it returned.
- **No authentication in the wire format** (yet). The sidecar API on `uniclaw-host` is unauthenticated; expose only on loopback / a trusted network segment. A future Uniclaw release adds bearer-token auth that this client will pick up via the `fetch` override.

## Pairs with

- **`@uniclaw/verifier`** — the lower-level package this client builds on. Use it directly if you want to verify a receipt URL without minting anything.
- **`uniclaw-host` with `--constitution`** — the Rust sidecar binary that serves the API. Build it with `cargo build --release --bin uniclaw-host -p uniclaw-host` and run it next to your TS process.

## Building

```bash
npm install
npm run typecheck
npm run test            # unit tests (mocked fetch)
UNICLAW_INTEGRATION=1 npm run test  # adds 7 integration tests against the live binary
npm run build           # emits dist/ (ESM)
```

## License

MIT OR Apache-2.0, matching the Uniclaw monorepo.
