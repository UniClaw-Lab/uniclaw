# Phase 3.5 Step 21 — HTTP proposal API

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **Crates touched:** `uniclaw-host` (new modules: `api`, `signer`, `clock`; new bin flags; deps move from dev to regular)
> **New artefacts:** `crates/uniclaw-host/src/{api,signer,clock}.rs`, `tests/api.rs`

## What is this step?

Steps 19 + 20 + 20a closed thresholds 1 (portability) and 2 (visibility): receipts are byte-identical across languages and a stranger can run one command to see the wedge end-to-end. The big remaining lever is **threshold 3 — adoption**: another claw says *"Uniclaw-compatible."*

Before step 21, the only way to integrate Uniclaw was to *link the Rust kernel* into your runtime. That works for ZeroClaw (Rust). It doesn't work for OpenClaw (TypeScript), NemoClaw (Python), or the other non-Rust claws — the majority of the integration market.

Step 21 ships the **local-sidecar integration pattern** from the war analysis: run `uniclaw-host` as a process next to your existing runtime; submit proposals over HTTP; get back signed receipts.

```
       ┌──────────────────────────────┐
       │   OpenClaw / NemoClaw / ...  │
       │   (TS, Python, Go, ...)      │
       └───────────────┬──────────────┘
                       │  POST /v1/proposals
                       │  POST /v1/approvals/{id}/resolve
                       ▼
       ┌──────────────────────────────┐
       │  uniclaw-host                │
       │  --constitution=...          │
       │  --signer-seed-hex=...       │
       │  (in-memory kernel + log)    │
       └───────────────┬──────────────┘
                       │  /receipts/<hash>
                       ▼
                  signed receipts
                  (verifiable cold via
                   @uniclaw/verifier or
                   /verify in any browser)
```

Net: any language that speaks HTTP can mint Uniclaw receipts, with the receipt-format guarantees intact.

## Where does this fit in the whole Uniclaw?

This step extends `uniclaw-host` with a second axis. Read-only mode (the original step-9 surface) is untouched; proposal mode is opt-in via `--constitution`.

```
                    ┌──────────────────────────────────────┐
                    │  uniclaw-host binary                 │
                    │                                      │
                    │   read-only mode (default):          │
                    │     GET /receipts/<hash>             │
                    │     GET /healthz                     │
                    │     GET /verify                      │
                    │                                      │
                    │   proposal mode (--constitution):    │
                    │     + POST /v1/proposals             │
                    │     + POST /v1/approvals/{id}/resolve│
                    │     + in-memory Kernel + Log         │
                    │     + shared RwLock<log> →           │
                    │       mints are immediately readable │
                    └──────────────────────────────────────┘
```

The api module reuses everything: kernel from `uniclaw-kernel`, constitution from `uniclaw-constitution`, log from `uniclaw-store::InMemoryReceiptLog`, signing from `uniclaw-receipt::crypto`. The wire format mirrors `Receipt` / `ReceiptBody` byte-for-byte — clients receive *exactly* the same JSON the kernel signed.

## What problem does it solve technically?

Three problems.

### 1. "How do I integrate Uniclaw if my runtime isn't Rust?"

Before this step, the war analysis enumerated three integration patterns — but only one (embedded kernel library) had a working code path. The other two (local sidecar, witness service) were aspirational.

Now the local sidecar works:

```bash
# operator side
$ uniclaw-host \
    --constitution ./constitutions/solo-dev.toml \
    --signer-seed-hex 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \
    --bind 127.0.0.1:8787

# any client (TypeScript, Python, Go, curl, ...)
$ curl -sS -X POST http://127.0.0.1:8787/v1/proposals \
    -H 'content-type: application/json' \
    -d '{"action": {
          "kind": "http.fetch",
          "target": "https://example.com/data",
          "input_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }}'

{
  "decision": "allowed",
  "content_id": "cab08070...",
  "receipt_url": "/receipts/cab08070...",
  "issuer": "197f6b23...",
  "sequence": 0,
  "schema_version": 2
}
```

The receipt is signed by the kernel, content-addressed, and immediately fetchable at `/receipts/<hash>` for offline verification. The client never sees the signing key.

### 2. "How does the request shape align with the war analysis's integration spec?"

The war analysis lists six endpoints; this step ships the first two (the ones that drive the Constitution + Budget pipeline). The remaining four — tool-executions, secret-uses, redactions, checkpoints — each need careful design because they carry security-sensitive payloads (credentials must never cross the wire as plain bytes; redaction reports commit to bytes the kernel never sees).

| Endpoint                                | Status        |
|-----------------------------------------|---------------|
| `POST /v1/proposals`                    | ✅ this PR    |
| `POST /v1/approvals/{id}/resolve`       | ✅ this PR    |
| `POST /v1/tool-executions`              | 🔜 future-step |
| `POST /v1/secret-uses`                  | 🔜 future-step |
| `POST /v1/redactions`                   | 🔜 future-step |
| `POST /v1/checkpoints`                  | 🔜 step 19c   |
| `GET /receipts/{content_id}`            | ✅ since step 9 |
| `GET /verify`                           | ✅ since step 12 |

The two proposal-mode endpoints are sufficient to demonstrate the Constitution + Approval flow end-to-end — which covers three of the five demo flows from step 20 (Allowed, Pending → Approved, Denied). Tool execution + secret use + redaction are next.

### 3. "How does authentication work?"

It doesn't, in this PR — and that's deliberate.

The local-sidecar pattern assumes loopback or unix-socket trust: the sidecar runs on the same host as the calling runtime, on a port nothing else can reach. That's the right baseline for a Phase-3.5 deliverable; production deployments wanting a remote sidecar can add a reverse proxy with bearer-token / mTLS in front of `:8787` without any change to Uniclaw.

The binary logs a warning on startup so operators don't accidentally bind to `0.0.0.0`:

```
uniclaw-host: WARN /v1 proposal API is unauthenticated — keep this
              bound to loopback or a trusted network segment.
```

A future PR adds first-class bearer-token auth configured at startup (one env var or flag). The wire-format `principal` field in `ResolveApprovalRequest` is already accepted (so adapters don't have to change shape later) but not yet recorded in receipts — identity-bound approvals are Phase-6 governance territory.

## How does it work in plain words?

`bin/uniclaw-host.rs` gets a new mode that activates when `--constitution <path>` is passed:

1. **Load the signer.** `--signer-seed-hex <64-hex>` → `Ed25519Signer::from_seed`. The seed is dev-grade (deterministic; real deployments add an HSM signer in a future step). The same seed across restarts means the issuer public key stays stable — useful for testing and for any external client that wants to pin the issuer.
2. **Load the constitution.** The TOML file goes through `uniclaw_constitution::parse_toml` → `InMemoryConstitution`. Rule edits require a host restart for now.
3. **Wire the kernel + log.** `Kernel::new(signer, SystemClock, constitution)` + `Arc<RwLock<InMemoryReceiptLog>>`. The log is shared with the read-only router so newly minted receipts are immediately fetchable at `/receipts/<hash>`.
4. **Mount the API.** `api_router(state)` returns the `/v1` routes; `Router::merge` composes them with the existing read-only router.

A request hits the wire:

```
POST /v1/proposals
{ "action": { "kind": "http.fetch", "target": "...", "input_hash": "..." } }
```

The handler:
1. Parses the action (validates hex `input_hash`).
2. Builds an unbounded `Proposal` with `Decision::Allowed` as the proposed decision.
3. Submits `KernelEvent::evaluate(p)` under the kernel mutex.
4. Appends the resulting receipt to the log under the async write lock.
5. Returns `{ decision, content_id, receipt_url, issuer, sequence, schema_version }`.

The kernel runs its own pipeline:
- Constitution check (may override to `Denied` or `Pending`).
- Budget check (skipped in v1 — all proposals are unbounded).
- Mint a signed receipt.

For the approval endpoint:

```
POST /v1/approvals/{content_id}/resolve
{ "principal": "operator@example.com", "outcome": "approved" }
```

The handler:
1. Parses `content_id` (validates hex).
2. Looks up the pending receipt in the log. 404 if missing.
3. Verifies it's actually `Pending` (409 otherwise).
4. Reconstructs the original proposal from the pending receipt's body.
5. Submits `KernelEvent::resolve(approval)`. The kernel re-runs all authenticity gates (signature verify, issuer match, decision-is-Pending, action match).
6. Appends + returns.

### Lock discipline

- `kernel: std::sync::Mutex<Kernel<...>>` — short, sync critical section. The kernel call doesn't `.await`; std-mutex is the correct primitive.
- `log: Arc<tokio::sync::RwLock<InMemoryReceiptLog>>` — async, multi-reader. The read-only routes take read locks; the API takes a write lock around `append`. Lock order: kernel first, then log; never the reverse.

## What you can do with this step today

- **Run the sidecar:**
  ```bash
  cargo run --release -p uniclaw-host --bin uniclaw-host -- \
      --constitution constitutions/solo-dev.toml \
      --signer-seed-hex 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \
      --bind 127.0.0.1:8787
  ```
- **Submit proposals from any language:** curl, fetch, requests, ureq, reqwest. The body shape is documented above.
- **Verify cold:** pass any returned receipt URL through `@uniclaw/verifier` (step 20a) or the browser `/verify` page (step 12).
- **Test the full flow:** the test constitution at `constitutions/solo-dev.toml` already denies `shell.exec` and requires approval for `*/admin/*`; a 4-step curl sequence (Allowed, Pending, Approved, Denied) exercises every code path.

## Verified during this PR

- **11 new integration tests (`tests/api.rs`) pass.** Happy paths (allowed/denied/pending/approved/denied-via-resolve), error paths (400/404/409 for each shape), and a chain test asserting that sequence numbers increment and `prev_hash` links across three sequential proposals.
- **5 new clock unit tests pass** covering epoch, known dates, pre-epoch, and the RFC 3339 shape contract.
- **Cross-language end-to-end smoke against the live binary.** Started `uniclaw-host` with the deterministic demo seed, submitted Allowed / Pending / Approved / Denied via curl, fetched each receipt URL via `npx uniclaw-verify-ts`. All 4 verify; tamper test (flip the `decision` field) correctly rejected.
- **Bench:** 4.2 ms per request with HTTP keepalive (500 sequential proposals via Python urllib). curl-per-request is 30 ms but dominated by curl process startup, not the API.
- **All 4 Rust gates clean:** fmt, build, **test 398/398 (+16 new)**, clippy. Workspace stays at 17 of 20 crates.

## Adopt-don't-copy

- The HTTP proposal endpoint shape is informed by the war analysis's sidecar API specification; the wire shape (`{action: {kind, target, input_hash}}` → `{decision, content_id, receipt_url, ...}`) is original to Uniclaw. None of the reference claw runtimes ship a comparable proposal-receipt API.
- The `SystemClock` RFC 3339 formatter uses Howard Hinnant's `civil_from_days` algorithm from <https://howardhinnant.github.io/date_algorithms.html> (public domain). Citation in the doc comment.
- axum's `Router::merge` + `with_state` pattern is the documented composition primitive.

## What this step does **not** ship

- **Tool execution / secret use / redaction endpoints.** Each carries security-sensitive payloads (the redaction report commits to bytes the kernel never sees; the secret-use event must never carry the secret value). They deserve a dedicated design pass and a dedicated PR.
- **Authentication.** The wire format includes a `principal` field; the binary logs a warning; future-step adds bearer-token / mTLS at the framework level.
- **Persistent storage in proposal mode.** Restart and the chain resets from genesis. SQLite-backed proposal mode is a future-step (the existing `SqliteReceiptLog` would slot in via a generic abstraction; the current `ApiState` is concrete on `InMemoryReceiptLog` for simplicity).
- **Identity-bound approvals.** The `principal` field is accepted in the wire format but not recorded in the receipt. Phase-6 governance.
- **WAF / rate limiting / circuit breakers.** Production deployments use a reverse proxy.
- **A first-party client SDK in TS / Python / Go.** The endpoints are simple enough that any HTTP client works; a dedicated SDK is a future-step.

## Performance / size

Measured on `release` profile, Linux x86_64, the same machine all prior benches ran on. See `bench-results/21-http-proposal-api.txt` (gitignored, not committed) for the raw numbers.

- `Kernel::handle` (direct, v2 JCS — baseline from step 19): ~45 µs / call.
- `POST /v1/proposals` over HTTP keepalive (Python urllib, 500 sequential): **4.218 ms / request**.
- `POST /v1/proposals` over fresh TCP (curl-per-request, 100 sequential): 29.96 ms / request — dominated by curl startup, not the API.
- The HTTP overhead (~4.17 ms over the direct kernel call) is well within "human time" for any realistic agent action. The local-sidecar pattern is viable.

Production-relevant binary size: the `uniclaw-host` binary stripped is ~6.5 MB (vs ~6 MB before this step), with the kernel + constitution + ed25519-dalek now linked into production. Acceptable.

## In summary

Step 21 ships the threshold-3 lever. *Any* language can now produce verifiable Uniclaw receipts by running a small sidecar and POSTing JSON — no Rust toolchain, no kernel embedding. Combined with `@uniclaw/verifier` (step 20a), the wedge is integration-ready: the receipt-as-protocol claim has both the production path (sidecar mints) and the consumption path (TS verifier validates) shipped.

Threshold status after this PR:

- ✅ Threshold 1 (portability) — closed by step 20a.
- ✅ Threshold 2 (visibility) — closed by step 20.
- 🟡 Threshold 3 (adoption) — **lever shipped.** Next: build the first adapter against a real claw (OpenClaw or ZeroClaw) and show "X is Uniclaw-compatible" in the wild.

The receipt is portable. The receipt is demonstrable. **The receipt is now integrable.**
