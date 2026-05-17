# Phase 3.5 Step 23 — Tool-execution API

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **Crates touched:** `boardproof-host` (new endpoint + handler) + `packages/client-ts` (new method)
> **New artefacts:** `POST /v1/tool-executions` server route, `client.recordToolExecution(...)` TS method

## What is this step?

Steps 21 + 22 shipped half the wedge: **proposal + approval** over HTTP. An external runtime could mint receipts for *"the agent asked permission"* and *"the operator answered"*, but **not** for *"the tool actually ran"*. That gap forced every real integration to either embed the Rust kernel or wait for this PR.

Step 23 closes the gap. The kernel already supported tool-execution events since Phase 3 (step 13 + 15 + 18); this step exposes that surface over HTTP and through the TypeScript client.

After this PR, the whole agent action flow works over HTTP:

```
  POST /v1/proposals             →  evaluate_proposal receipt
       (run the tool externally)
  POST /v1/tool-executions       →  $kernel/tool/executed receipt
       (with optional secret_used + redaction_applied edges)
```

Real integrators (OpenClaw, NemoClaw, custom TS agents) can now anchor *every step* of an agent action without any embedded Rust.

## Where does this fit in the whole BoardProof?

```
┌──────────────────────────┐     POST /v1/proposals
│  Agent runtime           │ ──────────────────────►  ┌──────────────────────┐
│  (TS / Python / Go / …)  │                          │ boardproof-host         │
│                          │ ◄──────  AllowedDecision │ + kernel             │
│  @boardproof/client         │                          │ + constitution       │
│  client.evaluate()       │                          │ + log (RwLock)       │
│                          │                          │                      │
│  (run tool here, get     │                          │                      │
│   output_hash + optional │                          │                      │
│   secrets + redaction)   │                          │                      │
│                          │     POST /v1/tool-execs  │                      │
│  client.recordTool       │ ──────────────────────►  │                      │
│   Execution()            │ ◄────  AllowedDecision   │                      │
└──────────────────────────┘     ($kernel/tool/exec)  └──────────────────────┘
                                                              │
                                                              ▼
                                       receipt chain (prev_hash links execution to allowed)
                                       provenance edges: tool_execution / tool_input /
                                       tool_output / secret_used*N / redaction_applied*N /
                                       tool_execution_failure (failure path)
```

The execution receipt's `body.merkle_leaf.prev_hash` always equals the leaf_hash of the Allowed receipt that authorised the call — auditors can walk back from any tool execution to the proposal that allowed it.

## What problem does it solve technically?

### 1. "How do I anchor what my tool actually returned?"

Before this step, only proposal/approval flows were HTTP-addressable. A real integration would proceed:

1. Submit proposal → get Allowed receipt URL.
2. Run the tool externally.
3. *(blank)* — no way to anchor the output without embedding the kernel.

After this step, step 3 is one line:

```ts
const exec = await client.recordToolExecution({
  allowedReceiptId: allowed.contentId,
  outputHash: blake3Hex(toolOutputBytes),
  secretsUsed: ["github.token"],     // optional
  redaction: redactor.report,        // optional
});
```

The kernel mints a `$kernel/tool/executed` receipt with full provenance: `tool_execution` edge linking back to the proposal, `tool_input` + `tool_output` edges anchoring both content hashes, one `secret_used` edge per consumed secret reference (names only — never values), one `redaction_applied` edge per redactor rule that matched (with count).

### 2. "Why is there one endpoint instead of three?"

The war analysis lists three conceptual endpoints — `tool-executions`, `secret-uses`, `redactions`. The kernel implementation collapses them into a single event with optional fields, because:

- A tool execution **without** secrets or redaction is just a successful tool call.
- A tool execution **with** `secrets_used` carries the same provenance shape as a standalone secret-use event would.
- A tool execution **with** `redaction` carries the same provenance shape as a standalone redaction event would.
- Detached secret-use or redaction events (not tied to any tool call) don't have a clear use case today.

One endpoint covers all three semantics. If a future BoardProof release adds standalone events, they can land as additional endpoints without changing this one.

### 3. "How does verify-by-default handle the new receipt class?"

Same as for proposal/approval receipts: the client re-fetches `/receipts/<hash>`, reconstructs canonical body bytes via the JCS port from `@boardproof/verifier`, recomputes BLAKE3, compares to the URL claim, and verifies the Ed25519 signature against the embedded issuer key. The `$kernel/tool/executed` action.kind is just another value in the body — the verifier doesn't care about kind, only about bytes and signatures.

### 4. "What can't I submit yet?"

- **ToolError variants other than `Failed(message)`.** The kernel supports five variants (`NotFound`, `InvalidInput`, `Failed`, `Timeout`, `CapabilityDenied`); the wire format currently only encodes `Failed`. A future PR adds an optional `error_kind` field. Until then, callers that need richer error reporting can encode the kind in the message string.
- **Tool input bytes.** The wire only takes the hash. This is by design — the kernel never sees tool inputs or outputs in clear, only commits to their hashes.
- **Authenticated approvals.** The `principal` field on `/v1/approvals/{id}/resolve` is accepted but not yet recorded in the receipt; same future-step.

## How does it work in plain words?

The server-side handler (`crates/boardproof-host/src/api.rs::post_tool_execution`):

1. Parses `allowed_receipt_id` as a 32-byte digest (400 on malformed hex).
2. Requires **exactly one** of `output_hash` / `error` to be set (400 otherwise).
3. Looks up the Allowed receipt in the log (404 if missing).
4. Confirms its decision is `Allowed` (409 otherwise) and its `action.kind` starts with `"tool."` (409 otherwise).
5. Reconstructs the original `Proposal` from the receipt's body (so the kernel's authenticity gate has everything it needs).
6. Builds a synthetic `ToolOutput` (success path) with the precomputed hash + `secrets_used` names, OR a `ToolError::Failed(message)` (failure path). Empty `bytes` — the kernel doesn't read them.
7. Builds the optional `RedactionReport` from the wire's redaction sub-object.
8. Submits `KernelEvent::record_tool_execution(execution)`. The kernel re-runs every authenticity gate (signature verify, issuer match, decision-is-Allowed, action-match), then mints the `$kernel/tool/executed` receipt with all the appropriate provenance edges.
9. Appends to the log, returns the standard `ReceiptResponse` shape.

The client-side method (`packages/client-ts/src/client.ts::recordToolExecution`) is a thin wrapper:
- camelCase → snake_case conversion at the boundary
- omits absent optional fields rather than emitting `null` (smaller wire body; the server's `Option<...>` deserializer handles missing keys cleanly)
- verify-by-default applies the same way as `evaluate()`

## What you can do with this step today

- **Anchor real tool executions over HTTP:**
  ```ts
  const allowed = await client.evaluate({
    kind: "tool.http_fetch",
    target: "https://api.example.com/data",
    inputHash: blake3Hex(inputBytes),
  });
  if (allowed.kind !== "allowed") return;

  const outputBytes = await runTool(...);
  const exec = await client.recordToolExecution({
    allowedReceiptId: allowed.contentId,
    outputHash: blake3Hex(outputBytes),
  });
  // exec.receiptUrl is now a public, content-addressed URL
  // any verifier can validate cold.
  ```
- **Record secret usage** without exposing values:
  ```ts
  await client.recordToolExecution({
    allowedReceiptId,
    outputHash,
    secretsUsed: ["github.token", "slack.webhook"],
  });
  ```
- **Commit the receipt to a post-redaction hash:**
  ```ts
  await client.recordToolExecution({
    allowedReceiptId,
    outputHash: preRedactionHash,
    redaction: {
      redactedOutputHash: postRedactionHash,
      stackHash: redactorStackHash,
      matches: [{ ruleId: "github_pat", count: 1 }],
    },
  });
  ```
- **Anchor failures:**
  ```ts
  await client.recordToolExecution({
    allowedReceiptId,
    error: "connection refused",
  });
  ```

## Verified during this PR

- **10 new Rust integration tests** in `crates/boardproof-host/tests/api.rs`:
  - Success path with chain linkage assertion (`prev_hash` of execution == `leaf_hash` of allowed).
  - `secrets_used` emits one `secret_used` provenance edge per name.
  - `redaction` populates `body.redactor_stack_hash`, emits `redaction_applied` edges only for rules with `count > 0`, and the `tool_output` provenance edge references the POST-redaction hash.
  - Failure path emits a `tool_execution_failure` edge with the error message.
  - 400 on missing-both fields, 400 on both-set, 400 on malformed hex.
  - 404 on unknown `allowed_receipt_id`.
  - 409 on non-Allowed receipt, 409 on non-`tool.*` action.
- **9 new TS unit tests** in `packages/client-ts/tests/client.test.ts`: wire-shape conversion, redaction camelCase ↔ snake_case, error mapping (400/404/409), narrowing failure (unexpected response decision).
- **3 new TS integration tests** in `packages/client-ts/tests/integration.test.ts` against the live binary:
  - Propose → record (with secrets + redaction) → fetch + verify chain link + assert all expected provenance edges (`tool_execution`, `tool_input`, `tool_output`, `secret_used`, `redaction_applied`).
  - 409 when recording against a non-`tool.*` Allowed receipt.
  - Failure path with `error` field, verifying cold.
- **All 4 cargo gates clean:** fmt, build, **test 408/408 (+10 new)**, clippy.
- **TS gates clean:** typecheck, **vitest 36/36 (+12 new)**, build.
- **Bench** (`bench-results/23-tool-execution-api.txt`, gitignored):
  - `client.recordToolExecution verify=false`: **3.11 ms/req** (slightly faster than `evaluate verify=false` at 5.34 ms — smaller wire body, kernel doesn't re-run the Constitution on tool-execution events).
  - Full propose+record chain with both calls verify=true: **20.6 ms/req**.
  - Client overhead vs raw fetch: ~2 ms/req across both endpoint paths.

## Adopt-don't-copy

- The HTTP wire shape (`allowed_receipt_id` + optional `output_hash` / `error` / `secrets_used` / `redaction`) is original to BoardProof. None of the reference claw runtimes ship a comparable surface — IronClaw has internal audit events, but they aren't published over HTTP with cryptographic anchoring.
- The kernel's `RecordToolExecution` flow was already in place since steps 13 + 15 + 18; this PR is the HTTP exposure, not a kernel change.

## What this step does **not** ship

- **Standalone `/v1/secret-uses` / `/v1/redactions` endpoints.** The combined `/v1/tool-executions` payload covers both semantics today. Future PRs can add detached endpoints if a use case appears.
- **`/v1/checkpoints` (chain-checkpoint receipts).** Queued as step 19c.
- **Richer `error_kind`s.** v1 maps all errors to `ToolError::Failed(message)`. Adding `Timeout` / `CapabilityDenied` / etc. on the wire is one additional optional field — future PR.
- **Authentication.** Same as steps 21/22: no auth in the wire format; bind to loopback or a trusted network segment.
- **Persistent storage in proposal mode.** Still in-memory; the `--db` path remains read-only.
- **Worked OpenClaw / NemoClaw integration demo.** Now actually buildable on top of this client — queued as a follow-up step.

## Performance / size

See `bench-results/23-tool-execution-api.txt` for full numbers.

- `recordToolExecution` is roughly the same latency as `evaluate` — both are dominated by HTTP round-trip + Ed25519 sign + log append. The new endpoint adds no measurable overhead.
- The server binary grows by ~0.5 KB stripped (one new handler + wire-type Deserialize impls). Workspace stays at 17 of 20 Rust crates; client-ts is unchanged in dependency count.

## In summary

Step 23 completes the proposal → approval → tool-execution surface over HTTP. Combined with the existing read-only routes and the verifier, every step of an agent action is now anchorable and verifiable from any non-Rust runtime.

Threshold status:

- ✅ Threshold 1 (portability) — closed by step 20a.
- ✅ Threshold 2 (visibility) — closed by step 20.
- 🟢 Threshold 3 (adoption) — **first adapter ships, complete enough to integrate real agents.** Next: a worked OpenClaw or NemoClaw demo using the now-complete API, plus a Python sibling for compliance tooling.

The proposal was BoardProof-anchored. The approval was BoardProof-anchored. **Now every tool action is BoardProof-anchored too.** The agent doesn't need to know Rust exists.
