# Phase 3 Step 1 — Tool Execution Foundation

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crate introduced:** `uniclaw-tools`
> **Crate updated:** `uniclaw-kernel` (new `KernelEvent::RecordToolExecution`)

## What is this step?

This step opens **Phase 3** — the phase where Uniclaw moves from "the agent is authorized to do things" to "the agent actually *does* things, and we know what came back."

It ships the **architecture** for tool execution, not any actual tools. A new crate `uniclaw-tools` defines:

- **What a tool is** — the `Tool` trait every backend (WASM, container, MCP, native) implements.
- **What a tool can do** — a typed `Capability` enum with seven variants (`NetConnect`, `FileRead`, `FileWrite`, `ShellExec`, `EnvRead`, `LlmQuery`, `SecretRead`), each carrying a glob pattern.
- **When approval is needed** — an `ApprovalPolicy` (`Never` / `Discretionary` / `Always`).
- **How calls and outputs are shaped** — `ToolCall`, `ToolOutput`, `ToolError`, with BLAKE3 input/output hashes precomputed for receipt minting.
- **Where tools live** — a `ToolHost` registry (name → `Box<dyn Tool>`).
- **A built-in tool** — `NoopTool` (input == output, no capabilities), for tests and empty deployments.

And the kernel learns one new event: `KernelEvent::RecordToolExecution`. After a caller approves a tool call (existing flow) and runs it externally, it submits the result back to the kernel; the kernel runs an **authenticity gate** (mirrors the Approval flow) and mints a follow-on `$kernel/tool/executed` receipt with input + output hashes in provenance.

**No WASM runtime ships in this step.** That's step 14.

## Where does this fit in the whole Uniclaw?

```
                 Caller orchestrates
                       │
       ┌───────────────┼───────────────┐
       │               │               │
       ▼               ▼               ▼
  Kernel        ToolHost::call    Kernel
  EvaluateProposal       │       RecordToolExecution
  "tool.<name>"          │       (mint follow-on receipt
  → Allowed receipt      ▼        linking back via
                  Tool::call       provenance)
                       │
                       ▼
                 Result<ToolOutput,
                        ToolError>
```

Two receipts per tool call: the **authorization receipt** (existing flow — Constitution + Budget gates) and the **execution receipt** (this step). Both are content-addressed and chained. The execution receipt's provenance includes a `tool_execution` edge linking to the authorization receipt's content id, plus `tool_input` and `tool_output` edges carrying the BLAKE3 hashes.

This mirrors the Approval flow's two-receipt pattern (Pending → Approved/Denied) — same trust model: kernel stays stateless and synchronous, all external orchestration lives in the caller.

## What problem does it solve technically?

Four problems.

### 1. "How do we record what a tool actually returned?"

Before this step, the kernel could mint an "Allowed" receipt for `Action { kind: "tool.echo", target: "...", input_hash: ... }` — but nothing tied the kernel back to the tool's actual *output*. An auditor could verify the agent was *authorized* to call the tool, but not what the tool *returned*. The audit chain had a gap.

With `KernelEvent::RecordToolExecution`, that gap closes: every approved tool call gets a follow-on receipt with the output hash. An auditor with both receipts can:

1. Verify the proposal was authorized (constitution rules, budget).
2. Verify the execution receipt links to that proposal.
3. Verify the output hash matches the tool's output (re-run the tool, compare).

### 2. "What can a tool do?"

We adopt **OpenFang's** capability-enum-with-globs pattern (master plan §6.2). Each tool's `ToolManifest` declares the capabilities it claims:

```rust
ToolManifest {
    name: "http_fetch".into(),
    description: "Fetch a URL.".into(),
    action_kind: "tool.http_fetch".into(),
    declared_capabilities: vec![
        Capability::NetConnect(GlobPattern::new("api.example.com")),
        Capability::NetConnect(GlobPattern::new("*.googleapis.com")),
    ],
    default_approval: ApprovalPolicy::Never,
}
```

The `Capability` enum is **qualitative** (which hosts, which paths, which commands) — it complements the existing `ResourceUse` (which is **quantitative**: bytes, tokens, ms). Both are needed; neither subsumes the other.

The host registry will eventually enforce capabilities at call time (a future step adds the runtime check). v0 just defines the shape; constitution rules can already deny on `action.kind = "tool.<name>"` if the tool itself is the concern.

### 3. "What does the glob matcher look like?"

Tiny. ~50 LOC, no_std, no_dependencies-beyond-`alloc`, no regex, no backtracking pathology. Supports `*`, `prefix*`, `*suffix`, `*middle*`, and arbitrary combinations like `foo*bar*baz`. One pass through the pattern; matches a 28-character hostname against `*.example.com` in **327 ns**.

```rust
let p = GlobPattern::new("*.example.com");
assert!(p.matches("api.example.com"));
assert!(!p.matches("evil.test"));
```

We rolled our own instead of pulling a glob crate so the no_std posture and dep count stay clean.

### 4. "How does the kernel keep this honest?"

A 5-step authenticity gate, mirroring the existing Approval gate exactly:

1. The prior `allowed_receipt`'s Ed25519 signature must verify under its embedded issuer key.
2. That issuer must be **this kernel's** public key (a receipt signed by another kernel can't anchor under ours).
3. The prior receipt's `decision` must be `Allowed` (not Pending, not Denied — the lifecycle requires a clean approve-then-execute pair).
4. The prior receipt's `action.kind` must start with `"tool."` (defends against the audit chain accumulating "tool execution" records for non-tool actions).
5. The original proposal's `action` must match the prior receipt's `action` (defends against an attacker substituting a different proposal while keeping a valid prior receipt).

Any failure → `KernelError::RecordToolExecutionRejected(ToolExecutionRejection::*)`. **No receipt is minted.** The chain doesn't advance. The kernel doesn't anchor an attacker's noise.

## Why this design choice and not another?

- **Why a sync `Tool::call` instead of `async`?** Same reason `Kernel::handle` is sync: the kernel doesn't drive tool execution. Async runtimes (which a real WASM runtime needs for I/O) wrap a sync `Tool` in their own scheduling. This trait stays no_std-friendly.
- **Why precompute hashes in `ToolCall`/`ToolOutput`?** So the kernel doesn't re-hash. The caller has the bytes; let it hash once at call-site time, then ship the hash all the way through.
- **Why not invoke the tool from inside the kernel handler?** The kernel is stateless and synchronous. Tools may do I/O (network, disk, subprocess). Holding tool state in the kernel would couple the kernel to a runtime; running async I/O from the kernel would either block or require the kernel to become async. Both are bigger architectural shifts than warranted. Keep external orchestration external.
- **Why a separate event for execution recording instead of bundling with the proposal?** Same reason Approval has two events: the *authorize* and the *execute* steps may be separated by seconds (a long-running tool) or hours (an approval queue). Two receipts naturally express two events.
- **Why doesn't `OutcomeKind::ToolExecutedFailed` carry the error message?** `OutcomeKind` is `Copy + Eq` (existing invariant), and `ToolError` carries `String`s that would break that. The full message lives in the receipt's `tool_execution_failure` provenance edge — auditors read it from there.
- **Why `core::mem::discriminant` for `Capability::matches_request`?** Original implementation had 7 identical match arms, which clippy flagged. Using `discriminant` for the variant-equality check + an internal `glob()` helper to extract the pattern produces one shared body. Cleaner code, same behavior.

## What we adopted from each reference claw

The investigation done before designing this step turned up four contributions worth adopting (without copying source):

- **`OpenFang`'s `Capability` enum with glob matching** — directly adopted as `Capability` + `GlobPattern`. Their `validate_capability_inheritance()` (child caps ⊆ parent caps) is on the future list; v0 enforces at execution time only.
- **`IronClaw`'s two-phase approval** (`requires_approval(&params)` enum, post-execution `ActionRecord`) — adopted as `ApprovalPolicy { Never, Discretionary, Always }` on the trait + `KernelEvent::RecordToolExecution` after the fact. `IronClaw`'s WIT Component Model is **not** adopted at this layer — it'll sit behind a `WasmTool` adapter in step 14.
- **`OpenClaw`'s gateway-level deny list for high-risk tools** — adopted philosophically as Constitution rule patterns (already supported). High-risk tool kinds get a `Deny` rule; that's where they belong, not in trait code.
- **`ZeroClaw`'s signed manifests with Ed25519** — on the future list (a separate step), with default-on signature verification (the opposite of `ZeroClaw`'s default-off).

No source borrowed from any of the four claws. Citations in `crates/uniclaw-tools/src/lib.rs` adopt-don't-copy section.

## What you can do with this step today

- Define your own `Tool` impl by implementing the trait.
- Register it on a `ToolHost`.
- Submit a `Proposal` with `action.kind = "tool.<name>"` to the kernel; get back an `Allowed` receipt.
- Call `host.call(&ToolCall)` to execute (sync).
- Submit `KernelEvent::record_tool_execution(ToolExecution { ... })` to anchor the result.
- Read the resulting receipt with `uniclaw-explain` — it shows the action kind, output hash, and provenance edges back to the authorization.

```rust
// Sketch of the full flow (pseudo-code).
let mut kernel = Kernel::new(signer, clock, constitution);
let mut host = ToolHost::new();
host.register(Box::new(NoopTool::new()));

let input = b"hello tools";
let proposal = Proposal::unbounded(
    Action {
        kind: "tool.noop".into(),
        target: "echo".into(),
        input_hash: Digest(*blake3::hash(input).as_bytes()),
    },
    Decision::Allowed, vec![], vec![],
);

let allowed = kernel.handle(KernelEvent::evaluate(proposal.clone()))?.receipt;

let output = host.call(&ToolCall {
    tool_name: "noop".into(),
    target: "echo".into(),
    input: input.to_vec(),
    input_hash: allowed.body.action.input_hash,
})?;

let exec = kernel.handle(KernelEvent::record_tool_execution(ToolExecution {
    allowed_receipt: allowed,
    original_proposal: proposal,
    result: Ok(output),
}))?;
// exec.kind == OutcomeKind::ToolExecutedAllowed { input_hash, output_hash }
// exec.receipt.body.action.kind == "$kernel/tool/executed"
```

## Performance baseline (release, x86_64 Linux)

| Operation | Per call |
|---|---|
| `RecordToolExecution` (success path, NoopTool, full Ed25519 verify + sign) | **116.20 µs** |
| `RecordToolExecution` (failure path, smaller provenance) | **91.53 µs** |
| `GlobPattern::matches` (28-char candidate, `*.example.com` pattern) | **327 ns** |
| `Capability::matches_request` (variant + glob) | **118 ns** |

The `RecordToolExecution` cost is dominated by the Ed25519 verify of the prior receipt (~52 µs warm) plus Ed25519 sign of the new receipt — same shape as the Approval flow. Both are well under any plausible network round-trip.

## What this step does **not** ship

- **No WASM runtime.** Step 14: `uniclaw-tools-wasm` with `wasmtime` + WIT Component Model.
- **No real tool implementations.** HTTP fetch, file read, shell exec — these arrive alongside the WASM runtime.
- **No runtime capability enforcement.** A tool that uses a capability not in its manifest currently isn't caught — capabilities are declared but not yet checked. Step 15 adds the host-layer enforcement (HTTP allowlist + SSRF defense, adopted from `IronClaw`).
- **No signed manifests.** Step in the queue.
- **No async API.** Tools are sync; runtimes that need async wrap a sync impl.

## In summary

Step 13 opens Phase 3 by laying down the trait surface every later tool-related step plugs into. The shape is informed by careful study of four reference claws — `IronClaw`, `OpenFang`, `OpenClaw`, `ZeroClaw` — and adopts the best ideas from each without copying source. The kernel learns one new event; the audit chain finally records *what the tool actually returned*, not just *that the agent was authorized to ask*. With this foundation in place, the WASM runtime, capability enforcement, secret broker, and container fallback can land as focused follow-up steps without re-architecting.
