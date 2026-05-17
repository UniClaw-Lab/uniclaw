# Phase 3 Step 5 — Output Sanitization / Redaction Proofs (18)

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crate introduced:** `boardproof-redact`
> **Crates updated:** `boardproof-receipt` (audit-data types), `boardproof-kernel` (RecordToolExecution wiring)

## What is this step?

Tools return bytes. Those bytes might contain a credential — the OAuth token an API echoed back, the bearer header a misbehaving service logged, the `Authorization:` line a debug endpoint included for "convenience." Without sanitization, those bytes go into the receipt's output, get hashed, and become part of the audit trail forever. Even worse, the bytes might also flow back to the LLM that called the tool — and the LLM might quote them in its next response, where they go into another receipt, where they get archived again.

Step 18 closes that gap. A new `boardproof-redact` crate runs operator-configured pattern matching over tool-output bytes BEFORE the kernel hashes them, replacing matches with `[REDACTED:<rule-id>]` placeholders. The kernel records what happened: the post-redaction hash becomes the receipt's `output_hash`, one `redaction_applied` provenance edge fires per rule that matched, and `ReceiptBody::redactor_stack_hash` (a placeholder field since RFC-0001) finally has a real producer.

Three properties matter:

1. **The receipt commits to the redacted form.** The `output_hash` in the audit chain is BLAKE3 of redacted bytes, not original bytes. The original bytes never reach the kernel.
2. **The receipt commits to *which* redactor stack ran.** `redactor_stack_hash` is a stable hash over the ordered list of redactor IDs. Two stacks with different IDs produce different hashes; auditors can verify "stack X ran on this output" by checking the stack's hash against the operator's published config.
3. **The audit edges name what fired.** One `redaction_applied` provenance edge per matching rule, with `to = "redaction:<rule_id>:count=<n>"`. Auditors querying "which receipts redacted GitHub PATs?" run a structural query.

This is the audit primitive the war-analysis positioning has been waiting for. After step 18, BoardProof can answer the question "what was redacted, by which rules, and when" with the same receipt-format guarantees it gives every other action.

## Where does this fit in the whole BoardProof?

The redaction pipeline lives **between the tool layer and the kernel** in the existing `RecordToolExecution` flow:

```
                  Caller
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      Kernel              ToolHost
      (Allowed                │
       receipt)               ▼
                          Tool::call returns
                              ToolOutput { bytes, output_hash, metadata }
                              │
                              ▼
                       ┌──────────────────────┐
                       │  boardproof-redact      │  ◀── new in 18
                       │  RedactorStack::redact(bytes)
                       │       │
                       │       ▼
                       │  RedactionResult {
                       │    redacted_bytes,
                       │    report: RedactionReport {
                       │      redacted_output_hash,
                       │      matches: Vec<RuleMatch>,
                       │      stack_hash,
                       │    }
                       │  }
                       └──────────────────────┘
                              │
                              ▼
                       Caller submits to kernel:
                         ToolExecution { result, redaction: Some(report) }
                              │
                              ▼
                       Kernel mints receipt:
                         output_hash = redacted_output_hash
                         redactor_stack_hash = stack_hash
                         + one `redaction_applied` edge
                           per RuleMatch with count > 0
```

The kernel doesn't see the original bytes. The redactor doesn't see the kernel. Each layer commits to its own piece of the audit chain.

## What problem does it solve technically?

Three problems.

### 1. "How does the audit chain commit to the redacted form rather than the leaky form?"

The kernel uses `redaction.redacted_output_hash` as the receipt's `output_hash` whenever the caller supplies a `redaction` payload. The original `output.output_hash` (computed by the tool over the un-redacted bytes) is *not* recorded anywhere. The receipt's signed body proves what was in the post-redaction output — which is exactly what an auditor wants.

### 2. "How does an auditor verify the operator's redactor stack actually ran?"

`ReceiptBody::redactor_stack_hash` (existed in RFC-0001 as a placeholder; step 18 finally produces it) holds `BLAKE3(stack_id + "\n" + redactor_id_1 + "\n" + …)`. The operator publishes their stack config; the auditor recomputes the hash from the published config; the receipt either matches or doesn't. If the receipt's hash matches, the operator's claimed stack is what ran. If not, something disagrees.

For v0, the hash commits to the *ID list*, not the rule patterns inside each redactor. Operators who want stricter commitments encode rule details into the redactor ID itself (e.g. `"default-rules-2026-05-08"`); a future Phase-6 `$kernel/policy/redactor` receipt will give a richer commitment.

### 3. "How do auditors find every receipt that redacted a particular credential class?"

`redaction_applied` provenance edges. Each edge has `from = "receipt:<id>"`, `to = "redaction:<rule_id>:count=<n>"`, `kind = "redaction_applied"`. Auditors querying for `kind = "redaction_applied" AND to LIKE "redaction:default::github_pat:%"` find every receipt where a GitHub PAT was redacted. Same shape as the `secret_used` edges from step 15; they compose into the same provenance graph.

## How does it work in plain words?

```rust
use std::sync::Arc;
use boardproof_redact::{PatternRedactor, RedactorStack, Redactor};
use boardproof_kernel::{KernelEvent, ToolExecution};

// 1. Operator configures their redactor stack at startup.
let stack = RedactorStack::new(
    "v0",
    vec![Arc::new(PatternRedactor::with_defaults("default"))
        as Arc<dyn Redactor>],
);

// 2. Caller runs the tool as usual.
let output = tool.call(&call)?;

// 3. Caller runs the redactor on the tool output.
let result = stack.redact(&output.bytes);
// `result.redacted_bytes` is what the caller passes to its
// own next consumer (the LLM, the user, the message thread).
// `result.report` is what the caller passes to the kernel.

// 4. Caller submits to the kernel as usual; the new
//    `redaction` field carries the audit-data report.
let exec_outcome = kernel.handle(KernelEvent::record_tool_execution(
    ToolExecution {
        allowed_receipt: prior,
        original_proposal: proposal,
        result: Ok(output),
        redaction: Some(result.report),
    },
))?;

// 5. The minted receipt:
//    - body.action.target shows post-redaction status
//    - body.redactor_stack_hash = stack.stack_hash()
//    - body.provenance includes one redaction_applied edge
//      per matched rule
//    - The OutcomeKind::ToolExecutedAllowed::output_hash
//      is the redacted hash.
```

The flow before step 18 is unchanged for callers who don't pass a `redaction` — the field defaults to `None`, the kernel records the tool's original output_hash, and `redactor_stack_hash` stays `None`. Backwards-compatible.

## Why this design choice and not another?

- **Why run the redactor *outside* the kernel?** The kernel is `no_std` and has no `regex` dependency. Pulling a regex engine into the kernel would be a big architectural change for a feature that doesn't need kernel-side state. The redactor runs in the caller's process with full `std`; the kernel records the outcome.
- **Why a `RedactionReport` audit-data type in `boardproof-receipt`?** That's the `no_std`-friendly home for kernel-shaped types. The `Redactor` *trait* and its impls live in `boardproof-redact` (`std`); the *data* the kernel reads lives in `boardproof-receipt`. Same split as `ToolMetadata` (data in `boardproof-tools`, kernel reads it).
- **Why pattern-based, not value-based?** Value-based scanning (search for the literal value of every registered secret) would require the kernel — or the redactor process — to fetch every secret value at receipt-mint time and have them all in memory simultaneously. That's a much bigger trust + memory surface. Pattern-based redaction handles the realistic credential-leak case (an API echoes a token); secret-value scanning is a future-step add-on.
- **Why include zero-count rule matches in `RedactionReport.matches` but skip emitting edges for them in the kernel?** The redactor returns what it ran (transparent reporting). The kernel emits provenance for what *fired* (audit signal). Zero-count entries say "this rule ran but matched nothing" — useful for the redactor's debug output but noise in the receipt. The kernel filters.
- **Why `BLAKE3(stack_id + redactor_ids)` for `stack_hash` instead of including the rule patterns?** Two trade-offs collapsed into one decision: (a) including rule patterns ties the hash to the exact regex syntax, which is brittle when patterns are updated for performance/coverage; (b) excluding them lets operators commit at the level of "stack X" via the operator's published config. For v0 the looser commitment is the right default; tighter commitments wait for the Phase-6 policy-receipt class.
- **Why the `regex` crate at full feature set?** `\b`/`\d`/`\w` need the `unicode-perl` feature. We could write the patterns without those classes — but that's more brittle for operators extending the rule list. The dep weight (~2 MB source, <100 KB binary contribution) is acceptable for v0; future tuning could swap to `regex::bytes::Regex` and rewrite the patterns to skip unicode classes.

## Adopt-don't-copy

- **`IronClaw`'s `crates/ironclaw_safety/` redaction discipline** — adopted in *philosophy*: "scan output for known secret patterns, redact, sign the result before the audit chain commits." Their pattern corpus informed our default-rule list (we cover the common shapes — GitHub, OpenAI, Anthropic, Slack, AWS, JWT, generic Bearer); their richer features (structured-leak detection, PII redaction, output sanitisation across logging stacks) are on the future-step list when use cases demand them. No source borrowed.

Citation lives in `crates/boardproof-redact/src/lib.rs`.

## What you can do with this step today

- Construct a `PatternRedactor::with_defaults` covering the common credential prefixes; wrap it in a `RedactorStack` with a stable ID; pass `result.report` to `KernelEvent::RecordToolExecution`.
- Add deployment-specific patterns via `PatternRedactor::with_rules` — internal API formats, custom token shapes, organisation prefixes. The default list is defense-in-depth, not exhaustive.
- Verify a receipt's `redactor_stack_hash` matches your published stack config — proof the operator's redactor actually ran.
- Query `kind = "redaction_applied"` provenance edges to find every receipt that redacted a particular rule class.
- Trust that a `ToolExecution` *without* a `redaction` field works exactly as today — the integration is purely additive.

## Performance baseline (release, x86_64 Linux)

| Operation | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| `PatternRedactor::with_defaults` redact (1 token to remove) | **25 µs (38 MiB/s)** | **116 µs (540 MiB/s)** | **2.4 ms (421 MiB/s)** |
| Same redactor, clean input (no matches) | 4 µs (221 MiB/s) | 331 µs (189 MiB/s) | 1.7 ms (591 MiB/s) |

Throughput is well into the "fast enough to run on every tool output" range. A 10 MiB output (HttpFetchTool's default cap) costs ~20 ms of redaction. The redactor's per-call overhead is dominated by per-rule `find_iter` on the input; future tuning could compile all default rules into a single `RegexSet` to amortise. See [`bench-results/17-output-sanitization.txt`](../../bench-results/17-output-sanitization.txt) for raw numbers and methodology.

## What this step does **not** ship

- **Secret-value scanning.** v0 only matches *patterns*. A future step could tie into `boardproof-secrets` to scan for the literal values of currently-registered secrets — risky because it requires the redactor to handle live secret material; defer until 18b.
- **Structural / JSON-path redaction.** Regex-only for v0; structural redaction would need deserialization and a path DSL. Future step.
- **`$kernel/policy/redactor` receipt class** for "operator configured stack X at time T." The operator's stack hash is committed to via `redactor_stack_hash`, but there's no separate receipt that anchors the operator's chosen config in the audit chain. Phase 6 governance.
- **Per-output redactor selection.** The kernel takes whatever `redaction` the caller passes. Routing decisions (e.g. "use strict redactor for filesystem outputs, lax redactor for hashes") live in the caller's wiring. Future step could surface a `Capability::RedactorChoice` if a use case demands kernel-side routing.
- **`PatternRedactor::with_defaults` exhaustiveness.** The default rule list is a starting corpus; deployments are expected to extend it. Tracking every new credential prefix that ships in the wild is an ongoing maintenance load; we'd rather ship a small, tested default than a huge stale one.

## In summary

Step 18 closes the loop on BoardProof's "redaction proof" claim from aspirational to demonstrated. The kernel's audit chain now commits to the post-redaction form of every tool output (when redaction was applied), records *which* rules fired with structural provenance edges, and pins *which* redactor stack ran via the long-placeholder `redactor_stack_hash` field. Phase 3's wedge is now complete: capability + SSRF + secrets + WASM (core / Component / with-host) + redaction + verifiable receipts for every action. Phase 3's next decision is whether to ship step 17 (container fallback) as an optional plugin or move directly to Phase 4 (federated memory) since the trust story is unambiguous.
