# Changelog

All notable changes to Uniclaw are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Receipt-format changes are versioned independently; see `RFCS/` for receipt
format change history.

## [Unreleased]

### Added

- **Beginner-friendly documentation set under `docs/`.** First doc-only PR;
  a standing rule going forward is that every implementation step ships
  with (or is followed by) a step doc in `docs/steps/`.
  - `docs/README.md` — index + navigation guidance + style conventions.
  - `docs/01-what-is-uniclaw.md` — intro for everyone (what Uniclaw is,
    what it does, who it's for, the eight skills).
  - `docs/02-uniclaw-vs-openclaw.md` — side-by-side comparison with the
    most popular agent runtime; "when to pick which" guidance.
  - `docs/03-roadmap.md` — friendly tour of the eight phases with
    Mermaid timeline.
  - `docs/steps/00-foundation-receipts.md` through
    `docs/steps/08-light-sleep.md` — one page per shipped step,
    covering: what it is → where it fits → what problem it solved →
    how it works → what you can do today.
  - All docs use plain English, define jargon on first use, and embed
    Mermaid diagrams where they help (GitHub renders them inline).

## [Phase 1 — Shippable Core] complete on `main`

- **`uniclaw-sleep` crate** — Light Sleep cleanup architecture (master
  plan §16.3.1). Workspace member 10. The Spine layer's
  background-task surface; the kernel turns each pass into a signed
  audit receipt.
  - `Cleanable` trait — `name() -> &str` + `clean() -> Result<CleanupReport,
    CleanupError>`. Subsystems implement it to participate in Light Sleep.
    Cleaners must be idempotent and cheap; failures are recorded, not
    propagated.
  - `CleanupReport { rows_affected, bytes_reclaimed }` — what one cleaner
    did. `CleanupReport::EMPTY` is the canonical no-op result for cleaners
    that ran but found nothing to do.
  - `LightSleepReport` — aggregated pass result with `cleaner_count`,
    `total_rows_affected`, `total_bytes_reclaimed`, `failed_count`,
    `all_succeeded` helpers. Order-preserving; per-cleaner outcomes
    stay aligned with the slice the orchestrator received.
  - `run_light_sleep(&mut [&mut dyn Cleanable]) -> LightSleepReport` —
    sequential best-effort orchestrator. A failing cleaner is logged
    in the report and the pass continues.
- **Kernel: Light Sleep receipt path.**
  - `KernelEvent::RunLightSleep(Box<LightSleepReport>)` variant +
    `KernelEvent::run_light_sleep(report)` constructor.
  - `OutcomeKind::LightSleepCompleted { failed_cleaners }` —
    successful pass even when individual cleaners failed; failures
    appear in the receipt's provenance edges, not in the kernel's
    error path.
  - Kernel mints one signed receipt per pass with
    `action.kind = "$kernel/sleep/light"`,
    `action.target = "cleaners=N rows=R bytes=B failed=F"`,
    and one provenance edge per cleaner
    (`from = "cleaner:<name>"`, `kind = "light_sleep_pass"` for
    successes / `"light_sleep_failure"` for failures with the message
    in `to`).
  - Sleep types are re-exported through `uniclaw-kernel` so
    downstream callers don't need a direct `uniclaw-sleep` dep just to
    construct the event.
- 8 new tests (4 sleep-crate unit + 4 kernel unit + 2 kernel
  integration with real Ed25519 signatures). Integration tests prove
  the empty-cleaner case still mints a verifiable receipt, the per-
  cleaner provenance is faithful, and tampering provenance breaks the
  signature.
- Workspace test count: 141 → 151.

### Why an empty pass still mints a receipt

In v0 there is no persistent session state, no SQLite, and no
provenance graph — so a Light Sleep pass with **zero registered
cleaners** is the norm. The receipt itself is the artifact proving
the schedule fired on time. As cleanup-needing subsystems land they
register `Cleanable` impls and the same receipt grows real
rows-affected counts.

### Performance (bench-results/, gitignored)

- Light Sleep pass, 0 cleaners: **32.65 µs/call** (just sign + leaf-hash —
  in line with the kernel::handle baseline)
- Light Sleep pass, 3 cleaners: **40.09 µs/call**
- Light Sleep pass, 10 cleaners: **46.04 µs/call** (~1.3 µs/cleaner of
  String allocation overhead for provenance edges)

### Notes

- Adopt-don't-copy: sleep-stage memory is net-new in this shape — none
  of the nine reference claw runtimes have it. The cleanup-pass *idea*
  generalizes long-known background-GC patterns from database engines
  (`PostgreSQL`'s autovacuum, `SQLite`'s incremental VACUUM); we mirror
  that idea, not their code. Cited in `uniclaw-sleep/src/lib.rs`.
- REM Sleep (§16.3.2) and Deep Sleep (§16.3.3) arrive in follow-up
  steps once their backing subsystems (provenance graph, federated
  memory CRDT) land.

- **`uniclaw-store` crate** — chain-validated, issuer-pinned receipt log
  (master plan §16.1 *Audit*). Workspace member 9. The substrate Light
  Sleep, public-URL receipt hosting, and provenance-graph queries all
  build on.
  - `ReceiptLog` trait — `append`, `len`, `last`, `get_by_sequence`,
    `get_by_id`, `verify_chain`. Implementations refuse any receipt
    that doesn't extend the chain.
  - `AppendError` typed enum: `OutOfOrder` / `ChainBroken` /
    `SignatureInvalid` / `IssuerMismatch` / `UnsupportedVersion` /
    `DuplicateId`. Refused appends do **not** modify log state — the
    invariant callers rely on for `len()` to reflect verified entries.
  - `VerifyChainError` typed enum: `SequenceGapAt` / `BrokenAt` /
    `SignatureInvalidAt`. Returns the **first** violation found.
  - `InMemoryReceiptLog` — `Vec<Receipt>`-backed with `BTreeMap` index
    for O(log n) content-id lookup. Issuer-pinned at construction so a
    log cannot accidentally interleave receipts from multiple kernels.
  - `IntoIterator` impl on `&InMemoryReceiptLog` for ergonomic
    `for r in &log { … }`.
- 13 new tests (8 unit + 4 integration + 1 from doc-test slot). The
  integration tests drive a real Ed25519 kernel through 16 receipts
  then prove tampering is caught by both `append` (sig invalid) and
  `verify_chain` (storage-layer mutation after the fact).
- 13 new tests overall (workspace count: 128 → 141).

### Performance (bench-results/, gitignored)

- `append` (full validation: version + issuer + sequence + chain +
  Ed25519 verify + BTreeMap insert): **64.6 µs/call**
- `verify_chain` on 1000-receipt log: **56.9 µs/receipt** (~57 ms total)
- `get_by_id` (BTreeMap on 32-byte keys): **0.131 µs/lookup**

### Notes

- Adopt-don't-copy: issuer-pinned + append-validating chain storage in
  this shape is net-new. `OpenFang`'s `audit.rs` records similar
  Merkle hashes but stores them in a kernel-owned `SQLite` table; we
  keep storage out-of-kernel and validate at the boundary. Cited in
  `uniclaw-store/src/lib.rs`.
- A `SqliteReceiptLog` impl arrives in a follow-up step. The trait
  surface is designed to support both without changes.

- **`uniclaw-router` crate** — channel-aware approval routing (master plan
  §21 #7). Workspace member 8.
  - `ApprovalRouter` trait — synchronous, takes `&mut self` so impls can
    own buffered IO without interior mutability. Returns
    `Result<ApprovalDecision, RouterError>`.
  - `RouterError` typed enum: `Io(String)` / `InvalidInput(String)` /
    `Cancelled` / `Backend(String)` — distinguishes IO failure from
    operator cancellation from backend unavailability so callers can
    react appropriately (retry, escalate, fall back).
  - `CliApprovalRouter<R: BufRead, W: Write>` — terminal router. Renders
    the pending receipt via `uniclaw-explain::render_text`, prompts
    `Approve this action? (y/n)`, retries up to 3 times on bad input,
    treats EOF as cancellation. Generic over IO so tests inject
    `Cursor<Vec<u8>>` and the production path uses
    `CliApprovalRouter::stdio()`.
  - `evaluate_with_routing(kernel, router, proposal)` — single-call
    orchestrator. Submits the proposal, routes any `PendingApproval`
    outcome through the router, resubmits the operator's response.
    Skips the router entirely when the proposal is decided directly
    (Allowed / Denied / budget-exhausted).
  - `OrchestrationError` aggregating `KernelError` + `RouterError` with
    `From` impls for ergonomic `?`.
  - 7 router unit tests + 2 orchestrator unit tests + 4 integration
    tests with a real Ed25519-signing kernel and mocked stdio. All 13
    new tests cover: y / yes / Y / YES / n / no / NO → correct decision;
    invalid input + retry; retry-budget exhaustion; EOF → Cancelled;
    Allowed pass-through skips router; Denied pass-through skips router;
    Pending → operator-approves yields signed Approved receipt with
    `approval_response` provenance edge; Pending → operator-denies yields
    signed Denied receipt with `$kernel/approval/denied_by_operator`;
    router error propagates as `OrchestrationError::Router`.
- 13 new tests overall (workspace count: 115 → 128).

### Notes

- Adapter scarcity rule (§24.5): only the CLI router ships in this
  release. Slack, email, webhook, mobile-notification, and other
  backends require ≥ 10 GitHub-thumbs of demand before development
  starts.
- Adopt-don't-copy: pattern inspired by IronClaw's exec-approval flow
  and OpenClaw's `deny`/`allowlist`/`ask` exec-policy modes;
  reimplemented from spec, no source borrowed. Cited in
  `uniclaw-router/src/lib.rs`.

### Performance (bench-results/, gitignored)

- `evaluate_with_routing` (CLI router, approve path): **174 µs/call**
  (~5 700 ops/sec). Adds ~48 µs over the raw approval round-trip
  (126 µs from PR #4) — that delta is the cost of explain-rendering
  the pending receipt as plain text plus Cursor I/O.


  receipts (master plan §11.3, §21 #7). v0 ships only the
  `ApprovalDecision` enum (`Approved` / `Denied`); the pluggable
  `ApprovalEngine` trait, channel-aware routing, timeout handling, and
  adaptive promotion arrive in subsequent steps.
- **`RuleVerdict::RequireApproval`** in `uniclaw-constitution`. Maps to
  `Decision::Pending` from the constitution evaluator. Precedence rule:
  `Deny` > `RequireApproval` > pass-through, so the safe-by-default
  property holds when both verdicts match.
- **Full approval flow in the kernel:**
  - New `KernelEvent::ResolveApproval(Approval)` event variant.
  - New `Approval { pending_receipt, original_proposal, response }`
    struct. The kernel does **not** store pending state — the caller
    holds both the pending receipt and the original proposal and
    resubmits them when the operator decides.
  - Authenticity gate at resolve time: verifies the pending receipt's
    Ed25519 signature, confirms the issuer matches **this** kernel's
    public key, confirms the body decision is `Pending`, and confirms
    the resubmitted action matches. Forged inputs surface as
    `KernelError::ResolveApprovalRejected(ApprovalRejection)` and
    **do not advance the audit chain or mint a receipt**.
  - The final receipt records a `provenance` edge
    `{from: "receipt:<pending_id>", to: "decision", kind: "approval_response"}`
    so cold readers can chase the cross-receipt link.
  - Budget timing: Pending receipts **do not charge** the lease. The
    charge happens at `Approved` time, with a fresh budget check that
    can still mint `Denied` if the lease has been exhausted in the
    meantime (`OutcomeKind::DeniedByBudgetAtApproveTime`).
- **`OutcomeKind` extended** with `PendingApproval`,
  `ApprovedAfterPending`, `DeniedByOperator`,
  `DeniedByBudgetAtApproveTime`. **`KernelError`** introduced as the
  return-side companion: rejections that don't produce receipts.
- **`Signer::public_key()`** — required so the kernel can answer "did I
  sign this pending receipt?" at resolve time without storing anything.
- **`KernelEvent::evaluate(p)` / `KernelEvent::resolve(a)`** convenience
  constructors so callers don't write `Box::new` everywhere.
- **`uniclaw-explain` extended:**
  - New `RuleKind::KernelApproval { reason }` decodes
    `$kernel/approval/<reason>` rule IDs (today: `denied_by_operator`).
  - New `Verdict::DeniedByOperator`. `Verdict::Pending { rules_consulted }`
    now carries the consulted-rule count, mirroring `Allowed`.
  - Renderer: prints "Awaiting operator approval" for `Pending`,
    "Operator approved a previously-pending action" for `Approved`,
    "Operator denied a previously-pending action" for the operator-
    denied case.
- **`constitutions/solo-dev.toml`** gains a `solo-dev/git-push-needs-approval`
  rule demonstrating `require_approval`. (Shadowed by `solo-dev/no-shell`
  in practice — both rules fire, deny wins, both appear in the receipt.)
- 23 new tests across three crates (the kernel grew from 19 to 23 unit
  tests with new approval-flow paths; integration tests grew from 5 to
  12 covering the full round-trip + every authenticity rejection path).

### Changed

- **`Kernel::handle` now returns `Result<KernelOutcome, KernelError>`**
  to honestly distinguish "honest rejection that produced a receipt"
  (constitution deny, budget exhausted, operator denied — all keep
  returning `Ok`) from "forged or malformed input that didn't produce
  one" (only `Err`). Existing callers add `.expect("ok")` or `?`.
- **`KernelEvent` variants are boxed** (`EvaluateProposal(Box<Proposal>)`,
  `ResolveApproval(Box<Approval>)`) so the enum stays small. Use the new
  `KernelEvent::evaluate(p)` / `KernelEvent::resolve(a)` constructors.

### Performance (bench-results/, gitignored)

- Pending mint only: **38.5 µs/call** (same as a normal proposal)
- Full approval round-trip (Pending mint + ResolveApproval): **126 µs/call**
  (~7900 ops/sec) — sign + verify + sign

- **`uniclaw-explain` crate** — cold receipt explainer (master plan §21
  #13). Library + standalone CLI binary that takes any signed receipt
  and produces a human-readable decision tree without access to kernel
  state.
  - `Explanation` struct: `receipt_id`, `canonical_url`
    (`uniclaw://receipt/<hash>`), `issuer`, `issued_at`,
    `SignatureStatus`, `ActionInfo`, `decision`, classified rules,
    `Verdict`, `MerkleInfo`, provenance edges.
  - `RuleKind` classifies each rule entry as
    `Constitution` (operator-authored), `KernelBudget { reason }`
    (virtual rule synthesized by the kernel), or `UnknownKernel`
    (forward-compat for `$kernel/*` rules from a newer runtime).
  - `Verdict` enum: `Allowed { rules_consulted }` /
    `DeniedByConstitution { rule_id }` /
    `DeniedByBudget { reason }` / `DeniedAsProposed` / `Approved` /
    `Pending`. Distinct from `Decision`: `Decision` is what the
    receipt body claims; `Verdict` is the explainer's classification
    of *why*.
  - `render_text` produces stable, snapshot-friendly plain-text;
    `render_json` produces pretty JSON with the same structure for
    tooling.
  - CLI binary `uniclaw-explain <receipt>` with `--json` flag. Reads
    from a file or stdin (`-`). Exits **2** on signature failure so
    the binary is scriptable.
  - 15 unit tests + 6 subprocess integration tests covering allowed,
    denied-by-constitution, denied-by-budget, denied-as-proposed,
    tampered receipts, JSON mode, malformed input.
  - **Stripped release binary: 727 KiB** (5 KiB more than
    `uniclaw-verify`); cold-path latency 3.67 ms/call.
- **`uniclaw_budget::BudgetError::from_short_name`** — inverse of
  `short_name`, single source of truth for explain tooling decoding
  `$kernel/budget/<reason>` rule IDs.

- **`uniclaw-budget` crate** — capability budget algebra (master plan
  §11 / §21 #2). Numeric grants of `net_bytes`, `file_writes`,
  `llm_tokens`, `wall_ms`, `max_uses` enforced by `CapabilityLease`.
  - `Budget` + `ResourceUse` with saturating arithmetic (no panic on
    overflow).
  - `CapabilityLease::try_charge` deducts `consumed` only on success;
    failure leaves state untouched and names the specific exhausted
    resource via `BudgetError`.
  - `CapabilityLease::delegate` carves a child lease using
    **reservation semantics**: parent's `consumed` is debited upfront
    by the full child budget. Guarantees a delegated agent can never
    exceed parent's remaining budget at delegation time.
  - 8 unit tests + 4 composition integration tests covering 3-level
    delegation chains, partial exhaustion, full delegation, revocation.
- **Kernel integration**: `Proposal` now carries
  `lease: Option<CapabilityLease>` + `charge: ResourceUse`; the kernel
  charges before minting. Budget exhaustion forces `Decision::Denied`
  and records a virtual `$kernel/budget/<reason>` rule in the receipt
  so the cold-verifiable artifact is self-explaining.
- **`KernelOutcome` extended** with `lease_after` (post-charge state
  for thread-through) and `kind: OutcomeKind` (machine-readable explain
  trail: `Allowed` / `DeniedByConstitution` / `DeniedByBudget(err)` /
  `AllowedAsDenied`).
- **Order**: Constitution → Budget. If the constitution denies, the
  lease is **not** charged (short-circuit; tested).
- 7 new kernel unit tests + 1 new chain integration test (8-call
  exhaustion sweep with real Ed25519 signing).
- Benchmark: `kernel.handle` with a threaded `CapabilityLease`
  measures within noise of the no-lease path (~32 vs ~35 µs/call).
  Charging the lease is free next to Ed25519 signing.

### Changed

- `Proposal` constructor changed: existing call-sites use
  `Proposal::unbounded(...)` (no lease) or `Proposal::with_lease(...)`.
  Tests updated accordingly.

- **`uniclaw-constitution` crate** — deterministic rules engine, separate
  from the model, judging proposed actions before the policy gate (master
  plan §11.3). v0 ships:
  - `Constitution` trait + `ConstitutionVerdict` (matched rules + optional
    forced override).
  - `EmptyConstitution` no-op + `InMemoryConstitution` evaluator.
  - TOML loader (`parse_toml`) with typed `ParseError`.
  - `Rule` / `MatchClause` / `RuleVerdict` (today: `Deny` only).
  - **Safe-by-default**: rules can force `Decision::Denied`, never grant
    `Decision::Allowed`.
- **First starter constitution** at `constitutions/solo-dev.toml` blocking
  `shell.exec`, package installation, and POSTs to known financial hosts.
- Kernel now consults a `Constitution` on every `EvaluateProposal`. The
  receipt records every matched rule in `body.constitution_rules` and the
  signature covers the post-override decision (so rolling back a deny in
  the receipt breaks verification).
- 21 new tests across the constitution crate + kernel: 13 constitution
  unit tests, 4 solo-dev TOML integration tests, 3 kernel unit tests
  proving override behavior, 1 kernel chain integration test that signs
  an override and verifies it cold.
- Benchmark: `Constitution::evaluate` adds sub-microsecond overhead (5
  rules, no match: 0.03 µs; 1 match: 0.25 µs). End-to-end
  `Kernel::handle()` is unchanged within noise — the constitution is
  effectively free at this rule scale.

### Changed

- `Kernel::new` and `Kernel::resume` now take a third argument: a
  `Constitution` implementation. Existing callers pass `EmptyConstitution`.

- **`uniclaw-kernel` crate** — the trusted runtime core (sketch). Generic
  over `Signer` + `Clock` traits so tests inject deterministic mocks and
  production can plug HSM-backed signers without touching the kernel.
  Modules: `state` (sequence + prev_hash), `event` (`Proposal`,
  `KernelEvent::EvaluateProposal`), `outcome`, `traits` (`Signer`, `Clock`),
  `leaf` (Merkle leaf hashing), `kernel` (`Kernel::new` / `Kernel::resume` /
  `Kernel::handle`).
- 14 kernel unit tests + 3 integration tests in `tests/chain.rs` exercising
  monotonic sequence, prev_hash chaining over 32 receipts, full Ed25519
  verification of every leaf, tampering detection at body and merkle-leaf
  level, and resume-from-prior-state continuity.
- Per-call benchmark: `Kernel::handle()` runs at **33.8 µs/call (~30 000
  ops/sec)** on x86_64 — Ed25519 sign + BLAKE3 leaf hash + serde_json body
  encoding, end to end.

- **RFC-0001 — Receipt Format**, the canonical specification of the wire
  format, canonical encoding, content-addressing, verification algorithm,
  security considerations, and versioning policy.
- `uniclaw-receipt::crypto` module gated by the `crypto` feature, providing
  `sign(body, &SigningKey) -> Receipt` and `verify(&Receipt) -> Result<(), VerifyError>`.
- Typed `VerifyError` enum (`InvalidIssuerKey`, `SignatureMismatch`,
  `UnsupportedVersion { found, expected }`, `EncodingFailed`).
- Five round-trip unit tests (sign, tamper-body, tamper-signature,
  wrong-issuer, unsupported-version) inside `uniclaw-receipt`.
- Eight subprocess integration tests in `uniclaw-verify/tests/round_trip.rs`
  exercising the actual binary end-to-end. **First public receipt verified.**
- `mint-sample` cargo example showing how to programmatically mint a receipt.
- Per-package profile overrides: `ed25519-dalek`, `curve25519-dalek`, `sha2`,
  `blake3` compile at `opt-level = 3` while the rest of the workspace stays at
  `opt-level = "z"`. Verification dropped from ~3.4 ms/call to ~52 µs/call (65×
  faster) for ~17 KiB of binary growth.

### Changed

- `uniclaw-verify` binary now delegates verification to
  `uniclaw_receipt::crypto::verify`, dropping its direct `ed25519-dalek`
  dependency. Tighter trust boundary: one place where signature math lives.
- Workspace `ed25519-dalek` enables `fast` (precomputed tables) feature.

### Initial workspace setup

- Cargo workspace skeleton with `uniclaw-receipt` and `uniclaw-verify` crates.
- Receipt format types (`Receipt`, `ReceiptBody`, `Action`, `Decision`,
  `RuleRef`, `ProvenanceEdge`, `MerkleLeaf`, `Digest`, `PublicKey`,
  `Signature`).
- Engineering discipline: dual MIT/Apache-2.0 license, `rustfmt`/`clippy`/
  `taplo`/`deny` configs, ZeroClaw-pattern release profile (`opt-level = "z"`,
  `lto = "fat"`, `codegen-units = 1`), GitHub Actions CI with
  cross-platform test matrix and hard-ceilings job (TOML-only, ≤ 20 crates).

[Unreleased]: https://github.com/uniclaw/uniclaw/compare/HEAD...HEAD
