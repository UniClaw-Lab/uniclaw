# Changelog

All notable changes to Uniclaw are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Receipt-format changes are versioned independently; see `RFCS/` for receipt
format change history.

## [Unreleased]

### Added

- **`uniclaw-tools` crate** — tool execution foundation (Phase 3 step 1
  / step 13). Workspace member 13. Defines the trait surface every
  later tool-related step plugs into; ships **architecture**, not a
  runtime.
  - `Tool` trait — `name`, `manifest`, `approval_policy(&call)`, `call`.
    Sync (async runtimes wrap a sync impl in their own scheduling).
  - `ToolManifest` — name, description, action_kind prefix,
    `declared_capabilities: Vec<Capability>`, `default_approval`.
  - `Capability` enum — 7 variants (`NetConnect`, `FileRead`,
    `FileWrite`, `ShellExec`, `EnvRead`, `LlmQuery`, `SecretRead`)
    each carrying a `GlobPattern`. Adopted from OpenFang's capability
    pattern (master plan §6.2). Complements `ResourceUse`
    (quantitative) — capabilities are qualitative.
  - `GlobPattern` + own tiny matcher — `*`, `prefix*`, `*suffix`,
    `*middle*`, and combinations. ~50 LOC, no_std, single-pass,
    no backtracking pathology, no regex dep.
  - `ApprovalPolicy { Never, Discretionary, Always }` on the trait —
    adopted from IronClaw's two-phase approval pattern.
  - `ToolHost` — `BTreeMap<String, Box<dyn Tool>>` registry.
  - `ToolCall` / `ToolOutput` — both carry precomputed BLAKE3 hashes
    so the kernel doesn't re-hash.
  - `ToolError` — typed enum (NotFound / InvalidInput / Failed /
    Timeout / CapabilityDenied) with `variant_name()` and
    `message()` for receipt provenance.
  - `NoopTool` builtin — identity tool, no capabilities, default
    approval `Never`.
- **Kernel: `KernelEvent::RecordToolExecution(Box<ToolExecution>)`**.
  Mirrors the Approval flow's pattern — caller orchestrates external
  tool execution, then submits the result to the kernel as a separate
  event. Five-step authenticity gate:
  1. Prior `allowed_receipt`'s Ed25519 signature verifies under issuer.
  2. Issuer == this kernel's public key.
  3. Prior receipt's `decision == Allowed`.
  4. Prior receipt's `action.kind` starts with `"tool."`.
  5. `original_proposal.action == allowed_receipt.body.action`.

  Failures → `KernelError::RecordToolExecutionRejected(rejection)`,
  no receipt minted, chain doesn't advance.
- **Kernel: `OutcomeKind::ToolExecutedAllowed { input_hash, output_hash }`
  / `ToolExecutedFailed { input_hash }`.** Both `Copy`-compatible (full
  failure message lives in the receipt's `tool_execution_failure`
  provenance edge so `OutcomeKind` stays `Copy + Eq`).
- **Kernel: `ToolExecution` event input** — references the
  previously-`Allowed` proposal receipt + the original proposal +
  the tool's `Result<ToolOutput, ToolError>`.
- **Receipts.** Successful executions get three provenance edges:
  - `from = "receipt:<allowed_id>"`, `to = "tool:<name>"`,
    `kind = "tool_execution"`
  - `from = "receipt:<allowed_id>"`, `to = "input:<hex>"`,
    `kind = "tool_input"`
  - `from = "receipt:<allowed_id>"`, `to = "output:<hex>"`,
    `kind = "tool_output"`

  Failed executions get one edge: `kind = "tool_execution_failure"`,
  `to = "error[<variant>]: <message>"`.
- **All `uniclaw-tools` types re-exported through `uniclaw-kernel`** so
  callers don't need a direct `uniclaw-tools` dep just to construct
  `RecordToolExecution`.
- **Phase 3 sub-step breakdown** added to `docs/03-roadmap.md` (steps
  13–18: foundation → WASM runtime → capability enforcement → secret
  broker → container fallback → output sanitization). Reflects the
  refined plan after studying IronClaw / OpenFang / ZeroClaw /
  OpenClaw. Master plan §28 Phase 3 stays canonical; the sub-step
  breakdown lives in the docs tree.

### Performance (bench-results/, gitignored — release, x86_64 Linux)

- `RecordToolExecution` (success path, NoopTool, full Ed25519 verify
  + sign + 3 provenance edges): **116.20 µs/req**
- `RecordToolExecution` (failure path, 1 provenance edge): **91.53 µs/req**
- `GlobPattern.matches` (28-char candidate, `*.example.com`): **327 ns/call**
- `Capability.matches_request` (variant + glob): **118 ns/call**

Cost is dominated by Ed25519 verify of the prior receipt + Ed25519 sign
of the new one — same shape as the Approval flow. Glob matching is
trivially cheap (single-pass, no backtracking).

### Design study summary

This step was preceded by parallel analysis of four reference claws
(`IronClaw`, `OpenFang`, `OpenClaw`, `ZeroClaw`). What we adopted:

- **OpenFang** — Capability enum + glob pattern matching (most
  important architectural finding).
- **IronClaw** — two-phase approval (`requires_approval(&params)` →
  execute → `ActionRecord`), per-tool resource limits idea (lands at
  step 14 with WASM runtime). Their WIT Component Model is also the
  intended runtime for step 14, but sits behind a `WasmTool` adapter
  so the trait surface stays backend-agnostic.
- **OpenClaw** — gateway-level deny list philosophy (already
  expressible as Constitution `Deny` rules — no extra step needed).
- **ZeroClaw** — signed manifests with Ed25519 (queued for a future
  step, with default-on signature verification rather than ZeroClaw's
  default-off).

No source borrowed from any of the four claws. Citations in
`crates/uniclaw-tools/src/lib.rs` adopt-don't-copy section.

### Tests

- 34 new unit tests in `uniclaw-tools` (15 glob matcher + 5
  capability + 4 tool error + 6 host + 4 noop tool).
- 7 new integration tests in `uniclaw-kernel/tests/chain.rs`
  (full success flow with NoopTool round-trip + failure path
  provenance + 5 rejection variants of the authenticity gate, each
  driven by a real Ed25519 signer).
- Workspace test count: **188 → 229**, all passing.
- New doc per the standing rule:
  `docs/steps/13-tool-foundation.md`. Roadmap and docs index updated.

- **HTML verifier UI on `uniclaw-host`** (Phase 2 step 4 / step 12).
  Closes the verifiability wedge to **non-engineers**: an auditor pastes
  a receipt JSON into `https://your-host/verify`, clicks Verify, and
  sees ✓/✗ in milliseconds — entirely client-side, no install, no
  account, no backend round-trip.
  - New `GET /verify` route serves a static, self-contained HTML page
    (~8.5 KB) embedded at compile time via `include_str!`. No external
    scripts, no external stylesheets, no CDN dependencies.
  - Verification path mirrors `uniclaw-receipt::crypto::verify`: parse
    JSON → reconstruct canonical body bytes via
    `JSON.stringify(receipt.body)` → `crypto.subtle.importKey("raw",
    issuerBytes, {name: "Ed25519"}, ...)` → `crypto.subtle.verify(
    "Ed25519", key, sigBytes, bodyBytes)`. Browser Ed25519 support
    detected on load; warning shown otherwise.
  - Result panel shows ✓/✗, decision, action kind/target, sequence,
    issued_at, and the issuer fingerprint (first 4 bytes hex).
  - **Trust model unchanged**: server does not verify, never claims
    `verified: true`. The page IS the verifier — auditor can save it
    locally (Ctrl+S) and run offline forever.
  - `Cache-Control: no-store` on `/verify` so JS updates propagate;
    `/receipts/<hash>` keeps `immutable, max-age=31536000` (unchanged).
  - `GET /` index updated to surface the verifier prominently.

### Performance (bench-results/, gitignored — release, in-process via tower::oneshot)

- `GET /verify` (8576-byte HTML page): **4.98 µs/request**
- `GET /` (smaller index, comparison): 5.47 µs/request

Handler cost is invisible behind any network RTT. Browser-side Ed25519
verification of a single receipt is ≤ 1 ms on commodity hardware.

### Notes

- 4 new tests in `uniclaw-host` (verifier page served + content-type +
  no-store cache + UI strings present including
  `crypto.subtle.verify("Ed25519"` + index links to `/verify` + CORS
  preserved). Workspace test count: 184 → 188.
- **Smoke test** validated the canonical-body reconstruction: a
  Rust-signed receipt JSON, parsed and re-stringified through the
  exact JS logic the page uses, verified successfully under Node 22's
  `crypto.subtle` — same API browsers ship. Confirms the
  `JSON.parse → JSON.stringify` round-trip preserves the kernel's
  signed bytes byte-for-byte (relies on ES2015+ insertion-order
  semantics, which all targeted browsers honor).
- Adopt-don't-copy: client-side verifier-as-static-page is net-new in
  this shape. Browser-native `crypto.subtle.verify("Ed25519", ...)`
  has been available in Chrome 113+, Firefox 130+, Safari 17+, and
  Node 20+ — no JS crypto library needed. Cited in
  `crates/uniclaw-host/src/verify.html`.
- New doc per the standing rule:
  `docs/steps/12-html-verifier.md`. Roadmap and index updated.

### Deliberately deferred (will land later if needed)

- **Drag-and-drop file upload** — paste-only for v0.
- **Bulk verification** — one receipt at a time.
- **Public-key allowlist** — auditor reads the issuer fingerprint and
  externally checks it matches the expected key.
- **Content-Security-Policy header** — small follow-up.
- **TLS termination** — run behind a reverse proxy.

- **Deep Sleep integrity walk** (master plan §16.3.3, ships as Phase 2
  step 3). The second sleep stage. Symmetric to Light Sleep but for
  read-only integrity checks instead of mutating cleanup.
  - `uniclaw-sleep` gains a `Walkable` trait, `WalkReport` (+ `EMPTY`),
    `WalkError`, `WalkerPass`, `DeepSleepReport`, and the
    `run_deep_sleep` orchestrator. Best-effort: a failing walker is
    recorded, not propagated.
  - Built-in `ReceiptLogWalker<'_, L: ReceiptLog>` wraps any
    `ReceiptLog` and runs `verify_chain()` as its walk.
  - **Kernel** gains `KernelEvent::RunDeepSleep(Box<DeepSleepReport>)`
    + `KernelEvent::run_deep_sleep(report)` ctor +
    `OutcomeKind::DeepSleepCompleted { failed_walkers }`. Mints a
    receipt with `action.kind = "$kernel/sleep/deep"`,
    `action.target = "walkers=N items=M bytes=B failed=F"`, and one
    provenance edge per walker (`deep_sleep_pass` for OK,
    `deep_sleep_failure` with the message in `to` for Err).
  - Sleep types are re-exported through `uniclaw-kernel` so callers
    don't need a direct `uniclaw-sleep` dep.
  - **2 of 3 sleep stages now ship.** REM Sleep waits until Phase 4
    (provenance graph + memory subsystems).
- 11 new tests (4 in `uniclaw-sleep` unit + 4 in `uniclaw-kernel`
  unit + 2 integration with real Ed25519 + ReceiptLogWalker over a
  signed log + 1 baseline). Workspace test count: 173 → 184.
- New doc per the standing rule:
  `docs/steps/11-deep-sleep.md`. Roadmap and docs index updated.

### Performance (bench-results/, gitignored — release, x86_64 Linux)

`run_deep_sleep` over a single `ReceiptLogWalker`:

| Chain length | Per-pass | Per-receipt |
|---|---|---|
| 100   | 5.0 ms | 50.1 µs |
| 1,000 | 54.1 ms | 54.1 µs |
| 10,000 | 530 ms | 53.0 µs |

Linear in chain length; per-receipt cost is dominated by Ed25519 verify
(~52 µs warm). A million-receipt chain takes ~52 seconds — comfortable
for weekly Deep Sleep.

### Notes

- Adopt-don't-copy: integrity-walk-as-receipt is net-new — no other
  claw runtime has a sleep-stage architecture, let alone one that
  mints signed audit receipts for the walks themselves. Cited in
  `uniclaw-sleep/src/lib.rs` (Postgres autovacuum / SQLite VACUUM are
  conceptual references for cleanup-style passes; integrity walks are
  ours).
- **`Walkable::walk` takes `&self`**, not `&mut self`, by design:
  integrity walks are read-only. Conflating walkers with cleaners
  would let a "walker" silently rewrite the chain it was supposed to
  audit — security smell avoided.

- **`uniclaw-store-sqlite` crate** — SQLite-backed `ReceiptLog` impl
  (master plan §16.1 *Audit*, follow-up to step 7, ships as Phase 2
  step 2 / "G2"). Workspace member 12. **Persistence**: receipts
  survive process restarts; the public-URL host (step 9) becomes a
  real service rather than a demo.
  - `SqliteReceiptLog::open(path, issuer)` — opens or creates a WAL-mode
    database, validates the schema/format/issuer pin, caches `len` and
    `last_leaf_hash` in memory for hot-path append validation.
  - `SqliteReceiptLog::open_in_memory(issuer)` — for tests.
  - `SqliteReceiptLog::peek_issuer(path)` — read just the pinned issuer
    without committing to opening; used by the `uniclaw-host` binary to
    decide whether a fresh DB needs `UNICLAW_HOST_ISSUER` or an
    existing DB pins it already.
  - Same five-step append validation as `InMemoryReceiptLog`. Same
    `verify_chain` semantics. Same issuer pin. Refused appends do not
    mutate state.
  - On-disk schema (version 1): `meta(key TEXT PRIMARY KEY, value BLOB)`
    + `receipts(sequence INTEGER PRIMARY KEY, content_id BLOB UNIQUE,
    issuer BLOB, body_json BLOB)`. Receipts are stored as canonical JSON
    blobs — bit-perfect for cold verification.
  - `OpenError`: `Sqlite` / `Decode` / `IssuerMismatch` /
    `UnsupportedSchema` / `UnsupportedFormatVersion`.
- **`uniclaw-host` binary: `--db <path>` flag.** Switches the host to
  the SQLite backend. The two backends (`--db` for SQLite, default
  `--receipts-dir` for in-memory JSON load) are mutually exclusive.
  Fresh DB requires `UNICLAW_HOST_ISSUER=<64-char-hex>` to pin the
  issuer; subsequent runs read it from the database.

### Changed

- **`ReceiptLog` trait — breaking change.** `last`, `get_by_sequence`,
  and `get_by_id` now return `Option<Receipt>` (owned) instead of
  `Option<&Receipt>`. SQLite-backed impls cannot return a borrow — the
  row arrives as a JSON blob and the receipt is materialized fresh. The
  in-memory impl just adds an inline `.cloned()` (~1 µs cost). The
  `uniclaw-host` caller already cloned, so no behavior change there.

### Performance (bench-results/, gitignored — release, x86_64 Linux, 1000-receipt log)

|                          | InMemory  | SQLite     |
|--------------------------|-----------|------------|
| `append`                 | 85.19 µs  | 369.85 µs  |
| `verify_chain` (per row) | 66.73 µs  | 62.48 µs   |
| `get_by_id`              | 0.37 µs   | 12.35 µs   |

The ~4× append slowdown is the WAL fsync; still 2,700 appends/sec.
`verify_chain` is essentially unchanged — both backends are bottlenecked
on Ed25519. `get_by_id` is 33× slower for SQLite, but 12 µs is invisible
behind a network round-trip.

### Notes

- Adopt-don't-copy: `OpenFang`'s `audit.rs` writes Merkle-hashed audit
  rows to a `SQLite` table inside its kernel; we keep storage
  out-of-kernel and validate at the trait boundary. No source borrowed.
  Cited in `uniclaw-store-sqlite/src/lib.rs`.
- 12 new tests in `uniclaw-store-sqlite` (8 trait conformance + 4
  persistence-specific: reopen preserves state, wrong issuer rejected,
  duplicate id, post-facto tampering caught by `verify_chain`).
  Workspace test count: 161 → 173.
- `rusqlite` and `libsqlite3-sys` get `opt-level = 3` profile overrides
  to keep query throughput in the same ballpark as the in-memory log.
- New doc per the standing rule:
  `docs/steps/10-sqlite-receipt-store.md`. Roadmap and docs index
  updated.

- **`uniclaw-host` crate** — public-URL receipt hosting (master plan §21
  #1, §28 Phase 2 step 1, "G1"). Workspace member 11. **First Phase 2
  step**; first crate to depend on `std` (the trusted core remains
  no_std-friendly).
  - `pub fn router<L>(log: Arc<RwLock<L>>) -> axum::Router` — generic
    over any `ReceiptLog + Send + Sync + 'static`. SQLite-backed log
    will plug in without changes.
  - `GET /receipts/:hash_hex` — returns the canonical receipt JSON or
    404. Successful fetches ship `Cache-Control: public,
    max-age=31536000, immutable` and a strong `ETag` derived from the
    hash. Honors `If-None-Match` for 304s.
  - `GET /healthz` — `{"ok": true, "count": <log_len>}`, `Cache-Control:
    no-store`.
  - `GET /` — minimal HTML index pointing at the project's GitHub.
  - CORS permissive on every route — receipts are *meant* to be
    verifiable from any origin.
  - **Trust model:** the server does not re-verify receipts on serving.
    Verification stays the client's job; that's the whole point of cold
    verification. The receipt log already validates signatures at append
    time (Phase 1 step 7).
  - Bundled `uniclaw-host` binary loads `*.json` receipts from a
    directory and serves them. Pins the log to the issuer of the first
    loaded receipt and validates the chain on load.
- **`Digest::to_hex` / `Digest::from_hex` on `uniclaw-receipt`** —
  public, allocator-only hex helpers, plus `HexDecodeError` for parse
  failures. Used by the `/receipts/<hex>` URL parser; cleaner than
  rolling private helpers in the host crate.
- **Stack additions (workspace deps):** `axum 0.7`, `tokio 1`,
  `tower 0.5`, `tower-http 0.6` (cors only). All scoped to
  `uniclaw-host`; the rest of the workspace is unaffected.
- 10 new tests (4 hex helpers in `uniclaw-receipt` + 7 host integration
  tests via `tower::ServiceExt::oneshot` with real Ed25519 receipts).
  Workspace test count: 151 → 161.
- New doc per the standing rule: `docs/steps/09-public-url-hosting.md`.
  Roadmap and docs index updated to reflect Phase 2 in progress.

### Performance (bench-results/, gitignored — release, in-process via tower::oneshot)

- `GET /receipts/<known>` (200, 100-entry log): **11.30 µs**
- `GET /receipts/<unknown>` (404): **5.07 µs**
- `GET /receipts/<known>` + matching If-None-Match (304): **7.94 µs**
- `GET /healthz` (1000-entry log): **3.84 µs**
- `GET /receipts/not-a-hash` (400): **4.03 µs**

Handler cost is well below typical network round-trip; the wire is the
bottleneck, not the handler.

### Notes

- Adopt-don't-copy: public, content-addressed, signed-receipt hosting
  in this shape is net-new — none of the nine reference claw runtimes
  ship signed receipts. HTTP shape follows ordinary REST + RFC 7234/9110
  cache conventions. Cited in `uniclaw-host/src/lib.rs`.
- TLS, rate limiting, persistent storage, and an HTML verifier UI are
  **deliberately deferred**. Run behind a reverse proxy for TLS; SQLite
  log lands as a follow-up step; rate limiting will land as a `tower`
  layer when there's a deployment that needs it.

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
