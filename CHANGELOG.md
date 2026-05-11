# Changelog

All notable changes to Uniclaw are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Receipt-format changes are versioned independently; see `RFCS/` for receipt
format change history.

## [Unreleased]

### Added

- **HTTP proposal API on `uniclaw-host`** (Phase 3.5 / step 21)
  — opt-in proposal/approval surface that mounts at `/v1` when the
  binary is started with `--constitution <path>`. Ships the
  **threshold-3 lever** from the deep-strategy memory: any language
  that speaks HTTP can now produce verifiable Uniclaw receipts via
  the local-sidecar integration pattern from the war analysis — no
  Rust toolchain, no kernel embedding required. Pairs with
  `@uniclaw/verifier` (step 20a) to give every non-Rust claw both
  the production path (sidecar mints) and the consumption path
  (TS verifier validates).
  - **Endpoints (this PR):**
    - `POST /v1/proposals` — submit `{action: {kind, target, input_hash}}`,
      receive `{decision, content_id, receipt_url, issuer, sequence,
      schema_version}`. Mints an `evaluate_proposal` receipt
      through the kernel's Constitution + Budget pipeline.
    - `POST /v1/approvals/{content_id}/resolve` — submit
      `{principal, outcome}`, receive a resolution receipt linked
      to the pending one via the kernel's `ResolveApproval` flow.
      Re-runs every authenticity gate (signature verify, issuer
      match, decision-is-Pending, action match).
    - Read-only routes (`/receipts/<hash>`, `/verify`, `/healthz`,
      `/`) are unchanged.
  - **`crates/uniclaw-host/src/api.rs`** (~370 LOC) — `ApiState`
    (concrete `Kernel<Ed25519Signer, SystemClock, InMemoryConstitution>`
    + shared `Arc<RwLock<InMemoryReceiptLog>>` with the read-only
    routes), `api_router()`, handlers, `ApiError → IntoResponse`
    mapping (400/404/409/500).
  - **`crates/uniclaw-host/src/signer.rs`** — reusable
    `Ed25519Signer` wrapper around `ed25519_dalek::SigningKey`
    implementing the kernel's `Signer` trait. Extracted from the
    end-to-end demo so future binaries don't redefine it.
  - **`crates/uniclaw-host/src/clock.rs`** — `SystemClock`
    (production wall-clock) + `StubClock` (deterministic, tests),
    both emitting RFC 3339 UTC seconds (`YYYY-MM-DDTHH:MM:SSZ`)
    via an inline `civil_from_days` formatter (Howard Hinnant's
    public-domain algorithm; no external date dependency).
  - **`bin/uniclaw-host.rs`** gains `--constitution <path>`,
    `--signer-seed-hex <64-hex>`. Presence of `--constitution`
    enables proposal mode; absence preserves the prior step-9
    read-only behavior. A startup `WARN` flags that `/v1` is
    unauthenticated.
  - **`uniclaw-kernel` / `uniclaw-constitution` / `uniclaw-approval`
    / `ed25519-dalek` move from dev-deps to regular deps** in
    `uniclaw-host`. The end-to-end demo's remaining dev-deps
    (`uniclaw-tools` / `uniclaw-tools-http` / `uniclaw-secrets` /
    `uniclaw-redact` / `base64`) stay dev-only.
  - **Concurrency:** `kernel: std::sync::Mutex<...>` (short, sync
    critical section; no `.await` inside) + `log:
    Arc<tokio::sync::RwLock<...>>` (shared with read-only routes,
    async multi-reader). Lock order: kernel → log; never the
    reverse.
  - **Tests:** 11 new integration tests in
    `crates/uniclaw-host/tests/api.rs` covering happy paths
    (allowed / denied / pending → approved / pending → denied),
    error paths (malformed JSON / bad hex / unknown content_id /
    resolving an Allowed receipt → 409), and chain linkage
    (sequence increments + `prev_hash` links across three
    sequential proposals). 5 new clock unit tests pin RFC 3339
    output for epoch / 2000-01-01 / 2026-05-09 / 2099-12-31 /
    1969-12-31 plus assert `SystemClock` emits 20-char
    well-formed strings.
  - **End-to-end cross-language smoke against the live binary.**
    Ran `target/release/uniclaw-host --constitution ... --signer-seed-hex
    2a*32 --bind 127.0.0.1:0`, submitted Allowed / Pending /
    Approved / Denied via curl, then verified each receipt URL via
    `node bin/verify-cli.mjs`. 4 of 4 verify; tamper test (flip
    `decision` via curl + jq) correctly rejected with `signature
    did not verify under the embedded issuer key`. The 4 status
    code paths (200/400/404/409) all return the expected `{"error",
    "detail"}` shape.
  - **Bench (gitignored at `bench-results/21-http-proposal-api.txt`):**
    `POST /v1/proposals` over HTTP keepalive (Python urllib, N=500
    sequential): **4.218 ms/req**. curl-per-request (N=100,
    fresh TCP each time): 29.96 ms/req — dominated by curl
    process startup. Baseline for direct `Kernel::handle` is
    ~45 µs (step 19); the HTTP API adds ~4.17 ms overhead, well
    within "human time" for any realistic agent action. Local-
    sidecar latency is not a concern.
  - **What this step does NOT ship:** tool-execution / secret-use /
    redaction endpoints (each carries security-sensitive payloads
    needing a dedicated design pass); authentication (the
    `principal` field is accepted in the wire format for forward-
    compatibility but not yet recorded — Phase-6 identity-bound
    approvals); persistent storage in proposal mode (restart resets
    the chain; SQLite proposal mode is a future-step);
    chain-checkpoint endpoint (queued as step 19c); first-party
    client SDK in TS/Python/Go (the endpoints are simple enough
    that any HTTP client works).

- **TypeScript verifier npm package — `@uniclaw/verifier`**
  (Phase 3.5 / step 20a) — first non-Rust verifier in the repo,
  shipping at `packages/verifier-ts/`. Workspace stays at 17 of
  20 Rust crates (the npm package doesn't count toward the cap).
  Per the war analysis: *"if verification is not universal,
  Uniclaw stays a Rust project. If verification is universal,
  Uniclaw becomes a protocol."* This PR makes verification
  programmatically universal — closes **success threshold 1
  (portability)** from the deep-strategy memory: a TypeScript
  developer can `npm install` a verifier and validate a
  Uniclaw receipt minted on a Rust kernel, with bytes matching,
  on any platform that runs Node 20+ or a modern browser.
  - **Package surface (~250 LOC across 6 modules):**
    - `canonicalizeBody(body)` / `canonicalizeJcs(value)` — RFC
      8785 JCS canonicalizer + the v1 fallback path
      (`JSON.stringify` over a parse-order-preserved body).
    - `computeContentIdHex(body)` / `computeContentIdBytes(body)`
      — BLAKE3 over the canonical bytes, via `@noble/hashes`.
    - `verifyReceipt(receipt)` / `verifyReceiptJson(json)`
      / `verifyReceiptUrl(url)` — Ed25519 check against the
      receipt's embedded issuer key via `@noble/curves`. Returns
      a plain `VerifyResult` object; only catastrophic input
      throws.
    - TypeScript types for `Receipt`, `ReceiptBody`,
      `ReceiptAction`, `RuleRef`, `ProvenanceEdge`,
      `MerkleLeaf`, `VerifyResult`. Each shape uses an index
      signature so forward-compatible schema fields don't fail
      typecheck.
    - ESM-only, Node 20+ floor. Browser-compatible (no
      Node-only APIs in the verify path). Two production
      dependencies — both audited Paul-Miller libraries with
      no native modules and no postinstall scripts.
  - **Tiny CLI** (`bin/verify-cli.mjs`) registered as
    `uniclaw-verify-ts`. Accepts a URL or a local JSON file
    path; exit code 0 on verified, 1 on failure, 2 on bad input.
    Pairs with the step-20 demo:
    `npx uniclaw-verify-ts http://127.0.0.1:PORT/receipts/HASH`
    → `✓ verified | issuer=197f6b23... decision=allowed schema_v=2 content_id=a957e6e6...`.
  - **34 tests pass** across 3 files
    (`canonical.test.ts` + `conformance.test.ts` + `verify.test.ts`):
    - 10 JCS primitive/string/container unit tests.
    - **10 cross-language conformance assertions** that load
      the SAME `crates/uniclaw-receipt/tests/vectors/canonical-v2.json`
      fixture the Rust snapshot test loads. All 5 vectors
      produce byte-identical canonical output and byte-identical
      BLAKE3 content_ids in the TS port. Same fixture is the
      single source of truth across all three implementations
      (Rust canonicalizer, browser verifier JS port,
      `@uniclaw/verifier`).
    - 13 sign+verify roundtrip + tamper-detection tests using
      the demo's deterministic key seed (`[42u8; 32]`).
  - **End-to-end smoke against the live demo:** ran
    `cargo run --release --example end-to-end-demo -p uniclaw-host`,
    fetched each of the 6 published receipts via
    `verifyReceiptUrl`. **6 of 6 verify**; the recomputed
    `content_id` byte-matches the URL hash for every receipt;
    tamper test (flip `decision` field via curl + jq) correctly
    rejected with `signature did not verify under the embedded
    issuer key`.
  - **Conformance test path** is the lockstep mechanism between
    `crates/uniclaw-receipt/src/canonical.rs`,
    `crates/uniclaw-host/src/verify.html`, and
    `packages/verifier-ts/`. Any change to one canonicalizer
    that alters bytes for the same logical body fails in
    Rust's snapshot test AND in vitest. Comment added to
    `verify.html` pointing future contributors to the npm
    package as the canonical TypeScript reference.
  - **Tooling additions:** `package.json` with
    `npm run typecheck` / `npm run test` / `npm run build`;
    `tsconfig.json` (strict + `noUncheckedIndexedAccess` +
    `exactOptionalPropertyTypes` + `verbatimModuleSyntax`);
    `vitest.config.ts`. Top-level `.gitignore` excludes
    `**/node_modules/`, `packages/*/dist/`, build artifacts.
  - **What this step does NOT ship:** `npm publish` (operations
    task — credentials and release process belong to a separate
    PR); a bundled `verify.html` that imports from this package
    (keeping `verify.html` self-contained is a feature);
    verifiers in Go / Python / Swift (queued as 19c — each
    will conform to the same `canonical-v2.json` fixture); CI
    integration of the conformance suite.
  - **Performance:** not measured as a headline number — the
    verifier is dominated by network for `verifyReceiptUrl`
    and by Ed25519 for the verify itself (~50 ms cold via
    `@noble/curves`). Whole vitest suite finishes in ~3.4 s.
    Built `dist/` is ~12 KB of source; transitive install
    including `@noble/*` is ~250 KB. No bench file — not a
    perf-sensitive component.

- **End-to-end demo** (Phase 3.5 / step 20)
  — one runnable artifact that wires Phase 3's complete stack
  (kernel + constitution + budget + approval + HTTP fetch tool +
  secret broker + redactor + canonical receipts) into one
  command. `cargo run --release --example end-to-end-demo -p uniclaw-host`
  walks 5 representative actions, prints 6 verifiable receipt
  URLs, and spins up `uniclaw-host` serving every receipt at
  `/receipts/<hash>` plus the browser verifier at `/verify`.
  Closes **success threshold 2 (visibility)** from the deep-
  strategy memory: a third party can run the demo, paste any
  printed URL into `/verify`, and watch the trust property work
  cold — no Uniclaw install required for the verifier, since
  the JS port of JCS + `crypto.subtle.verify` runs in the
  browser. Per the war analysis: *"the demo should be brutally
  concrete: agent proposes risky action → constitution requires
  approval → user approves → tool executes → secret used through
  broker without exposing raw material → output redacted →
  receipt chain published → third party verifies it from another
  machine."* All seven steps in one binary.
  - **`crates/uniclaw-host/examples/end-to-end-demo.rs`** (~580
    LOC, intentional single-function `main` with `#[allow(clippy::too_many_lines)]`
    — the storyline is the value, not the modularity). Five
    actions:
    1. **Allowed** — `http.fetch /data` against the built-in
       mock server → signed `Allowed` receipt.
    2. **Pending → Approved** — `http.fetch /admin/keys`
       → constitution's `admin-requires-approval` rule fires
       → `Pending` receipt → auto-approval with synthetic
       `demo-operator` principal → `Approved` receipt linked
       via `prev_hash` to the Pending.
    3. **Denied** — `shell.exec rm -rf /` → constitution's
       `deny-shell` rule → signed `Denied` receipt.
    4. **`secret_used` provenance edge** — `tool.http_fetch`
       with `BearerHeader { secret_ref: "github.token" }`
       against `/api/me`. The broker injects the bearer at
       call time; the kernel mints one `secret_used` edge
       per consumed reference (name only — never the value).
    5. **`redaction_applied` provenance edge** — `tool.http_fetch`
       against `/api/dump` returns a body containing `ghp_demo...`.
       The redactor decodes the base64-encoded body, scans,
       redacts, re-encodes, and the kernel mints one
       `redaction_applied` edge plus populates
       `redactor_stack_hash` (was a placeholder field since
       step 18). The receipt's `output_hash` is the post-
       redaction form.
  - **Built-in mock HTTP server** (~50 LOC inside the example)
    — a detached `std::thread` listening on `127.0.0.1:0` (OS
    picks a free port). Routes: `/data`, `/admin/keys`,
    `/api/me` (echoes request headers including the broker-
    injected `Authorization`), `/api/dump` (returns the leak-
    shaped body for the redaction step). Stop-flag for graceful
    shutdown. No real network calls; no flakiness from external
    services. Pattern matches `crates/uniclaw-tools-http/tests/integration.rs`
    (which we wrote ourselves — see step 14).
  - **Deterministic Ed25519 signing key** (`SigningKey::from_bytes(&[42u8; 32])`)
    so the demo's issuer public key is stable across runs.
    Production uses HSM-backed signers; the demo uses a fixed
    test key.
  - **`HttpFetchConfig::for_test_localhost()`** disables the
    SSRF gate — production refuses literal-IP private/loopback
    by default; the demo's mock server lives on `127.0.0.1`,
    so the test config is required. Documented as test-only.
  - **Graceful shutdown** via `tokio::signal::ctrl_c()` + axum's
    `with_graceful_shutdown`. Demo prints 6 URLs, then waits
    for Ctrl+C.
  - **Step doc** at `docs/steps/20-end-to-end-demo.md` — what
    the step proves, where it fits, how it works in plain
    words, design choices, what it doesn't ship, performance/
    size, and the threshold-2 closure.
  - **`uniclaw-host` Cargo.toml** dev-deps: `uniclaw-kernel`,
    `uniclaw-constitution`, `uniclaw-approval`, `uniclaw-store`,
    `uniclaw-tools`, `uniclaw-tools-http`, `uniclaw-secrets`,
    `uniclaw-redact`, `base64`. Dev-only because the host crate
    itself doesn't depend on these in production. New `[[example]]`
    entry pins the example path.
  - **No new crate** — workspace stays at 17 of 20 crates.
  - **Cold start:** ~37 s release build (one-time per machine);
    after that, the example binary starts in ~50 ms. Each demo
    run produces 6 receipts in <100 ms before the host comes
    up. Demo binary size: ~6 MB stripped (links wasmtime + tokio
    + axum + ureq + everything else; this is the price of
    "exercises all of Phase 3"). No bench file — it's a demo,
    not a perf-sensitive component.

- **Receipt Canonicalization (RFC 8785 JCS)** (Phase 3.5 / step 19)
  — receipts at `schema_version >= 2` now use a deterministic-
  across-languages canonical JSON encoding. The browser verifier
  produces byte-identical output to the Rust canonicalizer for
  every reference vector (5 of 5 pass via the Node smoke test).
  This is the foundation for cross-language verifier
  interoperability — per the war analysis (`UNICLAW_CLAW_WAR_ANALYSIS.md`),
  the highest-leverage work: *"if verification is not universal,
  Uniclaw stays a Rust project. If verification is universal,
  Uniclaw becomes a protocol."* The receipt is now portable.
  - **`uniclaw-receipt::canonical` module** — RFC 8785 JCS
    implementation (~100 LOC). Goes through
    `serde_json::to_value` for the intermediate Value tree,
    walks emitting canonical bytes:
    - Object keys sorted by UTF-16 code unit order.
    - Integers as decimal (no leading zeros, no `+`, no
      exponent). Floats panic — Uniclaw's schema has no
      floats; the panic is a load-bearing assertion against
      future drift.
    - Standard string escapes (`"` → `\"`, `\\` → `\\\\`,
      controls → `\uXXXX` lowercase, `\b\f\n\r\t` named).
      Slash `/` is **not** escaped.
    - No whitespace.
    16 unit tests covering ordering, escapes, integer
    formatting, RFC 8785 Appendix-B-style worked example,
    determinism across construction orders.
  - **`RECEIPT_FORMAT_VERSION` bumped 1 → 2.** New receipts
    minted by the kernel record `schema_version: 2` and use
    JCS. Pre-step-19 receipts (`schema_version: 1`) continue
    to verify under the legacy `serde_json` encoding via
    schema-version dispatch in `Receipt::content_id` /
    `crypto::sign` / `crypto::verify`. Backwards-compatible:
    every existing receipt verifies; new receipts verify in
    any JCS-conformant implementation.
  - **5 test vectors at `crates/uniclaw-receipt/tests/vectors/canonical-v2.json`**
    — minimal-allowed, denied-with-rule, with-provenance-edges,
    with-redactor-stack-hash, pending-approval. Each fixture
    pins `canonical_hex` (the canonical bytes) + `blake3_hex`
    (the content_id). The Rust snapshot test
    (`vectors_match_expected_canonical_and_hash`) fails any
    change to `canonical.rs` that alters byte-level output
    for the same logical body.
  - **Browser verifier (`crates/uniclaw-host/src/verify.html`)**
    updated with a JS port of the canonicalizer (~30 LOC).
    Dispatches on `body.schema_version`: v1 receipts use the
    pre-step-19 `JSON.stringify` path, v2 receipts use the JCS
    JS port. Same algorithm; same output.
  - **Node.js cross-language conformance smoke**
    (`crates/uniclaw-receipt/tests/vectors/conformance-smoke.mjs`).
    Loads `canonical-v2.json` and re-canonicalizes every body
    with a JS JCS implementation matching the one in
    `verify.html`. **5 of 5 vectors pass** — byte-identical
    output to Rust. Run manually:
    `node crates/uniclaw-receipt/tests/vectors/conformance-smoke.mjs`.
    Future-step CI integration could wire this into a Node
    setup.
  - **RFC-0001 updated** to `Schema version: 2` with a new
    section 0 documenting the canonicalization rules + pointing
    to the conformance fixture as the cross-language contract.
  - **Bench** (gitignored at
    `bench-results/18-receipt-canonicalization.txt`):
    `canonical::to_vec` ~36 µs/receipt (22.5 MiB/s) vs
    `serde_json::to_vec` ~5.3 µs (151.4 MiB/s). JCS overhead
    +30 µs/receipt (+572%). Full content_id (JCS + BLAKE3)
    ~26 µs. Acceptable for any realistic receipt volume —
    at 100/sec it's 0.36% of CPU. A direct serde Serializer
    (no Value-tree round-trip) is the future-step optimisation
    if volume ever justifies it; not on the v0 critical path.
  - **Adopt-don't-copy citation**: RFC 8785 (Cyberphone). The
    algorithm is small enough we wrote our own implementation
    (~100 LOC) rather than pull a transitive crate; the
    canonicalization correctness is load-bearing for the
    entire receipt format.
  - **Step doc** —
    [`docs/steps/19-receipt-canonicalization.md`](docs/steps/19-receipt-canonicalization.md).
  - **Phase 3.5 declared** for receipt-format hardening
    (between Phase 3 and Phase 4). Follow-ups: `key_id`
    field for key rotation, witness signatures + chain
    checkpoint receipts, multi-language verifiers (Go,
    Python, Swift).
- **Output Sanitization / Redaction Proofs** (Phase 3 step 5 /
  step 18) — pattern-based redaction over tool outputs with
  audit-grade receipts. The kernel's audit chain now commits
  to the post-redaction form of every tool output (when
  redaction was applied), records *which* rules fired with
  structural provenance edges, and pins *which* redactor stack
  ran via the long-placeholder `redactor_stack_hash` field.
  **Phase 3's wedge is complete**: capability + SSRF + secrets
  + WASM (core / Component / with-host) + redaction +
  verifiable receipts for every action.
  Reordered before step 17 (container fallback) because
  output sanitization produces a new audit primitive that
  maps directly to the war-analysis "redaction receipts"
  claim, while step 17 adds dep weight on a non-strategic axis.
  - **New `uniclaw-redact` crate** (workspace member 17).
    - `Redactor` trait + `RedactionResult` (redacted bytes
      for the caller + report for the kernel) + `id()` for
      stable identification in audit edges.
    - `PatternRedactor` regex-based reference impl. Compiles
      a list of `PatternRule { id, regex, replacement }` at
      construction; each match becomes a `[REDACTED:<rule>]`
      placeholder. `with_defaults(id)` ships a default-rule
      corpus covering the common credential prefixes:
      GitHub PATs/OAuth/server/u2s/refresh, OpenAI / Anthropic
      keys (`sk-…`, `sk-ant-…`), Slack tokens (`xoxb-…`,
      `xoxp-…`, `xoxa-…`, `xoxr-…`), AWS access keys (`AKIA…`),
      JWT shapes (`eyJ…`), generic `Authorization: Bearer …`
      header echoes. 13 rules total. Operators are expected
      to **extend, not replace** — the defaults are
      defense-in-depth.
    - `RedactorStack` for composition. Each redactor sees the
      previous one's output. `stack_hash()` produces
      `BLAKE3(stack_id + "\n" + redactor_id_1 + "\n" + …)`
      committing to the ordered list of redactor IDs.
    - 16 unit tests (default-rules-compile sanity,
      pass-through clean input, replace and count, multiple
      matches per rule, only-matching-rules-recorded,
      rule-id-prefixed-with-redactor-id, lossy decode of
      non-UTF-8 input, stack hash stability + variance, stack
      composition, stack_hash uses redactor IDs not pointer
      identity, stack `redact()` returns matching `stack_hash`).
  - **`uniclaw-receipt` audit-data types**: `RedactionReport
    { redacted_output_hash, matches: Vec<RuleMatch>, stack_hash }`
    and `RuleMatch { rule_id, count }`. `no_std`-compatible
    so the kernel can read them. The trait + impls live in
    `uniclaw-redact` (`std`); the kernel-side audit data lives
    in `uniclaw-receipt` (`no_std`). Same split as
    `ToolMetadata`.
  - **Kernel integration**: `ToolExecution.redaction:
    Option<RedactionReport>` field. When present, the kernel:
    - Uses `redaction.redacted_output_hash` as the receipt's
      `output_hash` (committing to the post-redaction form,
      not the original `output.output_hash`).
    - Mints one `redaction_applied` provenance edge per
      `RuleMatch` with `count > 0`. Edge format:
      `from = receipt:<id>, to = redaction:<rule_id>:count=<n>,
      kind = redaction_applied`.
    - Populates `ReceiptBody::redactor_stack_hash` with
      `redaction.stack_hash` (the field has been a placeholder
      in the receipt schema since RFC-0001; step 18 finally
      gives it a real producer).
    - When `redaction = None`, the kernel's behaviour is
      EXACTLY as before. Backwards-compatible — every existing
      `RecordToolExecution` flow continues to work without
      changes.
    Internal `Kernel::mint` helper now takes a 7th argument
    (`Option<Digest>` for `redactor_stack_hash`); all 5
    callers updated.
  - 4 new kernel integration tests:
    `tool_execution_with_redaction_uses_redacted_hash_and_emits_applied_edges`,
    `tool_execution_without_redaction_leaves_redactor_stack_hash_none_unchanged`,
    `tool_execution_with_zero_count_redaction_matches_emits_no_edges`,
    `tool_execution_with_redaction_signature_breaks_when_field_tampered`.
    All 25 pre-step-18 kernel tests still pass unchanged.
    Workspace 345 → 365.
  - **Workspace deps added**: `regex = "1.10"` (full features
    — `\b` / `\d` / `\w` need `unicode-perl`). ~2 MB source
    contribution; <100 KB binary at release.
  - **Bench** (gitignored at
    `bench-results/17-output-sanitization.txt`):
    `PatternRedactor::with_defaults` ~500 MiB/s sustained
    throughput on 64 KiB+ payloads (~25 µs for 1 KiB, ~116 µs
    for 64 KiB, ~2.4 ms for 1 MiB). Clean-input fast path
    (no matches) ~2× faster. Fast enough that kernel-side
    redaction is not a hot-path bottleneck.
  - **Adopt-don't-copy citations**: `IronClaw`'s
    `crates/ironclaw_safety/` redaction discipline (the
    *philosophy* of "scan output for known secret patterns,
    redact, sign the result before the audit chain commits"
    is adopted; their pattern corpus informed our
    default-rule list; their richer features —
    structured-leak detection, PII redaction, output
    sanitisation across logging stacks — are on the
    future-step list).
  - **Step doc** —
    [`docs/steps/18-output-sanitization.md`](docs/steps/18-output-sanitization.md).
- **WASM Host Imports** (Phase 3 step 4c / step 16c) — the
  capability-mediated host functions a WASM Component can import.
  The substrate swap is now complete: WASM tools can fetch HTTP,
  check secret existence, log, and read the clock through the
  *same* machinery native tools use, with the *same* receipt-
  format guarantees the kernel mints for native tools.
  - Extended `crates/uniclaw-tools-wasm/wit/tool.wit` with a
    new `host` interface containing four functions:
    - `log-message(level, message)` — structured logging,
      rate-limited host-side (1000 entries / 4 KiB per message;
      cap-busting calls become no-ops).
    - `now-millis()` — Unix epoch milliseconds.
    - `secret-exists(name) -> bool` — broker-backed existence
      check. **Returns the boolean only; never the value.**
    - `http-fetch(url, auth, timeout-ms) -> result<http-response,
      string>` — capability-mediated HTTP. The host delegates to
      the operator-supplied `HttpFetchTool` instance — *same*
      capability allowlist, *same* SSRF gate, *same* broker-
      backed Authorization injection. Whatever HttpFetchTool
      enforces, the guest gets, automatically.
  - New world `tool-with-host` (alongside the existing `tool`
    world from 16b) that imports `host` and exports `tool-api`.
    Backwards-compatible: 16b Components built against `tool`
    keep working unchanged.
  - New `WasmTool::from_component_bytes_with_host(bytes,
    manifest, config, http: Arc<HttpFetchTool>, broker:
    Arc<dyn SecretBroker>)` constructor. The guest's `http-fetch`
    calls go through `http`; `secret-exists` checks go through
    `broker`. The operator passes both because `HttpFetchTool`
    doesn't currently expose its internal broker reference;
    typically both Arcs reference the same broker.
  - `WasmTool::WasmKind` gains a `ComponentWithHost` variant
    alongside `Core` and `Component`. `Tool::call` dispatches
    three ways. The 16a/16b paths are unchanged.
  - New `src/host.rs` module:
    - `HostState` struct holds `Arc<HttpFetchTool>` +
      `Arc<dyn SecretBroker>` + per-call accumulators
      (`secrets_used: Vec<String>`, `logs: Vec<LogRecord>`,
      `http_fetch_calls: u32`). Constructed fresh per
      `WasmTool::call`; accumulators don't leak across calls.
    - `host::Host` trait (bindgen-generated) is implemented on
      `StoreData` (the per-call store-data type) and delegates
      to the inner `Option<HostState>`. For 16a/16b paths the
      Option stays None and the trait methods are never reached
      because the linker doesn't add the host imports.
    - `MAX_LOG_ENTRIES` = 1000, `MAX_LOG_MESSAGE_BYTES` = 4096
      (IronClaw's values).
  - `StoreData` (formerly just memory cap + WasiCtx + ResourceTable)
    gains an `Option<HostState>` field. Two factories: `new(...)`
    (no host; for 16a/16b) and `with_host(..., HostState)` (16c).
  - **`secret_used` provenance edges work for WASM tools by
    construction.** Per-call `secrets_used` (deduplicated union of
    every secret ref name the guest's `http-fetch` calls touched)
    is harvested from `HostState` into `ToolOutput::metadata.secrets_used`
    when the call returns. The kernel's existing
    `RecordToolExecution` handler reads that field and mints
    `ProvenanceEdge { from: "receipt:<id>", to: "secret:<ref>",
    kind: "secret_used" }` — same as for native HttpFetchTool
    calls, no kernel changes needed.
  - **Test fixture**: `tests/fixtures/http-tool-component/`. A
    Rust→WASM Component implementing `tool-with-host` that
    parses tiny ASCII command strings (`"fetch <url>"`,
    `"fetch_auth <url> <secret-ref>"`, `"check <name>"`,
    `"now"`, `"log"`) and uses each host import accordingly.
    Pre-built ~55 KB `.wasm` committed at
    `tests/fixtures/http-tool-component.wasm`. Source +
    `BUILD.md` next to it; CI loads the artefact as-is.
  - 9 new integration tests in `tests/host_imports.rs` covering
    every host-import path against a localhost mock server:
    response body returned to guest, Authorization header
    actually injected on the wire, capability denial relayed as
    `Err(string)`, broker-fetch failure fail-closed without
    opening a socket, secret-exists yes/no, now-millis, log
    doesn't crash, fuel bound inherited from 16a, invalid bytes
    rejected at construction. All 21 16a/16b tests still pass
    unchanged. Workspace 336 → 345.
  - **Adopt-don't-copy citations**: `IronClaw`'s
    `near:agent@0.3.0/host` interface design (we adopted the
    shape — log-level enum, structured response records,
    auth-by-reference, secret-existence-only — with a leaner
    v0 subset; richer pieces like `workspace-read`,
    `tool-invoke`, `headers-json` string land additively when
    use cases demand them); IronClaw's `StoreData` shape
    combining limiter + WasiCtx + Host trait impl into one
    type; IronClaw's rate-limit constants. No source borrowed;
    citations live in `wit/tool.wit`, `src/lib.rs`, `src/host.rs`.
  - New workspace deps in `uniclaw-tools-wasm`:
    `uniclaw-tools-http` (the host's `http-fetch` shim
    delegates to `HttpFetchTool::call`), `uniclaw-secrets`
    (for the `SecretBroker` trait passed to the constructor),
    `serde` + `serde_json` (the host bridge round-trips
    through `HttpFetchInput`/`HttpFetchOutput` JSON because
    `HttpFetchTool::call` takes/returns the JSON envelope —
    a future-step refactor could expose a non-JSON entry
    point), `base64` (decodes the response body from
    HttpFetchOutput's base64 envelope into the bytes the
    guest sees).
  - **Bench** (gitignored at
    `bench-results/16-wasm-host-imports.txt`): direct
    `HttpFetchTool::call` ~16.4 ms/call vs WASM-via-host-import
    ~27.7 ms/call; host-import overhead +11.3 ms (+68%). Per-
    call cost dominated by Component instantiation,
    canonical-ABI marshalling of the `http-response` record,
    and the JSON+base64 round-trip in the host bridge.
    `InstancePre` + persistent compile cache + a non-JSON
    HttpFetchTool entry point are the obvious future-step
    optimisations; all are pure internal swaps.
  - **Step doc** —
    [`docs/steps/16c-wasm-host-imports.md`](docs/steps/16c-wasm-host-imports.md).
- **WASM Component Model layer** (Phase 3 step 4b / step 16b) — the
  typed-interface upgrade on top of 16a's runtime skeleton. Tools
  can now be authored as Component-Model wasm against a small WIT
  and the host drives them through `wasmtime::component::bindgen!`-
  generated bindings instead of the packed-i64 trick from 16a.
  Both paths coexist behind the same `Tool` trait; tools choose.
  - `crates/uniclaw-tools-wasm/wit/tool.wit` defines
    `uniclaw:tool@0.1.0` with a single interface `tool-api`
    exporting `call: func(input: list<u8>) -> result<list<u8>,
    string>`. The world `tool` exports `tool-api` and imports
    nothing — host imports land in 16c via a separate
    `tool-with-host` world.
  - `crates/uniclaw-tools-wasm/src/bindings.rs` invokes
    `wasmtime::component::bindgen!` to generate the host
    bindings. Guarded with module-level allow-lints because the
    generator's emitted code triggers pedantic warnings that
    are out of our control.
  - New constructor `WasmTool::from_component_bytes(bytes,
    manifest, config)` mirrors `from_module_bytes` but for
    Component Model bytes. Internally `WasmTool` now holds a
    `WasmKind { Core(Module), Component(Component) }` enum;
    `Tool::call` dispatches based on what the constructor
    recorded.
  - The Component path uses `bindings::Tool::instantiate(...)`
    + `instance.uniclaw_tool_tool_api().call_call(...)`. The
    canonical ABI handles host↔guest memory ownership (no more
    `alloc`/packed-i64 plumbing). Guest-arm `Err(string)`
    surfaces as `ToolError::Failed("guest: <msg>")`; sandbox
    failures (fuel/epoch/memory) still surface unchanged from
    16a.
  - **Test fixture**: a committed Rust→WASM Component at
    `tests/fixtures/echo-component.wasm` (~46 KB). Source is at
    `tests/fixtures/echo-component/` with a `BUILD.md` next to
    it documenting the local-build path
    (`cargo install cargo-component` + `cargo component build
    --release`). CI doesn't rebuild — the artefact is the
    single source of truth for tests; reviewers can rebuild
    locally to verify.
  - **`wasmtime-wasi` dep** added to the workspace and to
    `uniclaw-tools-wasm`. A Rust→WASM Component built against
    `wasm32-wasip2` automatically declares WASI imports
    regardless of whether it touches them; without those
    imports satisfied on the host, instantiation fails. We
    register an empty WASI context per call (no preopens, no
    env, no stdio passthrough) — strictly to make the imports
    linkable, not to grant any capability. Step 16c replaces
    this with capability-checked Uniclaw imports.
  - `MemoryLimiter` retired; replaced with `StoreData` that
    holds the memory cap PLUS the WASI ctx + resource table.
    Same per-call freshness guarantee — each call gets its
    own store with its own state, nothing leaks. Implements
    both `wasmtime::ResourceLimiter` and
    `wasmtime_wasi::WasiView`.
  - 7 new integration tests for the Component path:
    `component_echo_returns_input_verbatim_via_canonical_abi`,
    `component_guest_error_arm_surfaces_as_failed`,
    `component_call_handles_4kib_input`,
    `component_multiple_calls_have_independent_state`,
    `component_with_zero_fuel_traps_with_failed`,
    `component_invalid_bytes_fail_at_construction`,
    `core_wasm_bytes_rejected_by_from_component_bytes`. All
    14 16a tests still pass unchanged.
  - **Adopt-don't-copy citations**: IronClaw's `near:agent@0.3.0`
    WIT package design (richer `record request/response` shape
    with JSON strings + `schema()`/`description()` exports —
    ours is a leaner `list<u8>` / `result<list<u8>, string>`
    surface; richer pattern is on the future-step list);
    IronClaw's `bindings.rs` shape; IronClaw's `StoreData`
    pattern combining limiter + WASI ctx into one store-data
    type. No source borrowed.
  - **Bench** (gitignored at
    `bench-results/15-wasm-component-model.txt`): cold
    construction core wasm ~17 ms vs Component Model ~860 ms
    (~50× — the fixture is 46 KB vs a few hundred bytes of
    WAT, plus canonical-ABI glue + WASI import resolution).
    Warm call core ~1.13 ms vs Component ~2.52 ms (+1.4 ms,
    +120%) — dominated by per-call
    `wasmtime_wasi::p2::add_to_linker_sync` and canonical-ABI
    marshalling. `InstancePre` + persistent component cache
    are obvious future-step optimisations; both are pure
    internal swaps that can land additively.
  - **Step doc** —
    [`docs/steps/16b-wasm-component-model.md`](docs/steps/16b-wasm-component-model.md).
- **`uniclaw-tools-wasm` crate** — sandboxed Tool runtime backed by
  wasmtime (Phase 3 step 4 / step 16a). Workspace member 16. The
  third real `Tool` implementation, validating the trait surface
  (and `ToolError::Timeout` in particular) against arbitrary
  guest code. Step 16 is split into three PRs (16a/16b/16c)
  because wasmtime is a heavy dep and the Component Model has
  rough edges; landing the runtime first means later failures
  localise cleanly.
  - `WasmTool::from_wat(wat, manifest, config)` and
    `WasmTool::from_module_bytes(bytes, manifest, config)`
    constructors. Both compile a wasmtime `Module`, validate
    that the v0 ABI exports (`memory`, `alloc(i32)->i32`,
    `call(i32,i32)->i64`) are present, set up the engine with
    `consume_fuel(true)` and `epoch_interruption(true)`, and
    spawn a per-tool ticker thread that drives the wall-clock
    deadline.
  - `WasmConfig { fuel, max_memory_bytes, timeout, epoch_tick }`
    with sensible defaults (100 M fuel, 16 MiB memory, 5 s
    timeout, 100 ms tick). Each call gets a fresh `Store` with
    these limits applied — no state leaks between calls.
  - **Three independent resource bounds** enforced per call:
    fuel (CPU; `wasmtime::Trap::OutOfFuel` → `ToolError::Failed("fuel exhausted")`),
    memory (`ResourceLimiter::memory_growing` refuses growth
    past the cap), and wall-clock (`Trap::Interrupt` from the
    epoch deadline → `ToolError::Timeout`). All three fire
    independently; the first one tripped wins. `ToolError::Timeout`
    finally has its first real producer.
  - **No host imports in 16a.** The guest is pure compute (no
    I/O, no clock, no randomness). 16c will add capability-mediated
    syscalls + secret broker bridges; the trait surface for
    those gates already exists from steps 13/14/15.
  - **No Component Model in 16a.** 16b layers
    `wasmtime::component::bindgen!` on top with a real Rust→WASM
    Component fixture. Validating the runtime against core wasm
    first means failures during 16b localise to the bindgen
    layer, not the runtime.
  - 14 integration tests authored as inline WAT fixtures
    (compiled at test time via `wat::parse_str`): echo happy
    path (3 sizes), fuel exhaustion, unreachable trap, memory
    growth refused (cap fires), memory growth allowed (cap
    high enough), epoch deadline → Timeout, missing-export
    construction errors (memory and call), invalid WAT
    construction error, multiple-call independence, approval
    policy mirroring, Send+Sync compile-time check. Plus 6
    unit tests covering config defaults / epoch deadline math
    / error display.
  - **Adopt-don't-copy citations** in `src/lib.rs`:
    `IronClaw`'s wasmtime + WIT Component Model substrate
    (architecture-level reference for the whole step 16
    series; 16a borrows the three-bound resource-limiter
    pattern). The wasmtime safe API is used directly; no
    `unsafe` (workspace lint forbids it).
  - **Bench** (gitignored at
    `bench-results/14-wasm-tool-runtime-skeleton.txt`):
    cold construction ~64 ms (mostly cranelift codegen),
    warm `WasmTool::call` ~770 µs for tiny inputs (mostly
    `Linker::instantiate` per-call cost — the price of the
    fresh-sandbox guarantee). 4 KiB input adds ~1.1 ms for
    the host↔guest memory shuffle. `InstancePre` is the
    obvious future optimisation but premature before host
    imports settle.
  - **Step doc** —
    [`docs/steps/16-wasm-tool-runtime-skeleton.md`](docs/steps/16-wasm-tool-runtime-skeleton.md)
    walks through the design choices, the v0 guest ABI, the
    resource-bound triad, the explicit deferrals (host imports,
    Component Model, persistent compile cache, async, multi-tenant
    accounting), and the rationale for splitting step 16 into
    three PRs.
- **`uniclaw-secrets` crate** — typed surface for credential injection
  (Phase 3 step 3 / step 15). Workspace member 15.
  - `SecretValue` — drop-zeroizing buffer (via the `zeroize` crate),
    redacted Debug (`SecretValue([REDACTED, len=N])`), no `Display`,
    no `Serialize`, no `Clone`, no `Default`. The shape is hostile to
    accidental logging by construction; `expose(&self) -> &str`
    returns a borrow that lives no longer than the broker call.
  - `SecretBroker` trait — one method, `fetch(name) -> Result<SecretValue,
    BrokerError>`. `Send + Sync` so brokers thread through
    `Arc<dyn SecretBroker>` cleanly. `BrokerError` distinguishes
    `NotFound`, `AccessDenied`, `Backend(String)`; the Display impl
    is value-free by construction (the secret value isn't part of the
    type).
  - `InMemorySecretBroker` — `BTreeMap`-backed reference impl.
    `insert(name, value)` / `insert_string(name, secret)`; Debug
    prints only the registered count (no names, no values). `fetch`
    re-allocates a fresh `SecretValue` per call (since
    `SecretValue: !Clone` is deliberate).
  - `EnvSecretBroker` — reads from environment variables under a
    configurable prefix. `env_var_name(secret_ref)` transforms
    `github.token` → `<PREFIX>GITHUB_TOKEN` (uppercase, `.` and `-`
    become `_`, other chars dropped). The env model inherits its
    threat model (OS sees plaintext, child processes may inherit) —
    documented in the crate doc.
  - **Adopt-don't-copy citations** in `lib.rs` and `broker.rs`:
    `IronClaw`'s fail-closed broker pattern, `OpenClaw`'s
    secret-reference (not value) audit model, `ZeroClaw`'s
    drop-zeroing discipline. The `zeroize` crate is the only new
    runtime dependency.
- **`HttpFetchTool` authentication** (Phase 3 step 15, in
  `uniclaw-tools-http`).
  - Three new constructors: `with_broker(allowed_hosts, broker)`,
    `with_broker_and_config(allowed_hosts, broker, config)`, plus a
    `has_broker()` accessor. `with_allowlist` and `with_config` keep
    their existing meaning (no broker → unauthenticated requests
    only).
  - `HttpFetchInput` gains an optional `auth: AuthSpec` field. v0
    supports `AuthSpec::BearerHeader { secret_ref: String }`; the
    JSON shape is tagged (`{"type":"bearer_header","secret_ref":...}`)
    so future variants land additively. `#[serde(default)]` on the
    field keeps existing receipts parseable.
  - `Tool::call` resolves the auth spec **after** the capability and
    SSRF gates and **before** the HTTP request: broker not configured
    or `BrokerError` from `fetch` — both fail-closed with
    `ToolError::Failed`, **no socket opened**. Two integration tests
    pin the no-IO property by asserting the mock server's captured
    requests are empty after a fail-closed call.
  - On success, the resolved secret is set as
    `Authorization: Bearer <value>` for the duration of the request
    only; the `SecretValue` is dropped (zeroed) at the end of the auth
    block. Test
    `authenticated_request_injects_authorization_bearer_header`
    asserts the header reaches the wire with the expected value.
- **`ToolOutput::metadata`** (`uniclaw-tools`). New
  `ToolMetadata { secrets_used: Vec<String> }` field. Carries the
  *reference names* of secrets a tool consumed during a call; values
  never appear here. Backwards-compatible additive change — a tool
  that consumes no secrets returns
  `metadata: ToolMetadata::default()`. All existing tools
  (`NoopTool`, `HttpFetchTool` unauthenticated path) populate empty
  metadata; only the auth path of `HttpFetchTool` writes a non-empty
  list.
- **`secret_used` provenance edges** in
  `Kernel::handle_record_tool_execution`. For each `secret_ref` in
  `output.metadata.secrets_used`, the kernel mints one
  `ProvenanceEdge { from: "receipt:<allowed_id_hex>", to:
  "secret:<ref>", kind: "secret_used" }` alongside the existing
  `tool_execution` / `tool_input` / `tool_output` edges. Auditors
  walking the receipt log can now answer "which receipts touched
  `secret:<X>`?" by structural query — without re-running tools and
  without ever seeing values.
- **Two new kernel tests** for the provenance integration:
  `tool_execution_emits_secret_used_provenance_edges_for_each_used_secret`
  (3 base + N secret edges, exact format check, no values anywhere
  in the receipt body) and
  `tool_execution_with_no_secrets_used_emits_only_base_edges` (sanity
  check that empty `secrets_used` produces no placeholder edges).
- **Step 15 doc** — [`docs/steps/15-secret-broker.md`](docs/steps/15-secret-broker.md)
  walks through the trust model, fail-closed semantics, kernel
  integration, perf baseline, and explicit deferrals (multi-secret
  per call, BasicAuth/CustomHeader/SigV4, ACL-by-caller, real Vault
  / AWS Secrets Manager / GCP Secret Manager backends, signed-config
  provenance, sanitization of secrets out of tool output bodies — all
  on the future-step list).

- **`uniclaw-tools-http` crate** — first real tool implementation
  (Phase 3 step 2 / step 14). Workspace member 14. Validates the
  trait surface from step 13 against actual network code, with three
  defenses wired in.
  - `HttpFetchTool` implements `Tool`. Synchronous GET via `ureq`
    (rustls TLS, no `tokio` / `reqwest` heaviness); JSON envelope
    input/output (`{"url": …}` → `{"status": …, "headers": [(name,
    value)…], "body_b64": …}`).
  - **Capability allowlist**: each tool is constructed with a list
    of `GlobPattern`s; every request passes through
    `Capability::is_granted_by(declared, requested)` before the HTTP
    client is touched. Denied requests fail with
    `ToolError::CapabilityDenied { attempted }` — no socket opened.
  - **SSRF defense**: literal-IP requests to private / loopback /
    link-local / multicast / reserved / IPv4-mapped-IPv6 ranges are
    refused by default. RFC-cited table in
    `uniclaw-tools-http/src/ssrf.rs`. Production config has
    `allow_private_ips: false`; tests use
    `HttpFetchConfig::for_test_localhost()` for `127.0.0.1`.
  - **Bounded read**: `max_response_bytes` (default 10 MiB) enforced
    via `Read::take(max + 1)`; oversize fails with
    `ToolError::Failed`, partial bodies are never returned.
  - **No auto-redirects**: `ureq::AgentBuilder::redirects(0)`. A 3xx
    is surfaced as the actual status + Location header; the caller
    decides whether to follow (and that follow goes through the
    capability allowlist again).
  - Configurable timeout (default 30 s), fixed User-Agent
    `uniclaw-tools-http/<version>`.
- **`uniclaw-tools::Capability::is_granted_by(&[Capability], &Capability) -> bool`**
  helper — small additive to the existing crate. Other tool crates
  (next: `uniclaw-tools-fs`, `uniclaw-tools-shell`, …) will use the
  same gate.
- 45 new tests (14 `uniclaw-tools-http` unit + 8
  `uniclaw-tools-http` integration against a hand-rolled localhost
  mock server + 5 new `Capability::is_granted_by` unit tests + the
  pre-existing 8 unit + 7 kernel integration carried forward from
  step 13). Workspace test count: **229 → 274**.

### Changed

- `uniclaw-tools-http` now depends on `uniclaw-secrets` (regular
  dep). The `serde` feature `alloc` is now enabled in
  `uniclaw-tools-http` to support the tagged-enum derive on
  `AuthSpec` (workspace `serde` has `default-features = false`,
  which lacks the alloc-gated `TaggedContentVisitor` needed by
  `#[serde(tag = "...")]`).
- All `ToolOutput` construction sites in the kernel and its tests
  updated to include `metadata: ToolMetadata::default()` (or a
  populated metadata, where applicable).
- `HttpFetchTool::Debug` impl now prints `broker: "<configured>"` /
  `"<none>"` rather than attempting to format the `dyn SecretBroker`
  (which has no `Debug` requirement, deliberately).
- Phase 3 sub-step plan in `docs/03-roadmap.md` reordered. The
  original step 13 PR proposed `13 → WASM → caps → secrets → container
  → sanitization`. This PR confirms a better order:
  `13 → HTTP+caps → secrets → WASM → container → sanitization`.
  Reason: WASM-with-I/O depends on capability enforcement, and
  capability enforcement is best validated against a real native
  tool first. Native HTTP first → secrets next → WASM with both
  already proven.

### Performance (release, x86_64 Linux, localhost mock server with `connection: close`)

- `HttpFetchTool` warm fetch, 5-byte body: **~25 ms/call**
- `HttpFetchTool` warm fetch, 1 MiB body: **~94 ms/call** (~11 MiB/s)
- `Capability::is_granted_by`: sub-microsecond (single-pass glob match)
- `ssrf::is_disallowed_ip`: sub-microsecond

The fetch numbers are dominated by TCP setup + the mock's per-request
thread spawn (the mock returns `connection: close`, defeating ureq's
keep-alive). Real-world deployments against a keep-alive server see
warm fetches in the low single-digit milliseconds. The capability
and SSRF gates are not visible in the totals.

### Adopt-don't-copy

- **`IronClaw`'s SSRF defense** — adopted as `uniclaw-tools-http::ssrf`.
  Same RFC table; we add the IPv6 side. No source borrowed.
- **`OpenFang`'s capability-enforcement-at-the-tool-boundary pattern**
  — adopted as `Capability::is_granted_by` called from
  `HttpFetchTool::call` before any I/O.

Cited in `crates/uniclaw-tools-http/src/lib.rs` and `ssrf.rs`.

### Notes

- New doc per the standing rule:
  `docs/steps/14-http-fetch-tool.md`. Roadmap and docs index
  updated to reflect the reorder.

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
