# Changelog

All notable changes to Uniclaw are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Receipt-format changes are versioned independently; see `RFCS/` for receipt
format change history.

## [Unreleased]

### Added

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
