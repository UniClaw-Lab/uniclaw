# Changelog

All notable changes to Uniclaw are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Receipt-format changes are versioned independently; see `RFCS/` for receipt
format change history.

## [Unreleased]

### Added

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
