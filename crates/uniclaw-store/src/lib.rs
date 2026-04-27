//! Receipt log for Uniclaw — chain-validated, issuer-pinned audit storage.
//!
//! A `ReceiptLog` accepts only receipts that:
//! 1. extend the previous one's Merkle leaf (sequence + 1, `prev_hash` matches),
//! 2. verify under the embedded issuer key, and
//! 3. were signed by the same issuer that pinned the log.
//!
//! Refused appends do **not** modify the log — the typed `AppendError`
//! reports exactly which check failed so callers can react.
//!
//! `verify_chain()` re-walks every stored receipt and re-checks the same
//! invariants end-to-end. Deep Sleep (master plan §16.3.3) calls this
//! periodically to detect storage-layer tampering.
//!
//! # Where this fits
//!
//! Master plan §16.1 (Storage Classes — *Audit*). Today only the
//! `InMemoryReceiptLog` implementation ships. A SQLite-backed impl
//! arrives in a follow-up step; the trait surface is designed to support
//! both without changes.
//!
//! # Adopt-don't-copy
//!
//! Issuer-pinned + append-validating chain storage is net-new in this
//! shape. `OpenFang`'s `audit.rs` records similar Merkle hashes but stores
//! them in a kernel-owned `SQLite` table; we keep storage out-of-kernel and
//! validate at the boundary. No source borrowed from any claw runtime.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod log;
mod memory;

pub use log::{AppendError, ReceiptLog, VerifyChainError};
pub use memory::InMemoryReceiptLog;
