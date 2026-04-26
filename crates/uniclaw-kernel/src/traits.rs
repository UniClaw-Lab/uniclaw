//! Pluggable dependencies the kernel injects.
//!
//! Defining these as traits — rather than calling concrete crypto / clock
//! functions directly — keeps the kernel testable (mock clocks, mock
//! signers), embeddable (`no_std` targets without a system clock), and ready
//! for HSM / hardware-wallet / post-quantum signing in future phases.

use alloc::string::String;

use uniclaw_receipt::{Receipt, ReceiptBody};

/// Signs a receipt body. The kernel never sees raw key material.
///
/// Default ed25519 implementation lives in tests and in the future runtime
/// crate, not here — the kernel itself is signature-algorithm-agnostic.
pub trait Signer {
    /// Sign `body` and return a complete `Receipt` (issuer + signature).
    fn sign(&self, body: ReceiptBody) -> Receipt;
}

/// Provides the wall-clock string used for receipt `issued_at` fields.
///
/// Required output is RFC 3339 / ISO 8601, e.g. `2026-04-26T12:00:00Z`.
/// Tests typically supply a fixed-clock impl; production binds to
/// `chrono` or `time` in the runtime crate.
pub trait Clock {
    /// Return the current time as an RFC 3339 string.
    fn now_iso8601(&self) -> String;
}
