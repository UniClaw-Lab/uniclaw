//! Pluggable dependencies the kernel injects.
//!
//! Defining these as traits — rather than calling concrete crypto / clock
//! functions directly — keeps the kernel testable (mock clocks, mock
//! signers), embeddable (`no_std` targets without a system clock), and ready
//! for HSM / hardware-wallet / post-quantum signing in future phases.

use alloc::string::String;

use boardproof_receipt::{PublicKey, Receipt, ReceiptBody};

/// Signs a receipt body and exposes the public half of its keypair.
///
/// The kernel never sees raw key material. The `public_key()` method exists
/// so the kernel can verify "did *I* sign this?" — necessary at approval-
/// resolution time to reject fabricated pending receipts attributed to
/// other issuers.
///
/// Default ed25519 implementation lives in tests and in the future runtime
/// crate, not here — the kernel itself is signature-algorithm-agnostic.
pub trait Signer {
    /// Sign `body` and return a complete `Receipt` (issuer + signature).
    fn sign(&self, body: ReceiptBody) -> Receipt;

    /// Public half of this signer's keypair, matching the `issuer` field
    /// of every receipt this signer produces.
    fn public_key(&self) -> PublicKey;

    /// Optional operator-chosen identifier for this signing key
    /// (step 19a, RFC-0001 rev 2.1).
    ///
    /// When `Some`, the kernel includes the value in every minted
    /// receipt's [`ReceiptBody::key_id`] field so auditors can
    /// correlate the receipt with an external key directory entry
    /// (rotation, revocation, expiry). When `None` (default),
    /// receipts omit the field and remain byte-identical to
    /// pre-19a output — fully backward-compatible.
    ///
    /// Implementations should keep the value short and stable for
    /// the lifetime of this signer (e.g. `"prod-2026"`,
    /// `"hsm-3"`). Rotation = construct a new `Signer` with a new
    /// `key_id`.
    fn key_id(&self) -> Option<&str> {
        None
    }
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
