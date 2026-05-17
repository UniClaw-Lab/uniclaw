//! Ed25519 signer adapter for the kernel.
//!
//! The kernel is generic over a `Signer` trait; this module supplies
//! the concrete adapter that wraps a `ed25519_dalek::SigningKey` and
//! routes receipts through `boardproof_receipt::crypto::sign`. The shape
//! mirrors the helper the end-to-end demo defines inline — it's
//! extracted into the library so the HTTP API binary (step 21) and
//! future binaries don't redefine it.
//!
//! ## Trust posture
//!
//! `Ed25519Signer` holds the raw signing key in process memory. That
//! is appropriate for a kernel sidecar process running on a host the
//! operator trusts (dev mode + the local-sidecar integration pattern
//! from the war analysis). For production deployments where key
//! compromise is a credible threat, a future PR will add an
//! HSM-backed signer that satisfies the same trait without exposing
//! the raw key bytes.

use ed25519_dalek::SigningKey;

use boardproof_kernel::Signer;
use boardproof_receipt::{PublicKey, Receipt, ReceiptBody, crypto};

/// Concrete `Signer` implementation backed by an in-memory
/// Ed25519 private key.
///
/// The wrapped `SigningKey` is intentionally not exposed — callers
/// construct one via [`Ed25519Signer::from_seed`] (deterministic
/// dev key) or [`Ed25519Signer::new`] (any `SigningKey`). The
/// associated public key is read via the `Signer` trait.
///
/// Optionally carries a [`key_id`](Signer::key_id) — an opaque,
/// operator-chosen identifier (e.g. `"prod-2026"`, `"hsm-3"`) that
/// the kernel embeds in every minted receipt's `body.key_id`. See
/// step 19a (RFC-0001 rev 2.1) for the rotation / revocation /
/// expiry semantics that build on this.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    key: SigningKey,
    key_id: Option<String>,
}

impl Ed25519Signer {
    /// Wrap an existing `SigningKey` with no `key_id`. Receipts
    /// minted by this signer omit the `body.key_id` field
    /// (byte-identical to pre-step-19a output).
    #[must_use]
    pub fn new(key: SigningKey) -> Self {
        Self { key, key_id: None }
    }

    /// Construct a signer from a 32-byte seed. Useful for tests
    /// and for the deterministic-key dev mode of `boardproof-host`.
    /// Real deployments should never construct keys from a fixed
    /// seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
            key_id: None,
        }
    }

    /// Attach an opaque `key_id` to this signer. The kernel embeds
    /// the value in every minted receipt's `body.key_id`. Returns
    /// `self` for chaining:
    ///
    /// ```rust,ignore
    /// let signer = Ed25519Signer::from_seed(&seed).with_key_id("prod-2026");
    /// ```
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Remove any previously-set `key_id` (useful in tests that
    /// want to confirm pre-step-19a byte-identical output).
    #[must_use]
    pub fn without_key_id(mut self) -> Self {
        self.key_id = None;
        self
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, body: ReceiptBody) -> Receipt {
        crypto::sign(body, &self.key)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(self.key.verifying_key().to_bytes())
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}
