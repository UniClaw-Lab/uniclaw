//! Ed25519 signer adapter for the kernel.
//!
//! The kernel is generic over a `Signer` trait; this module supplies
//! the concrete adapter that wraps a `ed25519_dalek::SigningKey` and
//! routes receipts through `uniclaw_receipt::crypto::sign`. The shape
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

use uniclaw_kernel::Signer;
use uniclaw_receipt::{PublicKey, Receipt, ReceiptBody, crypto};

/// Concrete `Signer` implementation backed by an in-memory
/// Ed25519 private key.
///
/// The wrapped `SigningKey` is intentionally not exposed — callers
/// construct one via [`Ed25519Signer::from_seed`] (deterministic
/// dev key) or [`Ed25519Signer::new`] (any `SigningKey`). The
/// associated public key is read via the `Signer` trait.
#[derive(Debug, Clone)]
pub struct Ed25519Signer(SigningKey);

impl Ed25519Signer {
    /// Wrap an existing `SigningKey`.
    #[must_use]
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    /// Construct a signer from a 32-byte seed. Useful for tests and
    /// for the deterministic-key dev mode of `uniclaw-host`. Real
    /// deployments should never construct keys from a fixed seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, body: ReceiptBody) -> Receipt {
        crypto::sign(body, &self.0)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }
}
