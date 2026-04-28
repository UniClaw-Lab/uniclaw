//! `ReceiptLog` trait + the typed errors append and chain-verification can return.

use uniclaw_receipt::{Digest, PublicKey, Receipt};

/// Issuer-pinned, chain-validating receipt storage.
///
/// Implementations refuse any receipt that doesn't extend the chain;
/// callers can rely on `len()` reflecting only verified entries.
pub trait ReceiptLog {
    /// The kernel public key this log is pinned to. Receipts signed by
    /// any other issuer are rejected by `append`.
    fn issuer(&self) -> PublicKey;

    /// Append `receipt` if and only if it extends the chain.
    ///
    /// # Errors
    ///
    /// Returns the specific check that failed. The log's state is **not**
    /// modified on error — the receipt is simply not stored.
    fn append(&mut self, receipt: Receipt) -> Result<(), AppendError>;

    /// Number of receipts currently stored.
    fn len(&self) -> usize;

    /// True when no receipts have been appended yet.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The most-recently-appended receipt, if any.
    ///
    /// Returns an owned `Receipt`. The trait deliberately does not borrow
    /// from `&self` because some impls (notably `SqliteReceiptLog` in
    /// `uniclaw-store-sqlite`) materialize receipts from a stored encoding
    /// and have nothing to lend.
    fn last(&self) -> Option<Receipt>;

    /// Look up by `merkle_leaf.sequence`. O(1) for `InMemoryReceiptLog`,
    /// O(log n) PK lookup for `SqliteReceiptLog`.
    fn get_by_sequence(&self, sequence: u64) -> Option<Receipt>;

    /// Look up by content id (`receipt.content_id()`).
    fn get_by_id(&self, id: &Digest) -> Option<Receipt>;

    /// Re-walk the entire stored chain and re-verify every invariant
    /// (sequence monotonicity, `prev_hash` chaining, signature on body).
    ///
    /// Used by Deep Sleep to detect storage-layer tampering after the
    /// fact. Cheap on healthy logs; the heavy cost is the per-receipt
    /// Ed25519 verify.
    ///
    /// # Errors
    ///
    /// Returns the **first** invariant violation found. Walks left-to-right.
    fn verify_chain(&self) -> Result<(), VerifyChainError>;
}

/// Why `ReceiptLog::append` refused a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendError {
    /// Receipt's `merkle_leaf.sequence` is not the next expected one.
    OutOfOrder { expected: u64, got: u64 },
    /// Receipt's `merkle_leaf.prev_hash` does not match the previous
    /// receipt's `merkle_leaf.leaf_hash`. (For the first receipt the
    /// expected `prev_hash` is all zeros.)
    ChainBroken { expected: Digest, got: Digest },
    /// Receipt's Ed25519 signature does not verify against its issuer key.
    SignatureInvalid,
    /// Receipt's issuer key does not match the log's pinned issuer.
    IssuerMismatch { expected: PublicKey, got: PublicKey },
    /// Receipt's wire-format `version` is not understood by this build.
    UnsupportedVersion { found: u32, expected: u32 },
    /// A receipt with this content id is already in the log.
    DuplicateId(Digest),
}

impl core::fmt::Display for AppendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfOrder { expected, got } => {
                write!(
                    f,
                    "receipt sequence {got} is out of order, expected {expected}"
                )
            }
            Self::ChainBroken { .. } => f.write_str("receipt prev_hash does not chain"),
            Self::SignatureInvalid => f.write_str("receipt signature did not verify"),
            Self::IssuerMismatch { .. } => f.write_str("receipt issuer does not match log issuer"),
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported receipt version {found} (log accepts {expected})"
                )
            }
            Self::DuplicateId(_) => f.write_str("receipt with same content id already in log"),
        }
    }
}

impl core::error::Error for AppendError {}

/// Why `ReceiptLog::verify_chain` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyChainError {
    /// Sequence numbers are not contiguous starting from 0.
    SequenceGapAt { expected: u64, got: u64 },
    /// `prev_hash` does not match the previous receipt's `leaf_hash`.
    BrokenAt {
        sequence: u64,
        expected: Digest,
        got: Digest,
    },
    /// Ed25519 signature does not verify on this receipt's body.
    SignatureInvalidAt { sequence: u64 },
}

impl core::fmt::Display for VerifyChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SequenceGapAt { expected, got } => {
                write!(f, "sequence gap at receipt {got}, expected {expected}")
            }
            Self::BrokenAt { sequence, .. } => {
                write!(f, "chain broken at receipt {sequence}")
            }
            Self::SignatureInvalidAt { sequence } => {
                write!(f, "signature invalid at receipt {sequence}")
            }
        }
    }
}

impl core::error::Error for VerifyChainError {}
