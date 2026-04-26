//! Kernel state — the minimum the kernel must carry between events.

use uniclaw_receipt::Digest;

/// State the kernel threads through every event.
///
/// Larger state (session table, capability lease registry, policy cache)
/// will live in their own crates and reference this. The sketch keeps only
/// what's strictly required to chain receipts.
///
/// `prev_hash` is the leaf hash of the most-recent receipt; `sequence` is
/// the index the next receipt will carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelState {
    /// Sequence number that the next-emitted receipt will carry.
    pub sequence: u64,
    /// Leaf hash of the most-recent receipt, or all zeros at genesis.
    pub prev_hash: Digest,
}

impl KernelState {
    /// Genesis state: no receipts yet, `prev_hash` all zeros.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            sequence: 0,
            prev_hash: Digest([0u8; 32]),
        }
    }

    /// Advance after emitting a receipt with `new_leaf` as its leaf hash.
    pub fn advance(&mut self, new_leaf: Digest) {
        self.sequence = self.sequence.saturating_add(1);
        self.prev_hash = new_leaf;
    }
}

impl Default for KernelState {
    fn default() -> Self {
        Self::genesis()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_starts_at_sequence_zero_with_zero_prev_hash() {
        let s = KernelState::genesis();
        assert_eq!(s.sequence, 0);
        assert_eq!(s.prev_hash, Digest([0u8; 32]));
    }

    #[test]
    fn default_equals_genesis() {
        assert_eq!(KernelState::default(), KernelState::genesis());
    }

    #[test]
    fn advance_increments_sequence_and_overwrites_prev_hash() {
        let mut s = KernelState::genesis();
        s.advance(Digest([1u8; 32]));
        assert_eq!(s.sequence, 1);
        assert_eq!(s.prev_hash, Digest([1u8; 32]));
        s.advance(Digest([2u8; 32]));
        assert_eq!(s.sequence, 2);
        assert_eq!(s.prev_hash, Digest([2u8; 32]));
    }

    #[test]
    fn advance_saturates_at_u64_max() {
        let mut s = KernelState {
            sequence: u64::MAX,
            prev_hash: Digest([0u8; 32]),
        };
        s.advance(Digest([3u8; 32]));
        assert_eq!(s.sequence, u64::MAX);
    }
}
