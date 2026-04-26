//! Merkle audit-chain leaf hashing.
//!
//! Per RFC-0001 §8:
//! `leaf_hash = BLAKE3(sequence ‖ issued_at ‖ action ‖ decision ‖ prev_hash)`
//!
//! `action` and `decision` are encoded with `serde_json::to_vec`, matching
//! the canonical encoding used for receipt signing (RFC-0001 §6.4).

use alloc::vec::Vec;

use uniclaw_receipt::{Action, Decision, Digest};

/// Compute the Merkle leaf hash for a receipt about to be emitted.
///
/// # Panics
///
/// Panics if `serde_json::to_vec` fails on a well-formed `Action` or
/// `Decision`. These types are infallibly serializable; failure indicates a
/// bug in `uniclaw-receipt` and must surface loudly rather than silently
/// degrading the audit chain.
#[must_use]
pub fn compute_leaf_hash(
    sequence: u64,
    issued_at: &str,
    action: &Action,
    decision: Decision,
    prev_hash: &Digest,
) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&sequence.to_le_bytes());
    hasher.update(issued_at.as_bytes());

    let action_bytes: Vec<u8> = serde_json::to_vec(action).expect("action serializable");
    hasher.update(&action_bytes);

    let decision_bytes: Vec<u8> = serde_json::to_vec(&decision).expect("decision serializable");
    hasher.update(&decision_bytes);

    hasher.update(&prev_hash.0);
    Digest(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action() -> Action {
        Action {
            kind: "http.fetch".into(),
            target: "https://example.com/".into(),
            input_hash: Digest([0u8; 32]),
        }
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let a = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        let b = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn changes_when_sequence_changes() {
        let a = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        let b = compute_leaf_hash(
            1,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn changes_when_decision_changes() {
        let a = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        let b = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Denied,
            &Digest([0u8; 32]),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn changes_when_prev_hash_changes() {
        let a = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        let b = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([1u8; 32]),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn changes_when_action_changes() {
        let mut other = sample_action();
        other.target = "https://evil.example/".into();
        let a = compute_leaf_hash(
            0,
            "ts",
            &sample_action(),
            Decision::Allowed,
            &Digest([0u8; 32]),
        );
        let b = compute_leaf_hash(0, "ts", &other, Decision::Allowed, &Digest([0u8; 32]));
        assert_ne!(a, b);
    }
}
