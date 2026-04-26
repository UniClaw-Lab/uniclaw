//! The kernel state machine.

use uniclaw_receipt::{MerkleLeaf, RECEIPT_FORMAT_VERSION, ReceiptBody};

use crate::event::{KernelEvent, Proposal};
use crate::leaf::compute_leaf_hash;
use crate::outcome::KernelOutcome;
use crate::state::KernelState;
use crate::traits::{Clock, Signer};

/// The trusted runtime core.
///
/// Generic over `Signer` and `Clock` so tests can inject deterministic
/// dependencies, embedded targets can supply their own clock, and production
/// can plug HSM-backed signers without touching the kernel itself.
#[derive(Debug)]
pub struct Kernel<S: Signer, C: Clock> {
    state: KernelState,
    signer: S,
    clock: C,
}

impl<S: Signer, C: Clock> Kernel<S, C> {
    /// Construct a fresh kernel at genesis state.
    pub fn new(signer: S, clock: C) -> Self {
        Self {
            state: KernelState::genesis(),
            signer,
            clock,
        }
    }

    /// Construct a kernel resuming from a known prior state.
    ///
    /// Used when a runtime restarts from a persisted Merkle chain.
    pub fn resume(state: KernelState, signer: S, clock: C) -> Self {
        Self {
            state,
            signer,
            clock,
        }
    }

    /// Inspect the current state.
    #[must_use]
    pub fn state(&self) -> &KernelState {
        &self.state
    }

    /// Drive the state machine with one event. Always emits a receipt today.
    pub fn handle(&mut self, event: KernelEvent) -> KernelOutcome {
        match event {
            KernelEvent::EvaluateProposal(p) => self.handle_proposal(p),
        }
    }

    fn handle_proposal(&mut self, p: Proposal) -> KernelOutcome {
        let issued_at = self.clock.now_iso8601();

        let leaf_hash = compute_leaf_hash(
            self.state.sequence,
            &issued_at,
            &p.action,
            p.decision,
            &self.state.prev_hash,
        );

        let body = ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at,
            action: p.action,
            decision: p.decision,
            constitution_rules: p.constitution_rules,
            provenance: p.provenance,
            redactor_stack_hash: None,
            merkle_leaf: MerkleLeaf {
                sequence: self.state.sequence,
                leaf_hash,
                prev_hash: self.state.prev_hash,
            },
        };

        let receipt = self.signer.sign(body);
        self.state.advance(leaf_hash);
        KernelOutcome { receipt }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use core::cell::Cell;

    use uniclaw_receipt::{Action, Decision, Digest, Receipt, ReceiptBody};

    /// Mock signer that produces deterministic, hand-crafted receipts —
    /// avoids ed25519 in unit tests so we can isolate state-machine logic.
    /// Integration tests use the real ed25519 signer.
    struct StubSigner;

    impl Signer for StubSigner {
        fn sign(&self, body: ReceiptBody) -> Receipt {
            Receipt {
                version: RECEIPT_FORMAT_VERSION,
                body,
                issuer: uniclaw_receipt::PublicKey([0xAA; 32]),
                signature: uniclaw_receipt::Signature([0xBB; 64]),
            }
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now_iso8601(&self) -> String {
            "2026-04-26T12:00:00Z".to_string()
        }
    }

    /// Clock that returns a different timestamp on every call — used to
    /// exercise that distinct `issued_at` values produce distinct leaf hashes.
    struct CountingClock {
        counter: Cell<u32>,
    }

    impl Clock for CountingClock {
        fn now_iso8601(&self) -> String {
            let n = self.counter.get();
            self.counter.set(n + 1);
            alloc::format!("2026-04-26T12:00:{n:02}Z")
        }
    }

    fn proposal() -> Proposal {
        Proposal {
            action: Action {
                kind: "http.fetch".into(),
                target: "https://example.com/".into(),
                input_hash: Digest([0u8; 32]),
            },
            decision: Decision::Allowed,
            constitution_rules: vec![],
            provenance: vec![],
        }
    }

    #[test]
    fn first_receipt_has_sequence_zero_and_zero_prev_hash() {
        let mut k = Kernel::new(StubSigner, FixedClock);
        let out = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 0);
        assert_eq!(out.receipt.body.merkle_leaf.prev_hash, Digest([0u8; 32]));
    }

    #[test]
    fn state_advances_after_handle() {
        let mut k = Kernel::new(StubSigner, FixedClock);
        assert_eq!(k.state().sequence, 0);
        let out = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(k.state().sequence, 1);
        assert_eq!(k.state().prev_hash, out.receipt.body.merkle_leaf.leaf_hash);
    }

    #[test]
    fn second_receipt_chains_to_first() {
        let mut k = Kernel::new(
            StubSigner,
            CountingClock {
                counter: Cell::new(0),
            },
        );
        let r1 = k.handle(KernelEvent::EvaluateProposal(proposal()));
        let r2 = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(r2.receipt.body.merkle_leaf.sequence, 1);
        assert_eq!(
            r2.receipt.body.merkle_leaf.prev_hash,
            r1.receipt.body.merkle_leaf.leaf_hash,
        );
    }

    #[test]
    fn distinct_issued_at_produces_distinct_leaf_hashes() {
        let mut k = Kernel::new(
            StubSigner,
            CountingClock {
                counter: Cell::new(0),
            },
        );
        let r1 = k.handle(KernelEvent::EvaluateProposal(proposal()));
        let r2 = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_ne!(
            r1.receipt.body.merkle_leaf.leaf_hash,
            r2.receipt.body.merkle_leaf.leaf_hash,
        );
    }

    #[test]
    fn resume_continues_from_provided_state() {
        let resumed_state = KernelState {
            sequence: 42,
            prev_hash: Digest([0xCD; 32]),
        };
        let mut k = Kernel::resume(resumed_state, StubSigner, FixedClock);
        let out = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 42);
        assert_eq!(out.receipt.body.merkle_leaf.prev_hash, Digest([0xCD; 32]));
        assert_eq!(k.state().sequence, 43);
    }
}
