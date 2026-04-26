//! The kernel state machine.

use alloc::vec::Vec;

use uniclaw_constitution::Constitution;
use uniclaw_receipt::{MerkleLeaf, RECEIPT_FORMAT_VERSION, ReceiptBody};

use crate::event::{KernelEvent, Proposal};
use crate::leaf::compute_leaf_hash;
use crate::outcome::KernelOutcome;
use crate::state::KernelState;
use crate::traits::{Clock, Signer};

/// The trusted runtime core.
///
/// Generic over `Signer`, `Clock`, and `Constitution` so tests can inject
/// deterministic dependencies, embedded targets can supply their own clock,
/// and production can plug HSM-backed signers and operator-authored
/// constitutions without touching the kernel itself.
#[derive(Debug)]
pub struct Kernel<S: Signer, C: Clock, K: Constitution> {
    state: KernelState,
    signer: S,
    clock: C,
    constitution: K,
}

impl<S: Signer, C: Clock, K: Constitution> Kernel<S, C, K> {
    /// Construct a fresh kernel at genesis state.
    pub fn new(signer: S, clock: C, constitution: K) -> Self {
        Self {
            state: KernelState::genesis(),
            signer,
            clock,
            constitution,
        }
    }

    /// Construct a kernel resuming from a known prior state.
    pub fn resume(state: KernelState, signer: S, clock: C, constitution: K) -> Self {
        Self {
            state,
            signer,
            clock,
            constitution,
        }
    }

    /// Inspect the current state.
    #[must_use]
    pub fn state(&self) -> &KernelState {
        &self.state
    }

    /// Drive the state machine with one event.
    pub fn handle(&mut self, event: KernelEvent) -> KernelOutcome {
        match event {
            KernelEvent::EvaluateProposal(p) => self.handle_proposal(p),
        }
    }

    fn handle_proposal(&mut self, p: Proposal) -> KernelOutcome {
        let issued_at = self.clock.now_iso8601();

        // Consult the constitution. The kernel records every matched rule
        // and accepts a forced override (today: only `Denied`).
        let verdict = self.constitution.evaluate(&p.action);
        let final_decision = verdict.override_decision.unwrap_or(p.decision);
        let constitution_rules =
            merge_constitution_rules(p.constitution_rules, verdict.matched_rules);

        let leaf_hash = compute_leaf_hash(
            self.state.sequence,
            &issued_at,
            &p.action,
            final_decision,
            &self.state.prev_hash,
        );

        let body = ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at,
            action: p.action,
            decision: final_decision,
            constitution_rules,
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

/// If the constitution matched any rules, the constitution is authoritative
/// for the receipt's `constitution_rules` field. Otherwise, fall back to
/// whatever the caller pre-populated (today this is mostly empty;
/// future steps may carry rules from upstream layers).
fn merge_constitution_rules(
    caller: Vec<uniclaw_receipt::RuleRef>,
    matched: Vec<uniclaw_receipt::RuleRef>,
) -> Vec<uniclaw_receipt::RuleRef> {
    if matched.is_empty() { caller } else { matched }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use core::cell::Cell;

    use uniclaw_constitution::{
        EmptyConstitution, InMemoryConstitution, MatchClause, Rule, RuleVerdict,
    };
    use uniclaw_receipt::{Action, Decision, Digest, Receipt, ReceiptBody};

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

    fn deny_shell() -> InMemoryConstitution {
        InMemoryConstitution::from_rules(vec![Rule {
            id: "test/no-shell".into(),
            description: "deny shell".into(),
            verdict: RuleVerdict::Deny,
            match_clause: MatchClause {
                kind: Some("shell.exec".into()),
                target_contains: None,
            },
        }])
    }

    #[test]
    fn first_receipt_has_sequence_zero_and_zero_prev_hash() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let out = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 0);
        assert_eq!(out.receipt.body.merkle_leaf.prev_hash, Digest([0u8; 32]));
    }

    #[test]
    fn state_advances_after_handle() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
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
            EmptyConstitution,
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
            EmptyConstitution,
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
        let mut k = Kernel::resume(resumed_state, StubSigner, FixedClock, EmptyConstitution);
        let out = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 42);
        assert_eq!(out.receipt.body.merkle_leaf.prev_hash, Digest([0xCD; 32]));
        assert_eq!(k.state().sequence, 43);
    }

    #[test]
    fn constitution_can_force_denied_on_proposed_allowed() {
        let mut k = Kernel::new(StubSigner, FixedClock, deny_shell());
        let mut p = proposal();
        p.action.kind = "shell.exec".into();
        p.decision = Decision::Allowed; // model proposed allow

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(
            out.receipt.body.decision,
            Decision::Denied,
            "constitution must override Allowed → Denied",
        );
        assert_eq!(out.receipt.body.constitution_rules.len(), 1);
        assert_eq!(out.receipt.body.constitution_rules[0].id, "test/no-shell");
    }

    #[test]
    fn constitution_does_not_relax_denied_to_allowed() {
        // Even if no rule fires, the constitution never grants Allowed.
        // Caller proposed Denied; constitution sees nothing; receipt stays Denied.
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let mut p = proposal();
        p.decision = Decision::Denied;

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Denied);
    }

    #[test]
    fn non_matching_action_passes_through_with_no_rules_recorded() {
        let mut k = Kernel::new(StubSigner, FixedClock, deny_shell());
        let p = proposal(); // kind = "http.fetch"

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Allowed);
        assert!(out.receipt.body.constitution_rules.is_empty());
    }
}
