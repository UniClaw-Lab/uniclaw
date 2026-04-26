//! The kernel state machine.

use alloc::vec::Vec;

use uniclaw_budget::BudgetError;
use uniclaw_constitution::Constitution;
use uniclaw_receipt::{Decision, MerkleLeaf, RECEIPT_FORMAT_VERSION, ReceiptBody, RuleRef};

use crate::event::{KernelEvent, Proposal};
use crate::leaf::compute_leaf_hash;
use crate::outcome::{KernelOutcome, OutcomeKind};
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

        // 1. Constitution.
        let verdict = self.constitution.evaluate(&p.action);
        let mut final_decision = verdict.override_decision.unwrap_or(p.decision);
        let mut constitution_rules =
            merge_constitution_rules(p.constitution_rules, verdict.matched_rules);
        let constitution_overrode = verdict.override_decision.is_some();

        // 2. Budget — only attempted if the constitution didn't already deny.
        let mut lease_after = p.lease;
        let mut budget_error: Option<BudgetError> = None;
        if final_decision != Decision::Denied
            && let Some(lease) = lease_after.as_mut()
            && let Err(e) = lease.try_charge(&p.charge)
        {
            final_decision = Decision::Denied;
            budget_error = Some(e);
            // Surface the budget error as a virtual rule in
            // `constitution_rules` so the receipt — which is the only
            // cold-verifiable artifact — is self-explaining without the
            // KernelOutcome alongside.
            constitution_rules.push(RuleRef {
                id: alloc::format!("$kernel/budget/{}", e.short_name()),
                matched: true,
            });
        }

        // 3. Mint the receipt.
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

        let kind = if let Some(e) = budget_error {
            OutcomeKind::DeniedByBudget(e)
        } else if constitution_overrode {
            OutcomeKind::DeniedByConstitution
        } else if final_decision == Decision::Denied {
            OutcomeKind::AllowedAsDenied
        } else {
            OutcomeKind::Allowed
        };

        KernelOutcome {
            receipt,
            lease_after,
            kind,
        }
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

    use uniclaw_budget::{Budget, CapabilityLease, LeaseId, ResourceUse};
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
        Proposal::unbounded(
            Action {
                kind: "http.fetch".into(),
                target: "https://example.com/".into(),
                input_hash: Digest([0u8; 32]),
            },
            Decision::Allowed,
            vec![],
            vec![],
        )
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

    fn budget(net: u64) -> Budget {
        Budget {
            net_bytes: net,
            file_writes: 1000,
            llm_tokens: 1_000_000,
            wall_ms: 600_000,
            max_uses: 10_000,
        }
    }

    fn charge(net: u64) -> ResourceUse {
        ResourceUse {
            net_bytes: net,
            file_writes: 0,
            llm_tokens: 0,
            wall_ms: 0,
            uses: 1,
        }
    }

    #[test]
    fn first_receipt_has_sequence_zero_and_zero_prev_hash() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let out = k.handle(KernelEvent::EvaluateProposal(proposal()));
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 0);
        assert_eq!(out.receipt.body.merkle_leaf.prev_hash, Digest([0u8; 32]));
        assert_eq!(out.kind, OutcomeKind::Allowed);
        assert!(out.lease_after.is_none());
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
        p.decision = Decision::Allowed;

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert_eq!(out.kind, OutcomeKind::DeniedByConstitution);
    }

    #[test]
    fn caller_proposed_denied_is_classified_as_allowed_as_denied() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let mut p = proposal();
        p.decision = Decision::Denied;

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert_eq!(out.kind, OutcomeKind::AllowedAsDenied);
    }

    #[test]
    fn budget_within_limits_allows_and_charges_lease() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let lease = CapabilityLease::new(LeaseId::ZERO, budget(1000));
        let p = Proposal::with_lease(
            proposal().action,
            Decision::Allowed,
            vec![],
            vec![],
            lease,
            charge(100),
        );

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Allowed);
        assert_eq!(out.kind, OutcomeKind::Allowed);

        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 100);
        assert_eq!(after.remaining().net_bytes, 900);
    }

    #[test]
    fn budget_exhausted_forces_denied_and_records_virtual_rule() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        // Lease too small for the proposed charge.
        let lease = CapabilityLease::new(LeaseId::ZERO, budget(50));
        let p = Proposal::with_lease(
            proposal().action,
            Decision::Allowed,
            vec![],
            vec![],
            lease,
            charge(100),
        );

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert!(matches!(
            out.kind,
            OutcomeKind::DeniedByBudget(BudgetError::NetBytesExhausted),
        ));

        // Receipt is self-explaining: it lists the virtual budget rule.
        let ids: Vec<&str> = out
            .receipt
            .body
            .constitution_rules
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert!(
            ids.contains(&"$kernel/budget/net_bytes_exhausted"),
            "expected virtual budget rule in receipt; got: {ids:?}",
        );

        // Lease state is unchanged on failure.
        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 0);
    }

    #[test]
    fn constitution_deny_short_circuits_budget_check() {
        // Both the constitution and the budget would deny, but the
        // constitution fires first — lease must be untouched.
        let mut k = Kernel::new(StubSigner, FixedClock, deny_shell());
        let lease = CapabilityLease::new(LeaseId::ZERO, budget(50));
        let mut p = Proposal::with_lease(
            proposal().action,
            Decision::Allowed,
            vec![],
            vec![],
            lease,
            charge(100), // would exceed budget too
        );
        p.action.kind = "shell.exec".into();

        let out = k.handle(KernelEvent::EvaluateProposal(p));
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert_eq!(out.kind, OutcomeKind::DeniedByConstitution);

        // Lease not charged.
        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 0);
    }
}
