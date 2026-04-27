//! The kernel state machine.

use alloc::format;
use alloc::vec::Vec;

use uniclaw_approval::ApprovalDecision;
use uniclaw_budget::BudgetError;
use uniclaw_constitution::Constitution;
use uniclaw_receipt::{
    Action, Decision, Digest, MerkleLeaf, ProvenanceEdge, RECEIPT_FORMAT_VERSION, Receipt,
    ReceiptBody, RuleRef, crypto,
};
use uniclaw_sleep::LightSleepReport;

use crate::event::{Approval, KernelEvent, Proposal};
use crate::leaf::compute_leaf_hash;
use crate::outcome::{ApprovalRejection, KernelError, KernelOutcome, OutcomeKind};
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
    ///
    /// Returns `Err` only when an event is rejected without minting a
    /// receipt — currently just authentication failures on
    /// `ResolveApproval`. Honest rejections (constitution deny, budget
    /// exhausted, operator denied) always succeed and produce a `Denied`
    /// receipt the caller can inspect.
    pub fn handle(&mut self, event: KernelEvent) -> Result<KernelOutcome, KernelError> {
        match event {
            KernelEvent::EvaluateProposal(p) => Ok(self.handle_proposal(*p)),
            KernelEvent::ResolveApproval(a) => self.handle_resolve_approval(*a),
            KernelEvent::RunLightSleep(r) => Ok(self.handle_light_sleep(&r)),
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
        let constitution_set_pending = verdict.override_decision == Some(Decision::Pending);

        // 2. Budget — only attempted if the constitution didn't already
        //    deny AND didn't set Pending. Pending receipts never charge
        //    the lease; the charge happens at resolve time.
        let mut lease_after = p.lease;
        let mut budget_error: Option<BudgetError> = None;
        if final_decision != Decision::Denied
            && !constitution_set_pending
            && let Some(lease) = lease_after.as_mut()
            && let Err(e) = lease.try_charge(&p.charge)
        {
            final_decision = Decision::Denied;
            budget_error = Some(e);
            constitution_rules.push(RuleRef {
                id: format!("$kernel/budget/{}", e.short_name()),
                matched: true,
            });
        }

        // 3. Mint the receipt.
        let receipt = self.mint(
            issued_at,
            p.action,
            final_decision,
            constitution_rules,
            p.provenance,
        );

        let kind = if let Some(e) = budget_error {
            OutcomeKind::DeniedByBudget(e)
        } else if final_decision == Decision::Pending {
            OutcomeKind::PendingApproval
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

    fn handle_resolve_approval(&mut self, a: Approval) -> Result<KernelOutcome, KernelError> {
        // --- Authenticity gate ---
        // 1. Pending receipt must verify under its embedded issuer.
        if crypto::verify(&a.pending_receipt).is_err() {
            return Err(KernelError::ResolveApprovalRejected(
                ApprovalRejection::PendingSignatureInvalid,
            ));
        }
        // 2. Issuer must be us. A receipt signed by another kernel
        //    cannot be resolved by this one.
        if a.pending_receipt.issuer != self.signer.public_key() {
            return Err(KernelError::ResolveApprovalRejected(
                ApprovalRejection::PendingIssuerMismatch,
            ));
        }
        // 3. The pending receipt's decision must actually be Pending.
        if a.pending_receipt.body.decision != Decision::Pending {
            return Err(KernelError::ResolveApprovalRejected(
                ApprovalRejection::NotAPendingReceipt,
            ));
        }
        // 4. The original proposal's action must match the pending one.
        //    Defends against an attacker substituting a different action
        //    while keeping a valid pending receipt.
        if a.original_proposal.action != a.pending_receipt.body.action {
            return Err(KernelError::ResolveApprovalRejected(
                ApprovalRejection::ActionMismatch,
            ));
        }

        // --- Mint the resolution receipt ---
        let issued_at = self.clock.now_iso8601();
        let pending_id_hex = hex32(&a.pending_receipt.content_id().0);
        let approval_edge = ProvenanceEdge {
            from: format!("receipt:{pending_id_hex}"),
            to: "decision".into(),
            kind: "approval_response".into(),
        };
        let mut provenance = a.original_proposal.provenance.clone();
        provenance.push(approval_edge);

        let mut lease_after = a.original_proposal.lease;
        let mut budget_error: Option<BudgetError> = None;
        let mut constitution_rules: Vec<RuleRef> = Vec::new();
        let final_decision = match a.response {
            ApprovalDecision::Approved => {
                // Re-check budget at approve time.
                if let Some(lease) = lease_after.as_mut()
                    && let Err(e) = lease.try_charge(&a.original_proposal.charge)
                {
                    budget_error = Some(e);
                    constitution_rules.push(RuleRef {
                        id: format!("$kernel/budget/{}", e.short_name()),
                        matched: true,
                    });
                    Decision::Denied
                } else {
                    Decision::Approved
                }
            }
            ApprovalDecision::Denied => {
                constitution_rules.push(RuleRef {
                    id: "$kernel/approval/denied_by_operator".into(),
                    matched: true,
                });
                Decision::Denied
            }
        };

        let receipt = self.mint(
            issued_at,
            a.original_proposal.action,
            final_decision,
            constitution_rules,
            provenance,
        );

        let kind = match (a.response, budget_error) {
            (ApprovalDecision::Approved, Some(e)) => OutcomeKind::DeniedByBudgetAtApproveTime(e),
            (ApprovalDecision::Approved, None) => OutcomeKind::ApprovedAfterPending,
            (ApprovalDecision::Denied, _) => OutcomeKind::DeniedByOperator,
        };

        Ok(KernelOutcome {
            receipt,
            lease_after,
            kind,
        })
    }

    fn handle_light_sleep(&mut self, report: &LightSleepReport) -> KernelOutcome {
        let issued_at = self.clock.now_iso8601();
        let cleaner_count = report.cleaner_count();
        let failed_cleaners = report.failed_count();
        let total_rows = report.total_rows_affected();
        let total_bytes = report.total_bytes_reclaimed();

        // Receipt summarizes the pass at a glance; per-cleaner detail is
        // in the provenance edges.
        let action = Action {
            kind: alloc::string::String::from("$kernel/sleep/light"),
            target: format!(
                "cleaners={cleaner_count} rows={total_rows} bytes={total_bytes} failed={failed_cleaners}",
            ),
            input_hash: Digest([0u8; 32]),
        };

        // One provenance edge per cleaner. Successful cleaners use
        // `kind = "light_sleep_pass"`; failed cleaners use
        // `kind = "light_sleep_failure"` and carry the message in `to`.
        let mut provenance: Vec<ProvenanceEdge> = Vec::with_capacity(cleaner_count);
        for pass in &report.passes {
            let edge = match &pass.outcome {
                Ok(r) => ProvenanceEdge {
                    from: format!("cleaner:{}", pass.name),
                    to: format!("rows={} bytes={}", r.rows_affected, r.bytes_reclaimed),
                    kind: "light_sleep_pass".into(),
                },
                Err(e) => ProvenanceEdge {
                    from: format!("cleaner:{}", pass.name),
                    to: format!("error: {}", e.message),
                    kind: "light_sleep_failure".into(),
                },
            };
            provenance.push(edge);
        }

        let receipt = self.mint(issued_at, action, Decision::Allowed, Vec::new(), provenance);

        KernelOutcome {
            receipt,
            lease_after: None,
            kind: OutcomeKind::LightSleepCompleted { failed_cleaners },
        }
    }

    fn mint(
        &mut self,
        issued_at: alloc::string::String,
        action: Action,
        final_decision: Decision,
        constitution_rules: Vec<RuleRef>,
        provenance: Vec<ProvenanceEdge>,
    ) -> Receipt {
        let leaf_hash = compute_leaf_hash(
            self.state.sequence,
            &issued_at,
            &action,
            final_decision,
            &self.state.prev_hash,
        );

        let body = ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at,
            action,
            decision: final_decision,
            constitution_rules,
            provenance,
            redactor_stack_hash: None,
            merkle_leaf: MerkleLeaf {
                sequence: self.state.sequence,
                leaf_hash,
                prev_hash: self.state.prev_hash,
            },
        };

        let receipt = self.signer.sign(body);
        self.state.advance(leaf_hash);
        receipt
    }
}

/// If the constitution matched any rules, the constitution is authoritative
/// for the receipt's `constitution_rules` field. Otherwise, fall back to
/// whatever the caller pre-populated (today this is mostly empty;
/// future steps may carry rules from upstream layers).
fn merge_constitution_rules(caller: Vec<RuleRef>, matched: Vec<RuleRef>) -> Vec<RuleRef> {
    if matched.is_empty() { caller } else { matched }
}

fn hex32(bytes: &[u8; 32]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(64);
    for &b in bytes {
        let nib = |n: u8| -> char {
            match n {
                0..=9 => (b'0' + n) as char,
                10..=15 => (b'a' + n - 10) as char,
                _ => unreachable!(),
            }
        };
        s.push(nib(b >> 4));
        s.push(nib(b & 0xf));
    }
    s
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

        fn public_key(&self) -> uniclaw_receipt::PublicKey {
            uniclaw_receipt::PublicKey([0xAA; 32])
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

    fn require_approval_shell() -> InMemoryConstitution {
        InMemoryConstitution::from_rules(vec![Rule {
            id: "test/shell-needs-approval".into(),
            description: "shell needs review".into(),
            verdict: RuleVerdict::RequireApproval,
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
        let out = k.handle(KernelEvent::evaluate(proposal())).expect("ok");
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 0);
        assert_eq!(out.receipt.body.merkle_leaf.prev_hash, Digest([0u8; 32]));
        assert_eq!(out.kind, OutcomeKind::Allowed);
        assert!(out.lease_after.is_none());
    }

    #[test]
    fn state_advances_after_handle() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        assert_eq!(k.state().sequence, 0);
        let out = k.handle(KernelEvent::evaluate(proposal())).expect("ok");
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
        let r1 = k.handle(KernelEvent::evaluate(proposal())).unwrap();
        let r2 = k.handle(KernelEvent::evaluate(proposal())).unwrap();
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
        let r1 = k.handle(KernelEvent::evaluate(proposal())).unwrap();
        let r2 = k.handle(KernelEvent::evaluate(proposal())).unwrap();
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
        let out = k.handle(KernelEvent::evaluate(proposal())).expect("ok");
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

        let out = k.handle(KernelEvent::evaluate(p)).unwrap();
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert_eq!(out.kind, OutcomeKind::DeniedByConstitution);
    }

    #[test]
    fn caller_proposed_denied_is_classified_as_allowed_as_denied() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let mut p = proposal();
        p.decision = Decision::Denied;

        let out = k.handle(KernelEvent::evaluate(p)).unwrap();
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

        let out = k.handle(KernelEvent::evaluate(p)).unwrap();
        assert_eq!(out.receipt.body.decision, Decision::Allowed);
        assert_eq!(out.kind, OutcomeKind::Allowed);

        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 100);
        assert_eq!(after.remaining().net_bytes, 900);
    }

    #[test]
    fn budget_exhausted_forces_denied_and_records_virtual_rule() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let lease = CapabilityLease::new(LeaseId::ZERO, budget(50));
        let p = Proposal::with_lease(
            proposal().action,
            Decision::Allowed,
            vec![],
            vec![],
            lease,
            charge(100),
        );

        let out = k.handle(KernelEvent::evaluate(p)).unwrap();
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert!(matches!(
            out.kind,
            OutcomeKind::DeniedByBudget(BudgetError::NetBytesExhausted),
        ));

        let ids: Vec<&str> = out
            .receipt
            .body
            .constitution_rules
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert!(ids.contains(&"$kernel/budget/net_bytes_exhausted"));

        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 0);
    }

    #[test]
    fn constitution_deny_short_circuits_budget_check() {
        let mut k = Kernel::new(StubSigner, FixedClock, deny_shell());
        let lease = CapabilityLease::new(LeaseId::ZERO, budget(50));
        let mut p = Proposal::with_lease(
            proposal().action,
            Decision::Allowed,
            vec![],
            vec![],
            lease,
            charge(100),
        );
        p.action.kind = "shell.exec".into();

        let out = k.handle(KernelEvent::evaluate(p)).unwrap();
        assert_eq!(out.receipt.body.decision, Decision::Denied);
        assert_eq!(out.kind, OutcomeKind::DeniedByConstitution);

        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 0);
    }

    // --- E1: approval flow ---

    #[test]
    fn require_approval_rule_yields_pending_receipt_without_charging_lease() {
        let mut k = Kernel::new(StubSigner, FixedClock, require_approval_shell());
        let lease = CapabilityLease::new(LeaseId::ZERO, budget(1000));
        let p = Proposal::with_lease(
            Action {
                kind: "shell.exec".into(),
                target: "ls".into(),
                input_hash: Digest([0u8; 32]),
            },
            Decision::Allowed,
            vec![],
            vec![],
            lease,
            charge(100),
        );

        let out = k.handle(KernelEvent::evaluate(p)).unwrap();
        assert_eq!(out.receipt.body.decision, Decision::Pending);
        assert_eq!(out.kind, OutcomeKind::PendingApproval);

        // Lease was NOT charged on the Pending path.
        let after = out.lease_after.expect("lease threaded through");
        assert_eq!(after.consumed.net_bytes, 0);
        assert_eq!(after.remaining().net_bytes, 1000);
    }

    // The remaining approval-flow tests exercise authentic Ed25519
    // signatures and thus live in `tests/chain.rs` where ed25519-dalek is
    // a dev-dependency. The unit tests here use StubSigner which is not a
    // real signer; constructing signature-valid pending receipts under it
    // is more work than it's worth.

    // --- H1: Light Sleep ---

    use uniclaw_sleep::{CleanerPass, CleanupError, CleanupReport, LightSleepReport};

    fn light_sleep_report(passes: Vec<CleanerPass>) -> LightSleepReport {
        LightSleepReport { passes }
    }

    #[test]
    fn empty_light_sleep_pass_still_mints_a_receipt() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let out = k
            .handle(KernelEvent::run_light_sleep(LightSleepReport::empty()))
            .expect("ok");

        assert_eq!(out.receipt.body.action.kind, "$kernel/sleep/light");
        assert_eq!(
            out.receipt.body.action.target,
            "cleaners=0 rows=0 bytes=0 failed=0",
        );
        assert_eq!(out.receipt.body.decision, Decision::Allowed);
        assert!(out.receipt.body.constitution_rules.is_empty());
        assert!(out.receipt.body.provenance.is_empty());
        assert_eq!(
            out.kind,
            OutcomeKind::LightSleepCompleted { failed_cleaners: 0 },
        );
        assert!(out.lease_after.is_none());
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 0);
    }

    #[test]
    fn light_sleep_summary_aggregates_per_cleaner_totals() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let report = light_sleep_report(vec![
            CleanerPass {
                name: "store/sessions".into(),
                outcome: Ok(CleanupReport {
                    rows_affected: 5,
                    bytes_reclaimed: 100,
                }),
            },
            CleanerPass {
                name: "budget/leases".into(),
                outcome: Ok(CleanupReport {
                    rows_affected: 3,
                    bytes_reclaimed: 50,
                }),
            },
        ]);

        let out = k.handle(KernelEvent::run_light_sleep(report)).unwrap();
        assert_eq!(
            out.receipt.body.action.target,
            "cleaners=2 rows=8 bytes=150 failed=0",
        );
        assert_eq!(out.receipt.body.provenance.len(), 2);
        assert_eq!(
            out.receipt.body.provenance[0].from,
            "cleaner:store/sessions"
        );
        assert_eq!(out.receipt.body.provenance[0].kind, "light_sleep_pass");
        assert_eq!(out.receipt.body.provenance[1].from, "cleaner:budget/leases");
    }

    #[test]
    fn light_sleep_records_failed_cleaners_in_provenance_and_summary() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let report = light_sleep_report(vec![
            CleanerPass {
                name: "store/sessions".into(),
                outcome: Ok(CleanupReport {
                    rows_affected: 4,
                    bytes_reclaimed: 80,
                }),
            },
            CleanerPass {
                name: "graph/edges".into(),
                outcome: Err(CleanupError::new("lock contention")),
            },
        ]);

        let out = k.handle(KernelEvent::run_light_sleep(report)).unwrap();
        assert_eq!(
            out.receipt.body.action.target,
            "cleaners=2 rows=4 bytes=80 failed=1",
        );
        assert_eq!(
            out.kind,
            OutcomeKind::LightSleepCompleted { failed_cleaners: 1 },
        );

        let failure_edge = &out.receipt.body.provenance[1];
        assert_eq!(failure_edge.kind, "light_sleep_failure");
        assert_eq!(failure_edge.from, "cleaner:graph/edges");
        assert_eq!(failure_edge.to, "error: lock contention");
    }

    #[test]
    fn light_sleep_advances_chain_state_like_any_other_event() {
        let mut k = Kernel::new(
            StubSigner,
            CountingClock {
                counter: Cell::new(0),
            },
            EmptyConstitution,
        );
        let r1 = k.handle(KernelEvent::evaluate(proposal())).unwrap();
        let r2 = k
            .handle(KernelEvent::run_light_sleep(LightSleepReport::empty()))
            .unwrap();

        assert_eq!(r2.receipt.body.merkle_leaf.sequence, 1);
        assert_eq!(
            r2.receipt.body.merkle_leaf.prev_hash,
            r1.receipt.body.merkle_leaf.leaf_hash,
        );
        assert_eq!(k.state().sequence, 2);
    }
}
