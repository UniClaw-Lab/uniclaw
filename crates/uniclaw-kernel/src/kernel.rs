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
use uniclaw_sleep::{DeepSleepReport, LightSleepReport};

use crate::event::{Approval, KernelEvent, Proposal, ToolExecution};
use crate::leaf::compute_leaf_hash;
use crate::outcome::{
    ApprovalRejection, KernelError, KernelOutcome, OutcomeKind, ToolExecutionRejection,
};
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
            KernelEvent::RunDeepSleep(r) => Ok(self.handle_deep_sleep(&r)),
            KernelEvent::RecordToolExecution(e) => self.handle_record_tool_execution(&e),
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

    fn handle_deep_sleep(&mut self, report: &DeepSleepReport) -> KernelOutcome {
        let issued_at = self.clock.now_iso8601();
        let walker_count = report.walker_count();
        let failed_walkers = report.failed_count();
        let total_items = report.total_items_walked();
        let total_bytes = report.total_bytes_walked();

        let action = Action {
            kind: alloc::string::String::from("$kernel/sleep/deep"),
            target: format!(
                "walkers={walker_count} items={total_items} bytes={total_bytes} failed={failed_walkers}",
            ),
            input_hash: Digest([0u8; 32]),
        };

        // One provenance edge per walker. Successful walkers use
        // `kind = "deep_sleep_pass"` and report counts in `to`; failed
        // walkers (including those that *detected* tampering) use
        // `kind = "deep_sleep_failure"` and put the message in `to`.
        let mut provenance: Vec<ProvenanceEdge> = Vec::with_capacity(walker_count);
        for pass in &report.passes {
            let edge = match &pass.outcome {
                Ok(r) => ProvenanceEdge {
                    from: format!("walker:{}", pass.name),
                    to: format!("items={} bytes={}", r.items_walked, r.bytes_walked),
                    kind: "deep_sleep_pass".into(),
                },
                Err(e) => ProvenanceEdge {
                    from: format!("walker:{}", pass.name),
                    to: format!("error: {}", e.message),
                    kind: "deep_sleep_failure".into(),
                },
            };
            provenance.push(edge);
        }

        let receipt = self.mint(issued_at, action, Decision::Allowed, Vec::new(), provenance);

        KernelOutcome {
            receipt,
            lease_after: None,
            kind: OutcomeKind::DeepSleepCompleted { failed_walkers },
        }
    }

    fn handle_record_tool_execution(
        &mut self,
        e: &ToolExecution,
    ) -> Result<KernelOutcome, KernelError> {
        // --- Authenticity gate (mirrors handle_resolve_approval's gate
        //     exactly; same trust principle: verify a prior receipt is
        //     ours and untampered before anchoring a follow-on entry) ---

        // 1. allowed_receipt's signature verifies under its embedded issuer.
        if crypto::verify(&e.allowed_receipt).is_err() {
            return Err(KernelError::RecordToolExecutionRejected(
                ToolExecutionRejection::AllowedSignatureInvalid,
            ));
        }
        // 2. Issuer must be us — a receipt signed by another kernel
        //    cannot anchor an execution under this kernel's chain.
        if e.allowed_receipt.issuer != self.signer.public_key() {
            return Err(KernelError::RecordToolExecutionRejected(
                ToolExecutionRejection::AllowedIssuerMismatch,
            ));
        }
        // 3. The prior receipt must actually be Allowed. Pending,
        //    Approved, or Denied receipts don't get follow-on
        //    execution records.
        if e.allowed_receipt.body.decision != Decision::Allowed {
            return Err(KernelError::RecordToolExecutionRejected(
                ToolExecutionRejection::NotAnAllowedReceipt,
            ));
        }
        // 4. The action.kind must look like a tool action. We don't
        //    record "tool executions" for http.fetch or shell.exec
        //    proposals — those go through their own paths.
        if !e.allowed_receipt.body.action.kind.starts_with("tool.") {
            return Err(KernelError::RecordToolExecutionRejected(
                ToolExecutionRejection::NotAToolAction,
            ));
        }
        // 5. The original_proposal's action must match the prior
        //    receipt's action. Defends against an attacker substituting
        //    a different proposal while keeping a valid receipt.
        if e.original_proposal.action != e.allowed_receipt.body.action {
            return Err(KernelError::RecordToolExecutionRejected(
                ToolExecutionRejection::ActionMismatch,
            ));
        }

        // --- Mint the execution receipt ---

        let issued_at = self.clock.now_iso8601();
        let allowed_id = e.allowed_receipt.content_id();
        let allowed_id_hex = hex32(&allowed_id.0);
        let tool_action_kind = &e.allowed_receipt.body.action.kind;
        let tool_name = tool_action_kind
            .strip_prefix("tool.")
            .unwrap_or(tool_action_kind);

        // Provenance edges:
        // - Always one edge linking back to the Allowed proposal receipt.
        // - On success: one edge each for the tool input hash and the
        //   tool output hash (so audit readers can query either).
        // - On failure: one edge with the error variant + message.
        let mut provenance: Vec<ProvenanceEdge> = Vec::with_capacity(3);
        provenance.push(ProvenanceEdge {
            from: format!("receipt:{allowed_id_hex}"),
            to: format!("tool:{tool_name}"),
            kind: "tool_execution".into(),
        });

        let (kind, action_target) = match &e.result {
            Ok(output) => {
                let in_hex = hex32(&e.allowed_receipt.body.action.input_hash.0);
                let out_hex = hex32(&output.output_hash.0);
                provenance.push(ProvenanceEdge {
                    from: format!("receipt:{allowed_id_hex}"),
                    to: format!("input:{in_hex}"),
                    kind: "tool_input".into(),
                });
                provenance.push(ProvenanceEdge {
                    from: format!("receipt:{allowed_id_hex}"),
                    to: format!("output:{out_hex}"),
                    kind: "tool_output".into(),
                });
                (
                    OutcomeKind::ToolExecutedAllowed {
                        input_hash: e.allowed_receipt.body.action.input_hash,
                        output_hash: output.output_hash,
                    },
                    format!("tool={tool_name} status=ok"),
                )
            }
            Err(err) => {
                provenance.push(ProvenanceEdge {
                    from: format!("receipt:{allowed_id_hex}"),
                    to: format!("error[{}]: {}", err.variant_name(), err.message()),
                    kind: "tool_execution_failure".into(),
                });
                (
                    OutcomeKind::ToolExecutedFailed {
                        input_hash: e.allowed_receipt.body.action.input_hash,
                    },
                    format!("tool={tool_name} status=failed kind={}", err.variant_name()),
                )
            }
        };

        let action = Action {
            kind: alloc::string::String::from("$kernel/tool/executed"),
            target: action_target,
            input_hash: Digest([0u8; 32]),
        };

        let receipt = self.mint(issued_at, action, Decision::Allowed, Vec::new(), provenance);

        Ok(KernelOutcome {
            receipt,
            lease_after: None,
            kind,
        })
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

    // --- Phase 2 step 11: Deep Sleep ---

    use uniclaw_sleep::{DeepSleepReport, WalkError, WalkReport, WalkerPass};

    fn deep_sleep_report(passes: Vec<WalkerPass>) -> DeepSleepReport {
        DeepSleepReport { passes }
    }

    #[test]
    fn empty_deep_sleep_pass_still_mints_a_receipt() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let out = k
            .handle(KernelEvent::run_deep_sleep(DeepSleepReport::empty()))
            .expect("ok");

        assert_eq!(out.receipt.body.action.kind, "$kernel/sleep/deep");
        assert_eq!(
            out.receipt.body.action.target,
            "walkers=0 items=0 bytes=0 failed=0",
        );
        assert_eq!(out.receipt.body.decision, Decision::Allowed);
        assert!(out.receipt.body.constitution_rules.is_empty());
        assert!(out.receipt.body.provenance.is_empty());
        assert_eq!(
            out.kind,
            OutcomeKind::DeepSleepCompleted { failed_walkers: 0 },
        );
        assert!(out.lease_after.is_none());
        assert_eq!(out.receipt.body.merkle_leaf.sequence, 0);
    }

    #[test]
    fn deep_sleep_summary_aggregates_per_walker_totals() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let report = deep_sleep_report(vec![
            WalkerPass {
                name: "audit/main".into(),
                outcome: Ok(WalkReport {
                    items_walked: 1000,
                    bytes_walked: 64_000,
                }),
            },
            WalkerPass {
                name: "provenance/edges".into(),
                outcome: Ok(WalkReport {
                    items_walked: 500,
                    bytes_walked: 8_000,
                }),
            },
        ]);

        let out = k.handle(KernelEvent::run_deep_sleep(report)).unwrap();
        assert_eq!(
            out.receipt.body.action.target,
            "walkers=2 items=1500 bytes=72000 failed=0",
        );
        assert_eq!(out.receipt.body.provenance.len(), 2);
        assert_eq!(out.receipt.body.provenance[0].from, "walker:audit/main");
        assert_eq!(out.receipt.body.provenance[0].kind, "deep_sleep_pass");
        assert_eq!(out.receipt.body.provenance[0].to, "items=1000 bytes=64000",);
    }

    #[test]
    fn deep_sleep_records_walker_failures_in_provenance_and_summary() {
        let mut k = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let report = deep_sleep_report(vec![
            WalkerPass {
                name: "audit/main".into(),
                outcome: Ok(WalkReport {
                    items_walked: 4,
                    bytes_walked: 0,
                }),
            },
            WalkerPass {
                name: "provenance/edges".into(),
                outcome: Err(WalkError::new("dangling edge from receipt:abc")),
            },
        ]);

        let out = k.handle(KernelEvent::run_deep_sleep(report)).unwrap();
        assert_eq!(
            out.receipt.body.action.target,
            "walkers=2 items=4 bytes=0 failed=1",
        );
        assert_eq!(
            out.kind,
            OutcomeKind::DeepSleepCompleted { failed_walkers: 1 },
        );

        let failure_edge = &out.receipt.body.provenance[1];
        assert_eq!(failure_edge.kind, "deep_sleep_failure");
        assert_eq!(failure_edge.from, "walker:provenance/edges");
        assert_eq!(failure_edge.to, "error: dangling edge from receipt:abc");
    }

    #[test]
    fn deep_sleep_advances_chain_state_like_any_other_event() {
        let mut k = Kernel::new(
            StubSigner,
            CountingClock {
                counter: Cell::new(0),
            },
            EmptyConstitution,
        );
        let r1 = k.handle(KernelEvent::evaluate(proposal())).unwrap();
        let r2 = k
            .handle(KernelEvent::run_deep_sleep(DeepSleepReport::empty()))
            .unwrap();
        assert_eq!(r2.receipt.body.merkle_leaf.sequence, 1);
        assert_eq!(
            r2.receipt.body.merkle_leaf.prev_hash,
            r1.receipt.body.merkle_leaf.leaf_hash,
        );
        assert_eq!(k.state().sequence, 2);
    }
}
