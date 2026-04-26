//! Integration test: drive the kernel with a real Ed25519 signer and verify
//! the chain invariants end-to-end.
//!
//! Properties exercised:
//! - sequence is monotonic starting from zero
//! - each receipt's `prev_hash` matches the previous receipt's `leaf_hash`
//! - every emitted receipt verifies under the kernel's signing key
//! - tampering any byte of any receipt breaks verification

use ed25519_dalek::SigningKey;
use uniclaw_approval::ApprovalDecision;
use uniclaw_budget::{Budget, CapabilityLease, LeaseId, ResourceUse};
use uniclaw_constitution::{
    EmptyConstitution, InMemoryConstitution, MatchClause, Rule, RuleVerdict,
};
use uniclaw_kernel::{
    Approval, ApprovalRejection, Clock, Kernel, KernelError, KernelEvent, OutcomeKind, Proposal,
    Signer,
};
use uniclaw_receipt::{
    Action, Decision, Digest, ProvenanceEdge, Receipt, ReceiptBody, RuleRef, crypto,
};

const N_RECEIPTS: usize = 32;

struct Ed25519Signer(SigningKey);

impl Signer for Ed25519Signer {
    fn sign(&self, body: ReceiptBody) -> Receipt {
        crypto::sign(body, &self.0)
    }

    fn public_key(&self) -> uniclaw_receipt::PublicKey {
        uniclaw_receipt::PublicKey(self.0.verifying_key().to_bytes())
    }
}

struct CountingClock(std::cell::Cell<u32>);

impl Clock for CountingClock {
    fn now_iso8601(&self) -> String {
        let n = self.0.get();
        self.0.set(n + 1);
        format!("2026-04-26T12:{:02}:{:02}Z", n / 60, n % 60)
    }
}

fn make_proposal(i: usize) -> Proposal {
    Proposal::unbounded(
        Action {
            kind: "http.fetch".into(),
            target: format!("https://example.com/{i}"),
            input_hash: Digest([0u8; 32]),
        },
        if i.is_multiple_of(5) {
            Decision::Denied
        } else {
            Decision::Allowed
        },
        vec![RuleRef {
            id: "solo-dev/no-shell-without-approval".into(),
            matched: false,
        }],
        vec![ProvenanceEdge {
            from: "user".into(),
            to: "model".into(),
            kind: "request".into(),
        }],
    )
}

#[test]
fn chain_invariants_hold_over_many_receipts() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        EmptyConstitution,
    );

    let mut receipts = Vec::with_capacity(N_RECEIPTS);
    for i in 0..N_RECEIPTS {
        let outcome = kernel
            .handle(KernelEvent::evaluate(make_proposal(i)))
            .expect("ok");
        receipts.push(outcome.receipt);
    }

    // Sequence is monotonic from 0.
    for (i, r) in receipts.iter().enumerate() {
        assert_eq!(
            r.body.merkle_leaf.sequence, i as u64,
            "receipt {i} has wrong sequence",
        );
    }

    // First receipt's prev_hash is zero (genesis).
    assert_eq!(
        receipts[0].body.merkle_leaf.prev_hash,
        Digest([0u8; 32]),
        "genesis prev_hash must be zero",
    );

    // Each subsequent receipt chains to the previous one.
    for i in 1..receipts.len() {
        assert_eq!(
            receipts[i].body.merkle_leaf.prev_hash,
            receipts[i - 1].body.merkle_leaf.leaf_hash,
            "receipt {i} does not chain to receipt {}",
            i - 1,
        );
    }

    // Every receipt verifies under the kernel's signing key.
    for (i, r) in receipts.iter().enumerate() {
        crypto::verify(r).unwrap_or_else(|e| panic!("receipt {i} failed to verify: {e}"));
    }

    // Final state matches the last receipt.
    assert_eq!(kernel.state().sequence, N_RECEIPTS as u64);
    assert_eq!(
        kernel.state().prev_hash,
        receipts.last().unwrap().body.merkle_leaf.leaf_hash,
    );
}

#[test]
fn tampering_any_receipt_breaks_verification() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        EmptyConstitution,
    );

    let outcome = kernel
        .handle(KernelEvent::evaluate(make_proposal(0)))
        .expect("ok");
    let receipt = outcome.receipt;

    // Mutate the action target after signing — must fail.
    let mut tampered = receipt.clone();
    tampered.body.action.target = "https://evil.example/".into();
    assert!(
        crypto::verify(&tampered).is_err(),
        "tampered body must not verify",
    );

    // Mutate the merkle leaf — must fail.
    let mut tampered_leaf = receipt.clone();
    tampered_leaf.body.merkle_leaf.sequence = 9999;
    assert!(
        crypto::verify(&tampered_leaf).is_err(),
        "tampered merkle_leaf must not verify",
    );

    // Untouched receipt still verifies.
    assert!(crypto::verify(&receipt).is_ok());
}

#[test]
fn resume_state_continues_chain_correctly() {
    let key = SigningKey::from_bytes(&[7u8; 32]);

    // Run 3 receipts, then resume from the resulting state and run 3 more.
    let mut kernel_a = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        EmptyConstitution,
    );
    let mut receipts = Vec::new();
    for i in 0..3 {
        let out = kernel_a
            .handle(KernelEvent::evaluate(make_proposal(i)))
            .expect("ok");
        receipts.push(out.receipt);
    }
    let resumed_state = *kernel_a.state();
    drop(kernel_a);

    let key2 = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel_b = Kernel::resume(
        resumed_state,
        Ed25519Signer(key2),
        CountingClock(std::cell::Cell::new(3)),
        EmptyConstitution,
    );
    for i in 3..6 {
        let out = kernel_b
            .handle(KernelEvent::evaluate(make_proposal(i)))
            .expect("ok");
        receipts.push(out.receipt);
    }

    // Across the resume boundary, the chain still holds.
    for i in 1..receipts.len() {
        assert_eq!(
            receipts[i].body.merkle_leaf.prev_hash,
            receipts[i - 1].body.merkle_leaf.leaf_hash,
            "chain broke at boundary i={i}",
        );
    }
}

#[test]
fn constitution_override_appears_in_signed_receipt() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let constitution = InMemoryConstitution::from_rules(vec![Rule {
        id: "block-shell".into(),
        description: "Block shell.exec".into(),
        verdict: RuleVerdict::Deny,
        match_clause: MatchClause {
            kind: Some("shell.exec".into()),
            target_contains: None,
        },
    }]);

    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        constitution,
    );

    // Caller proposes Allowed; constitution must force Denied.
    let p = Proposal::unbounded(
        Action {
            kind: "shell.exec".into(),
            target: "rm -rf /".into(),
            input_hash: Digest([0u8; 32]),
        },
        Decision::Allowed,
        vec![],
        vec![],
    );

    let outcome = kernel.handle(KernelEvent::evaluate(p)).expect("ok");
    let r = &outcome.receipt;

    // The receipt records the override.
    assert_eq!(
        r.body.decision,
        Decision::Denied,
        "constitution must force Denied"
    );
    assert_eq!(r.body.constitution_rules.len(), 1);
    assert_eq!(r.body.constitution_rules[0].id, "block-shell");

    // The signature is over the post-override body, so it verifies.
    crypto::verify(r).expect("override receipt must verify");

    // Mutating the body's decision back to Allowed would break the chain.
    let mut tampered = r.clone();
    tampered.body.decision = Decision::Allowed;
    assert!(
        crypto::verify(&tampered).is_err(),
        "rolling back the constitution override must break verification",
    );
}

#[test]
fn budget_thread_through_eight_calls_then_exhausts() {
    // Drive the kernel with a real Ed25519 signer, threading a single lease
    // through several proposals. After enough charges the lease exhausts
    // and the kernel mints a Denied receipt that records the budget rule.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        EmptyConstitution,
    );

    // Lease that covers exactly 7 charges of 100 bytes each.
    let mut lease = Some(CapabilityLease::new(
        LeaseId::ZERO,
        Budget {
            net_bytes: 700,
            file_writes: 0,
            llm_tokens: 0,
            wall_ms: 0,
            max_uses: 100,
        },
    ));

    let charge = ResourceUse {
        net_bytes: 100,
        file_writes: 0,
        llm_tokens: 0,
        wall_ms: 0,
        uses: 1,
    };

    let mut allowed_count = 0usize;
    let mut denied_count = 0usize;

    for i in 0..8 {
        let p = Proposal::with_lease(
            Action {
                kind: "http.fetch".into(),
                target: format!("https://example.com/{i}"),
                input_hash: Digest([0u8; 32]),
            },
            Decision::Allowed,
            vec![],
            vec![],
            lease
                .take()
                .expect("lease threaded through every iteration"),
            charge,
        );
        let out = kernel.handle(KernelEvent::evaluate(p)).expect("ok");

        // Every receipt verifies cold regardless of the outcome.
        crypto::verify(&out.receipt).expect("receipt must verify");

        match out.kind {
            OutcomeKind::Allowed => allowed_count += 1,
            OutcomeKind::DeniedByBudget(_) => denied_count += 1,
            other => panic!("unexpected kind on iter {i}: {other:?}"),
        }
        lease = out.lease_after;
    }

    assert_eq!(
        allowed_count, 7,
        "first 7 charges should fit in 700-byte budget"
    );
    assert_eq!(denied_count, 1, "eighth charge must be denied");

    // Final lease has consumed the full budget but no more.
    let final_lease = lease.expect("lease still present after exhaustion");
    assert_eq!(final_lease.consumed.net_bytes, 700);
    assert_eq!(final_lease.remaining().net_bytes, 0);
}

// --- E1: full approval round-trip with real Ed25519 signatures ---

fn require_approval_constitution() -> InMemoryConstitution {
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

fn shell_proposal_with_lease(lease_net: u64) -> Proposal {
    Proposal::with_lease(
        Action {
            kind: "shell.exec".into(),
            target: "ls".into(),
            input_hash: Digest([0u8; 32]),
        },
        Decision::Allowed,
        vec![],
        vec![],
        CapabilityLease::new(
            LeaseId::ZERO,
            Budget {
                net_bytes: lease_net,
                file_writes: 0,
                llm_tokens: 0,
                wall_ms: 0,
                max_uses: 10,
            },
        ),
        ResourceUse {
            net_bytes: 100,
            file_writes: 0,
            llm_tokens: 0,
            wall_ms: 0,
            uses: 1,
        },
    )
}

#[test]
fn approval_flow_approve_path_yields_approved_receipt_chained_via_provenance() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );

    // Step 1: submit shell proposal — constitution forces Pending.
    let pending_out = kernel
        .handle(KernelEvent::evaluate(shell_proposal_with_lease(1000)))
        .expect("ok");
    assert_eq!(pending_out.receipt.body.decision, Decision::Pending);
    assert_eq!(pending_out.kind, OutcomeKind::PendingApproval);
    crypto::verify(&pending_out.receipt).expect("pending receipt signed");

    // Step 2: operator approves. Caller resubmits the original proposal.
    let approval = Approval {
        pending_receipt: pending_out.receipt.clone(),
        original_proposal: shell_proposal_with_lease(1000),
        response: ApprovalDecision::Approved,
    };
    let final_out = kernel.handle(KernelEvent::resolve(approval)).expect("ok");

    // Final receipt: Approved + verifies + chains correctly.
    assert_eq!(final_out.receipt.body.decision, Decision::Approved);
    assert_eq!(final_out.kind, OutcomeKind::ApprovedAfterPending);
    crypto::verify(&final_out.receipt).expect("final receipt signed");
    assert_eq!(
        final_out.receipt.body.merkle_leaf.prev_hash,
        pending_out.receipt.body.merkle_leaf.leaf_hash,
        "final must chain to pending via Merkle prev_hash",
    );

    // Provenance graph carries an explicit edge to the pending receipt.
    let pending_id = pending_out.receipt.content_id();
    let pending_id_hex: String = pending_id
        .0
        .iter()
        .flat_map(|b| [(b >> 4), (b & 0xf)])
        .map(|n| match n {
            0..=9 => (b'0' + n) as char,
            _ => (b'a' + n - 10) as char,
        })
        .collect();
    let edge_target = format!("receipt:{pending_id_hex}");
    assert!(
        final_out
            .receipt
            .body
            .provenance
            .iter()
            .any(|e| e.from == edge_target && e.kind == "approval_response"),
        "final receipt must record approval_response provenance edge",
    );

    // Lease was charged at approve time, not at pending time.
    let after = final_out.lease_after.expect("lease threaded");
    assert_eq!(after.consumed.net_bytes, 100);
}

#[test]
fn approval_flow_deny_path_yields_denied_receipt_with_operator_rule() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );

    let pending_out = kernel
        .handle(KernelEvent::evaluate(shell_proposal_with_lease(1000)))
        .expect("ok");

    let approval = Approval {
        pending_receipt: pending_out.receipt,
        original_proposal: shell_proposal_with_lease(1000),
        response: ApprovalDecision::Denied,
    };
    let final_out = kernel.handle(KernelEvent::resolve(approval)).expect("ok");

    assert_eq!(final_out.receipt.body.decision, Decision::Denied);
    assert_eq!(final_out.kind, OutcomeKind::DeniedByOperator);

    let ids: Vec<&str> = final_out
        .receipt
        .body
        .constitution_rules
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert!(ids.contains(&"$kernel/approval/denied_by_operator"));

    // Operator-denied: lease not charged.
    let after = final_out.lease_after.expect("lease threaded");
    assert_eq!(after.consumed.net_bytes, 0);
}

#[test]
fn approval_flow_approved_but_budget_exhausted_yields_denied_with_budget_reason() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );

    // Pending proposal with a big lease.
    let pending_out = kernel
        .handle(KernelEvent::evaluate(shell_proposal_with_lease(1000)))
        .expect("ok");

    // ...but at approve time, the lease the caller resubmits is exhausted.
    // (Simulates the lease being spent down on other actions in the
    // meantime — the caller is responsible for the lease's state across
    // events.)
    let mut nearly_exhausted = CapabilityLease::new(
        LeaseId::ZERO,
        Budget {
            net_bytes: 100,
            file_writes: 0,
            llm_tokens: 0,
            wall_ms: 0,
            max_uses: 10,
        },
    );
    // Pre-charge it so only 50 bytes remain — the proposal needs 100.
    nearly_exhausted
        .try_charge(&ResourceUse {
            net_bytes: 50,
            file_writes: 0,
            llm_tokens: 0,
            wall_ms: 0,
            uses: 1,
        })
        .unwrap();
    let approval = Approval {
        pending_receipt: pending_out.receipt,
        original_proposal: Proposal::with_lease(
            Action {
                kind: "shell.exec".into(),
                target: "ls".into(),
                input_hash: Digest([0u8; 32]),
            },
            Decision::Allowed,
            vec![],
            vec![],
            nearly_exhausted,
            ResourceUse {
                net_bytes: 100,
                file_writes: 0,
                llm_tokens: 0,
                wall_ms: 0,
                uses: 1,
            },
        ),
        response: ApprovalDecision::Approved,
    };
    let final_out = kernel.handle(KernelEvent::resolve(approval)).expect("ok");

    assert_eq!(final_out.receipt.body.decision, Decision::Denied);
    assert!(matches!(
        final_out.kind,
        OutcomeKind::DeniedByBudgetAtApproveTime(_),
    ));
}

#[test]
fn approval_flow_rejects_forged_pending_receipt() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );

    // Real pending receipt.
    let pending_out = kernel
        .handle(KernelEvent::evaluate(shell_proposal_with_lease(1000)))
        .expect("ok");

    // Tamper with the body — signature no longer verifies.
    let mut forged = pending_out.receipt.clone();
    forged.body.action.target = "evil-command".into();

    let approval = Approval {
        pending_receipt: forged,
        original_proposal: shell_proposal_with_lease(1000),
        response: ApprovalDecision::Approved,
    };
    let err = kernel
        .handle(KernelEvent::resolve(approval))
        .expect_err("forged pending must be rejected");
    assert_eq!(
        err,
        KernelError::ResolveApprovalRejected(ApprovalRejection::PendingSignatureInvalid),
    );

    // Kernel state did NOT advance — sequence is still 1 (after the
    // initial pending mint), not 2.
    assert_eq!(kernel.state().sequence, 1);
}

#[test]
fn approval_flow_rejects_pending_signed_by_different_kernel() {
    let our_key = SigningKey::from_bytes(&[7u8; 32]);
    let other_key = SigningKey::from_bytes(&[9u8; 32]);

    // The "other" kernel mints a Pending receipt.
    let mut other_kernel = Kernel::new(
        Ed25519Signer(other_key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );
    let foreign_pending = other_kernel
        .handle(KernelEvent::evaluate(shell_proposal_with_lease(1000)))
        .expect("ok")
        .receipt;

    // Our kernel refuses to resolve a foreign pending.
    let mut our_kernel = Kernel::new(
        Ed25519Signer(our_key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );
    let approval = Approval {
        pending_receipt: foreign_pending,
        original_proposal: shell_proposal_with_lease(1000),
        response: ApprovalDecision::Approved,
    };
    let err = our_kernel
        .handle(KernelEvent::resolve(approval))
        .expect_err("foreign pending must be rejected");
    assert_eq!(
        err,
        KernelError::ResolveApprovalRejected(ApprovalRejection::PendingIssuerMismatch),
    );
}

#[test]
fn approval_flow_rejects_when_action_doesnt_match_pending() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        require_approval_constitution(),
    );

    let pending_out = kernel
        .handle(KernelEvent::evaluate(shell_proposal_with_lease(1000)))
        .expect("ok");

    let mut wrong_proposal = shell_proposal_with_lease(1000);
    wrong_proposal.action.target = "different-action".into();

    let approval = Approval {
        pending_receipt: pending_out.receipt,
        original_proposal: wrong_proposal,
        response: ApprovalDecision::Approved,
    };
    let err = kernel
        .handle(KernelEvent::resolve(approval))
        .expect_err("action mismatch must be rejected");
    assert_eq!(
        err,
        KernelError::ResolveApprovalRejected(ApprovalRejection::ActionMismatch),
    );
}

#[test]
fn approval_flow_rejects_when_receipt_isnt_pending() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut kernel = Kernel::new(
        Ed25519Signer(key),
        CountingClock(std::cell::Cell::new(0)),
        EmptyConstitution,
    );

    // Mint an Allowed receipt — not Pending.
    let allowed = kernel
        .handle(KernelEvent::evaluate(make_proposal(0)))
        .expect("ok")
        .receipt;

    let approval = Approval {
        pending_receipt: allowed,
        original_proposal: make_proposal(0),
        response: ApprovalDecision::Approved,
    };
    let err = kernel
        .handle(KernelEvent::resolve(approval))
        .expect_err("non-Pending receipt must be rejected");
    assert_eq!(
        err,
        KernelError::ResolveApprovalRejected(ApprovalRejection::NotAPendingReceipt),
    );
}
