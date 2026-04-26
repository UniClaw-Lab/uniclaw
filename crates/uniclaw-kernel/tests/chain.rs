//! Integration test: drive the kernel with a real Ed25519 signer and verify
//! the chain invariants end-to-end.
//!
//! Properties exercised:
//! - sequence is monotonic starting from zero
//! - each receipt's `prev_hash` matches the previous receipt's `leaf_hash`
//! - every emitted receipt verifies under the kernel's signing key
//! - tampering any byte of any receipt breaks verification

use ed25519_dalek::SigningKey;
use uniclaw_budget::{Budget, CapabilityLease, LeaseId, ResourceUse};
use uniclaw_constitution::{
    EmptyConstitution, InMemoryConstitution, MatchClause, Rule, RuleVerdict,
};
use uniclaw_kernel::{Clock, Kernel, KernelEvent, OutcomeKind, Proposal, Signer};
use uniclaw_receipt::{
    Action, Decision, Digest, ProvenanceEdge, Receipt, ReceiptBody, RuleRef, crypto,
};

const N_RECEIPTS: usize = 32;

struct Ed25519Signer(SigningKey);

impl Signer for Ed25519Signer {
    fn sign(&self, body: ReceiptBody) -> Receipt {
        crypto::sign(body, &self.0)
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
        let outcome = kernel.handle(KernelEvent::EvaluateProposal(make_proposal(i)));
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

    let outcome = kernel.handle(KernelEvent::EvaluateProposal(make_proposal(0)));
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
        let out = kernel_a.handle(KernelEvent::EvaluateProposal(make_proposal(i)));
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
        let out = kernel_b.handle(KernelEvent::EvaluateProposal(make_proposal(i)));
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

    let outcome = kernel.handle(KernelEvent::EvaluateProposal(p));
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
        let out = kernel.handle(KernelEvent::EvaluateProposal(p));

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
