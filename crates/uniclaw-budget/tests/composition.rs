//! Integration test: delegation chains preserve the budget invariant.
//!
//! For any chain  root → child → grandchild,
//! the sum of all leases' (consumed + remaining) along the live path must
//! never exceed root.budget. Reservation semantics are what make this
//! provable: when root delegates to child, root debits the full child
//! budget upfront, so child's eventual consumption can never spill back
//! into root's pool.

use uniclaw_budget::{Budget, BudgetError, CapabilityLease, LeaseId, ResourceUse};

fn b(net: u64) -> Budget {
    Budget {
        net_bytes: net,
        file_writes: 0,
        llm_tokens: 0,
        wall_ms: 0,
        max_uses: 0,
    }
}

fn u(net: u64) -> ResourceUse {
    ResourceUse {
        net_bytes: net,
        file_writes: 0,
        llm_tokens: 0,
        wall_ms: 0,
        uses: 0,
    }
}

#[test]
fn three_level_chain_respects_budgets() {
    let mut root = CapabilityLease::new(LeaseId::ZERO, b(1000));
    let mut child = root.delegate(LeaseId([1u8; 16]), b(500)).unwrap();
    let mut grandchild = child.delegate(LeaseId([2u8; 16]), b(200)).unwrap();

    // Ledger after delegations:
    //   root.remaining = 1000 - 500 = 500   (child reserved)
    //   child.remaining = 500 - 200 = 300   (grandchild reserved)
    //   grandchild.remaining = 200
    assert_eq!(root.remaining().net_bytes, 500);
    assert_eq!(child.remaining().net_bytes, 300);
    assert_eq!(grandchild.remaining().net_bytes, 200);

    // Grandchild spends within its own pool.
    grandchild.try_charge(&u(150)).unwrap();
    assert_eq!(grandchild.remaining().net_bytes, 50);
    // Child and root unaffected by grandchild's spend (reservation already debited).
    assert_eq!(child.remaining().net_bytes, 300);
    assert_eq!(root.remaining().net_bytes, 500);

    // Grandchild cannot exceed its pool — even though child/root have plenty.
    assert_eq!(
        grandchild.try_charge(&u(100)),
        Err(BudgetError::NetBytesExhausted),
    );
}

#[test]
fn child_revocation_does_not_unreserve_from_parent() {
    // Reservation semantics: revoking a child does NOT credit the parent
    // back. This keeps the budget bookkeeping monotonic and predictable.
    // (Future: a `release` operation can return unused budget; deliberately
    // out of v0 scope.)
    let mut root = CapabilityLease::new(LeaseId::ZERO, b(1000));
    let mut child = root.delegate(LeaseId([1u8; 16]), b(500)).unwrap();
    let root_remaining_before = root.remaining().net_bytes;
    child.revoke();
    let root_remaining_after = root.remaining().net_bytes;
    assert_eq!(
        root_remaining_before, root_remaining_after,
        "revoking a child must not credit the parent in v0",
    );
}

#[test]
fn delegation_at_zero_remaining_fails() {
    let mut root = CapabilityLease::new(LeaseId::ZERO, b(100));
    root.try_charge(&u(100)).unwrap();
    assert_eq!(root.remaining().net_bytes, 0);
    assert_eq!(
        root.delegate(LeaseId([1u8; 16]), b(1)),
        Err(BudgetError::DelegationExceedsParent),
    );
}

#[test]
fn full_delegation_leaves_parent_at_zero() {
    let mut root = CapabilityLease::new(LeaseId::ZERO, b(100));
    let _child = root.delegate(LeaseId([1u8; 16]), b(100)).unwrap();
    assert_eq!(root.remaining().net_bytes, 0);
    // Parent now cannot charge or delegate further.
    assert_eq!(root.try_charge(&u(1)), Err(BudgetError::NetBytesExhausted));
}
