//! `CapabilityLease` — a charged-against budget with delegation semantics.

use serde::{Deserialize, Serialize};

use crate::budget::{Budget, ResourceUse};
use crate::error::BudgetError;

/// 16-byte opaque lease identifier.
///
/// Callers are responsible for uniqueness. Production runtimes generate
/// these from a cryptographic RNG; tests use fixed bytes for
/// reproducibility. The kernel never inspects the contents — only equality
/// via the `parent` chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub [u8; 16]);

impl LeaseId {
    /// All-zero id, useful as a default in tests.
    pub const ZERO: Self = Self([0u8; 16]);
}

/// A capability with a numeric budget. Charges deplete `consumed`;
/// delegation reserves a chunk of the parent's remaining capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLease {
    /// Stable identifier.
    pub id: LeaseId,
    /// Total grant.
    pub budget: Budget,
    /// Cumulative consumption to date.
    pub consumed: ResourceUse,
    /// Parent lease id, if this lease was delegated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<LeaseId>,
    /// True if revoked. A revoked lease rejects every charge.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub revoked: bool,
}

impl CapabilityLease {
    /// Construct a fresh root lease at zero consumption.
    #[must_use]
    pub const fn new(id: LeaseId, budget: Budget) -> Self {
        Self {
            id,
            budget,
            consumed: ResourceUse::ZERO,
            parent: None,
            revoked: false,
        }
    }

    /// Remaining capacity = `budget - consumed` (saturating).
    #[must_use]
    pub fn remaining(&self) -> Budget {
        Budget {
            net_bytes: self
                .budget
                .net_bytes
                .saturating_sub(self.consumed.net_bytes),
            file_writes: self
                .budget
                .file_writes
                .saturating_sub(self.consumed.file_writes),
            llm_tokens: self
                .budget
                .llm_tokens
                .saturating_sub(self.consumed.llm_tokens),
            wall_ms: self.budget.wall_ms.saturating_sub(self.consumed.wall_ms),
            max_uses: self.budget.max_uses.saturating_sub(self.consumed.uses),
        }
    }

    /// Try to charge `amount` against this lease.
    ///
    /// On success, `consumed` is updated and `Ok(())` is returned.
    /// On failure, `consumed` is **not** modified and a `BudgetError`
    /// names the specific resource that would have overflowed.
    pub fn try_charge(&mut self, amount: &ResourceUse) -> Result<(), BudgetError> {
        if self.revoked {
            return Err(BudgetError::Revoked);
        }
        let remaining = self.remaining();
        if amount.net_bytes > remaining.net_bytes {
            return Err(BudgetError::NetBytesExhausted);
        }
        if amount.file_writes > remaining.file_writes {
            return Err(BudgetError::FileWritesExhausted);
        }
        if amount.llm_tokens > remaining.llm_tokens {
            return Err(BudgetError::LlmTokensExhausted);
        }
        if amount.wall_ms > remaining.wall_ms {
            return Err(BudgetError::WallTimeExhausted);
        }
        if amount.uses > remaining.max_uses {
            return Err(BudgetError::UsesExhausted);
        }
        self.consumed = self.consumed.saturating_add(*amount);
        Ok(())
    }

    /// Carve a child lease from this lease's remaining capacity.
    ///
    /// Reservation semantics: the parent's `consumed` is increased by the
    /// child's full budget at delegation time. The child runs against its
    /// own pool; the parent cannot reuse those resources until the child
    /// returns, expires, or is revoked. This guarantees a delegated agent
    /// can never exceed the parent's remaining budget at the time of
    /// delegation.
    ///
    /// # Errors
    ///
    /// Returns `BudgetError::DelegationExceedsParent` if any field of
    /// `child_budget` exceeds the parent's remaining capacity. Returns
    /// `BudgetError::Revoked` if the parent has been revoked.
    pub fn delegate(
        &mut self,
        child_id: LeaseId,
        child_budget: Budget,
    ) -> Result<CapabilityLease, BudgetError> {
        if self.revoked {
            return Err(BudgetError::Revoked);
        }
        let reservation = child_budget.as_use();
        let remaining = self.remaining();
        if reservation.net_bytes > remaining.net_bytes
            || reservation.file_writes > remaining.file_writes
            || reservation.llm_tokens > remaining.llm_tokens
            || reservation.wall_ms > remaining.wall_ms
            || reservation.uses > remaining.max_uses
        {
            return Err(BudgetError::DelegationExceedsParent);
        }
        self.consumed = self.consumed.saturating_add(reservation);
        Ok(CapabilityLease {
            id: child_id,
            budget: child_budget,
            consumed: ResourceUse::ZERO,
            parent: Some(self.id),
            revoked: false,
        })
    }

    /// Revoke this lease. All future charges and delegations fail.
    pub const fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(net: u64, files: u32, tokens: u32, wall: u64, uses: u32) -> Budget {
        Budget {
            net_bytes: net,
            file_writes: files,
            llm_tokens: tokens,
            wall_ms: wall,
            max_uses: uses,
        }
    }

    fn u(net: u64, files: u32, tokens: u32, wall: u64, uses: u32) -> ResourceUse {
        ResourceUse {
            net_bytes: net,
            file_writes: files,
            llm_tokens: tokens,
            wall_ms: wall,
            uses,
        }
    }

    #[test]
    fn fresh_lease_has_zero_consumption_and_full_remaining() {
        let lease = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        assert_eq!(lease.consumed, ResourceUse::ZERO);
        assert_eq!(lease.remaining(), b(100, 5, 1000, 30_000, 10));
        assert!(!lease.revoked);
        assert!(lease.parent.is_none());
    }

    #[test]
    fn try_charge_within_budget_succeeds_and_deducts() {
        let mut lease = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        lease.try_charge(&u(40, 1, 100, 5_000, 1)).unwrap();
        assert_eq!(lease.remaining(), b(60, 4, 900, 25_000, 9));
    }

    #[test]
    fn try_charge_does_not_modify_consumed_on_failure() {
        let mut lease = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        let before = lease.consumed;
        let err = lease
            .try_charge(&u(200, 0, 0, 0, 0))
            .expect_err("should fail");
        assert_eq!(err, BudgetError::NetBytesExhausted);
        assert_eq!(
            lease.consumed, before,
            "consumed must be unchanged on failure"
        );
    }

    #[test]
    fn each_resource_exhaustion_reports_specifically() {
        // Tight budget; charge each field above its limit individually.
        let make = || CapabilityLease::new(LeaseId::ZERO, b(10, 1, 10, 10, 1));
        assert_eq!(
            make().try_charge(&u(11, 0, 0, 0, 0)),
            Err(BudgetError::NetBytesExhausted),
        );
        assert_eq!(
            make().try_charge(&u(0, 2, 0, 0, 0)),
            Err(BudgetError::FileWritesExhausted),
        );
        assert_eq!(
            make().try_charge(&u(0, 0, 11, 0, 0)),
            Err(BudgetError::LlmTokensExhausted),
        );
        assert_eq!(
            make().try_charge(&u(0, 0, 0, 11, 0)),
            Err(BudgetError::WallTimeExhausted),
        );
        assert_eq!(
            make().try_charge(&u(0, 0, 0, 0, 2)),
            Err(BudgetError::UsesExhausted),
        );
    }

    #[test]
    fn delegation_carves_from_parent_and_grants_child_pool() {
        let mut parent = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        let child = parent
            .delegate(LeaseId([1u8; 16]), b(40, 2, 400, 10_000, 4))
            .unwrap();
        // Parent debited upfront (reservation).
        assert_eq!(parent.remaining(), b(60, 3, 600, 20_000, 6));
        // Child has its own pool.
        assert_eq!(child.budget, b(40, 2, 400, 10_000, 4));
        assert_eq!(child.consumed, ResourceUse::ZERO);
        assert_eq!(child.parent, Some(LeaseId::ZERO));
    }

    #[test]
    fn delegation_fails_when_child_exceeds_parents_remaining() {
        let mut parent = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        // Eat most of the parent first.
        parent.try_charge(&u(80, 0, 0, 0, 0)).unwrap();
        assert_eq!(parent.remaining().net_bytes, 20);
        // Now delegate more than 20 bytes — must fail.
        let err = parent
            .delegate(LeaseId([1u8; 16]), b(25, 0, 0, 0, 0))
            .expect_err("must fail");
        assert_eq!(err, BudgetError::DelegationExceedsParent);
        // Parent unchanged.
        assert_eq!(parent.remaining().net_bytes, 20);
    }

    #[test]
    fn child_cannot_charge_more_than_its_own_pool() {
        let mut parent = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        let mut child = parent
            .delegate(LeaseId([1u8; 16]), b(40, 0, 0, 0, 4))
            .unwrap();
        // Child's budget is 40, even though parent had 60 left at this point.
        assert_eq!(
            child.try_charge(&u(50, 0, 0, 0, 1)),
            Err(BudgetError::NetBytesExhausted),
        );
        // But up to the child's own budget is fine.
        child.try_charge(&u(40, 0, 0, 0, 1)).unwrap();
    }

    #[test]
    fn revoked_lease_rejects_charges_and_delegation() {
        let mut lease = CapabilityLease::new(LeaseId::ZERO, b(100, 5, 1000, 30_000, 10));
        lease.revoke();
        assert_eq!(
            lease.try_charge(&u(1, 0, 0, 0, 0)),
            Err(BudgetError::Revoked)
        );
        assert_eq!(
            lease.delegate(LeaseId([1u8; 16]), b(1, 0, 0, 0, 0)),
            Err(BudgetError::Revoked),
        );
    }
}
