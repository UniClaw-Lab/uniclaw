//! Kernel outcome — what flows out of `Kernel::handle()`.

use uniclaw_budget::{BudgetError, CapabilityLease};
use uniclaw_receipt::Receipt;

/// Result of a kernel event.
#[derive(Debug, Clone)]
pub struct KernelOutcome {
    /// Signed receipt the event produced. Always present in v0 — every
    /// state-mutating event mints one (master plan §24.6).
    pub receipt: Receipt,
    /// Post-charge state of the proposal's capability lease, if one was
    /// supplied. Caller threads this into the next `Proposal::lease` to
    /// continue using the lease. `None` if the proposal was unbounded.
    pub lease_after: Option<CapabilityLease>,
    /// Detailed explanation of how the decision was reached. The receipt
    /// is the cold-verifiable artifact; this enum is the runtime's
    /// machine-readable trail used by `uniclaw explain`.
    pub kind: OutcomeKind,
}

/// How the kernel arrived at the receipt's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// Proposal passed every gate; the receipt's decision is the caller's
    /// proposed decision.
    Allowed,
    /// The Constitution forced `Decision::Denied`.
    DeniedByConstitution,
    /// The capability lease was exhausted or revoked.
    DeniedByBudget(BudgetError),
    /// The caller proposed `Denied`; nothing else needed to fire.
    AllowedAsDenied,
}
