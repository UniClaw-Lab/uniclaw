//! Budget operation failures.

/// Reasons a `try_charge` or `delegate` can refuse.
///
/// Each variant names the *specific* resource that ran out so the kernel
/// can surface it in `KernelOutcome::kind` and (eventually) in the receipt's
/// explain output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    /// `net_bytes` would exceed the budget.
    NetBytesExhausted,
    /// `file_writes` would exceed the budget.
    FileWritesExhausted,
    /// `llm_tokens` would exceed the budget.
    LlmTokensExhausted,
    /// `wall_ms` would exceed the budget.
    WallTimeExhausted,
    /// `max_uses` would exceed the budget.
    UsesExhausted,
    /// Child budget at delegation time exceeds parent's remaining capacity.
    DelegationExceedsParent,
    /// The lease was explicitly revoked.
    Revoked,
}

impl BudgetError {
    /// Stable short identifier suitable for receipt explain output, e.g.
    /// `"net_bytes_exhausted"`. Public-URL receipts will surface this.
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::NetBytesExhausted => "net_bytes_exhausted",
            Self::FileWritesExhausted => "file_writes_exhausted",
            Self::LlmTokensExhausted => "llm_tokens_exhausted",
            Self::WallTimeExhausted => "wall_time_exhausted",
            Self::UsesExhausted => "uses_exhausted",
            Self::DelegationExceedsParent => "delegation_exceeds_parent",
            Self::Revoked => "lease_revoked",
        }
    }
}

impl core::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NetBytesExhausted => "net_bytes budget exhausted",
            Self::FileWritesExhausted => "file_writes budget exhausted",
            Self::LlmTokensExhausted => "llm_tokens budget exhausted",
            Self::WallTimeExhausted => "wall_ms budget exhausted",
            Self::UsesExhausted => "max_uses budget exhausted",
            Self::DelegationExceedsParent => "delegated budget exceeds parent's remaining",
            Self::Revoked => "capability lease has been revoked",
        })
    }
}

impl core::error::Error for BudgetError {}
