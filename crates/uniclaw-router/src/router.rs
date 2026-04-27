//! `ApprovalRouter` trait + the typed errors it can return.

use uniclaw_approval::ApprovalDecision;
use uniclaw_kernel::Proposal;
use uniclaw_receipt::Receipt;

/// Anything that can deliver a `Pending` receipt to an operator and return
/// their decision.
///
/// Implementations are **synchronous**. An async wrapper (timeouts, retries,
/// channel backends with network IO) lives in a future runtime crate that
/// composes this trait without changing it.
///
/// The trait takes `&mut self` rather than `&self` so implementations can
/// own buffered IO handles without interior mutability.
pub trait ApprovalRouter {
    /// Present the `Pending` receipt to the operator and return their
    /// decision.
    ///
    /// `pending` is the kernel-signed `Pending` receipt awaiting resolution.
    /// `original_proposal` is the proposal that produced the pending
    /// receipt — passed through so the router can show full context (lease
    /// state, charges, provenance) and so any UI can highlight the
    /// difference between the action requested and the action ultimately
    /// resolved.
    ///
    /// # Errors
    ///
    /// Returns `RouterError` when the response cannot be obtained:
    /// IO failure, operator cancellation, malformed input, or backend
    /// unavailability.
    fn route(
        &mut self,
        pending: &Receipt,
        original_proposal: &Proposal,
    ) -> Result<ApprovalDecision, RouterError>;
}

/// Why a router could not produce an `ApprovalDecision`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterError {
    /// IO error reading from input or writing to output. String detail.
    Io(String),
    /// Operator's input could not be parsed as Approved/Denied after the
    /// router's retry budget was exhausted.
    InvalidInput(String),
    /// Operator declined to respond (e.g., explicit cancel, EOF on stdin).
    Cancelled,
    /// Backend-specific failure (Slack down, email server timeout, …).
    Backend(String),
}

impl core::fmt::Display for RouterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "router IO error: {s}"),
            Self::InvalidInput(s) => write!(f, "router invalid operator input: {s}"),
            Self::Cancelled => f.write_str("router cancelled by operator"),
            Self::Backend(s) => write!(f, "router backend error: {s}"),
        }
    }
}

impl std::error::Error for RouterError {}
