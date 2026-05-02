//! Kernel outcome — what flows out of `Kernel::handle()`.

use uniclaw_budget::{BudgetError, CapabilityLease};
use uniclaw_receipt::{Digest, Receipt};

/// Result of a kernel event that produced a receipt.
#[derive(Debug, Clone)]
pub struct KernelOutcome {
    /// Signed receipt the event produced.
    pub receipt: Receipt,
    /// Post-charge state of the proposal's capability lease, if one was
    /// supplied. Caller threads this into the next `Proposal::lease` to
    /// continue using the lease. `None` if the proposal was unbounded or
    /// if the event was a `ResolveApproval` that didn't carry a lease.
    pub lease_after: Option<CapabilityLease>,
    /// Detailed explanation of how the decision was reached. The receipt
    /// is the cold-verifiable artifact; this enum is the runtime's
    /// machine-readable trail used by `uniclaw explain` and similar tools.
    pub kind: OutcomeKind,
}

/// How the kernel arrived at the receipt's decision.
///
/// All variants describe a successfully-minted receipt. Rejected events
/// (forged pending receipts, action mismatches, etc.) surface as
/// `KernelError`, not as an `OutcomeKind` — they don't produce receipts
/// and don't advance the audit chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// Proposal passed every gate; the receipt's decision is `Allowed`.
    Allowed,
    /// The Constitution forced `Decision::Denied`.
    DeniedByConstitution,
    /// The capability lease was exhausted or revoked at evaluation time.
    DeniedByBudget(BudgetError),
    /// The caller proposed `Denied`; nothing else needed to fire.
    AllowedAsDenied,
    /// The Constitution forced `Decision::Pending` — the receipt is
    /// awaiting an operator response via `KernelEvent::ResolveApproval`.
    PendingApproval,
    /// Operator responded `Approved` to a previously-pending action and
    /// the budget check at resolve time succeeded. Final decision is
    /// `Approved`.
    ApprovedAfterPending,
    /// Operator responded `Denied` to a previously-pending action.
    DeniedByOperator,
    /// Operator responded `Approved`, but the lease had exhausted in the
    /// meantime. Final decision is `Denied` with the budget reason.
    DeniedByBudgetAtApproveTime(BudgetError),
    /// A Light Sleep pass completed and the kernel minted its receipt.
    /// `failed_cleaners` counts cleaners that returned an error during
    /// the pass — they are recorded in the receipt's provenance edges
    /// but do not turn the outcome into a denial; Light Sleep is
    /// best-effort.
    LightSleepCompleted { failed_cleaners: usize },
    /// A Deep Sleep integrity walk completed and the kernel minted its
    /// receipt. `failed_walkers` counts walkers that returned an error
    /// (including walkers that *detected* tampering — that is the
    /// expected path, not a kernel error). Failures appear in the
    /// receipt's provenance edges; the kernel does not act on them,
    /// leaving response policy to the caller.
    DeepSleepCompleted { failed_walkers: usize },
    /// A tool executed successfully and the kernel minted the
    /// `$kernel/tool/executed` receipt that records its input + output
    /// hashes. The full output bytes never enter the kernel — only the
    /// `output_hash` makes it into the audit chain.
    ToolExecutedAllowed {
        input_hash: Digest,
        output_hash: Digest,
    },
    /// A tool ran but reported failure. The kernel minted a
    /// `$kernel/tool/executed` receipt with the error in the
    /// provenance edge (so audit readers see what went wrong) but
    /// the full message stays out of the `OutcomeKind` so this enum
    /// can remain `Copy`.
    ToolExecutedFailed { input_hash: Digest },
}

/// Reasons the kernel can refuse to act on an event without minting a
/// receipt.
///
/// `KernelError` deliberately covers only the cases where producing a
/// receipt would be wrong — typically because the input is forged or
/// inconsistent and we don't want to anchor an attacker's noise into the
/// audit chain. Honest rejections (constitution deny, budget exhausted)
/// always mint a receipt; they're outcomes, not errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    /// `ResolveApproval` was submitted with a pending receipt that didn't
    /// pass authenticity checks. See `ApprovalRejection` for which check
    /// failed.
    ResolveApprovalRejected(ApprovalRejection),
    /// `RecordToolExecution` was submitted but failed the authenticity
    /// gate. See [`ToolExecutionRejection`] for which check failed.
    RecordToolExecutionRejected(ToolExecutionRejection),
}

impl core::fmt::Display for KernelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ResolveApprovalRejected(r) => {
                write!(f, "resolve-approval rejected: {r}")
            }
            Self::RecordToolExecutionRejected(r) => {
                write!(f, "record-tool-execution rejected: {r}")
            }
        }
    }
}

impl core::error::Error for KernelError {}

/// Why a `ResolveApproval` event was refused without producing a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalRejection {
    /// Pending receipt's Ed25519 signature did not verify.
    PendingSignatureInvalid,
    /// Pending receipt was signed by a different kernel — not us.
    PendingIssuerMismatch,
    /// Pending receipt's body decision is not `Pending`.
    NotAPendingReceipt,
    /// `original_proposal.action` does not match `pending_receipt.body.action`.
    ActionMismatch,
}

impl core::fmt::Display for ApprovalRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PendingSignatureInvalid => "pending receipt signature did not verify",
            Self::PendingIssuerMismatch => "pending receipt was signed by a different issuer",
            Self::NotAPendingReceipt => "receipt body decision is not Pending",
            Self::ActionMismatch => {
                "original proposal action does not match pending receipt action"
            }
        })
    }
}

/// Why a `RecordToolExecution` event was refused without producing a
/// receipt. Mirrors [`ApprovalRejection`]'s shape — the same
/// authenticity-gate pattern, just for tool executions instead of
/// approval responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecutionRejection {
    /// `allowed_receipt`'s Ed25519 signature did not verify.
    AllowedSignatureInvalid,
    /// `allowed_receipt` was signed by a different kernel — not us.
    AllowedIssuerMismatch,
    /// `allowed_receipt`'s body decision is not `Allowed` — we don't
    /// record tool executions for proposals that were `Denied`,
    /// `Pending`, or anything else. The execution lifecycle requires
    /// a clean approve-then-execute pair.
    NotAnAllowedReceipt,
    /// `allowed_receipt.body.action.kind` doesn't start with `"tool."`.
    /// Defends against the audit chain accumulating "tool execution"
    /// records for actions that weren't tool calls in the first place.
    NotAToolAction,
    /// `original_proposal.action` does not match
    /// `allowed_receipt.body.action`. Defends against an attacker
    /// substituting a different proposal while keeping a valid prior
    /// receipt.
    ActionMismatch,
}

impl core::fmt::Display for ToolExecutionRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AllowedSignatureInvalid => "allowed receipt signature did not verify",
            Self::AllowedIssuerMismatch => "allowed receipt was signed by a different issuer",
            Self::NotAnAllowedReceipt => "receipt body decision is not Allowed",
            Self::NotAToolAction => "action.kind does not start with \"tool.\"",
            Self::ActionMismatch => {
                "original proposal action does not match allowed receipt action"
            }
        })
    }
}
