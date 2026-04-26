//! Events the kernel state machine consumes.

use alloc::vec::Vec;
use uniclaw_receipt::{Action, Decision, ProvenanceEdge, RuleRef};

/// A proposal awaiting kernel evaluation.
///
/// In the current sketch the caller pre-computes `decision`. Future steps
/// add the Constitution check, policy gate, capability lease, and approval
/// engine — at which point the kernel itself decides and this field becomes
/// advisory only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The action the agent wants to perform.
    pub action: Action,
    /// Pre-computed decision (sketch only).
    pub decision: Decision,
    /// Constitution rules consulted (may be empty in the sketch).
    pub constitution_rules: Vec<RuleRef>,
    /// Provenance edges (may be empty in the sketch).
    pub provenance: Vec<ProvenanceEdge>,
}

/// All events the kernel currently handles.
///
/// Variants we plan to add (in order): `Ingress(InboundMessage)` for channel
/// input, `ApprovalGiven`/`ApprovalDenied` for operator response, `ToolResult`
/// for sandboxed tool completion, and `SleepTick` for scheduler-driven
/// Light/REM/Deep Sleep stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    /// Evaluate a proposal and emit a signed receipt.
    EvaluateProposal(Proposal),
}
