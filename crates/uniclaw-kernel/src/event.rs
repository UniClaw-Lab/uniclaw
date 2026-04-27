//! Events the kernel state machine consumes.

use alloc::vec::Vec;

use uniclaw_approval::ApprovalDecision;
use uniclaw_budget::{CapabilityLease, ResourceUse};
use uniclaw_receipt::{Action, Decision, ProvenanceEdge, Receipt, RuleRef};
use uniclaw_sleep::LightSleepReport;

/// A proposal awaiting kernel evaluation.
///
/// In the current sketch the caller pre-computes `decision`. The kernel
/// then resolves the **final** decision through a fixed pipeline:
///
/// 1. Constitution check (`Constitution::evaluate`) — may force `Denied`
///    or `Pending`.
/// 2. Budget check (`CapabilityLease::try_charge`) — only when the
///    constitution did not force `Pending`. May force `Denied`.
/// 3. The receipt records the final decision and the matched rules.
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
    /// Optional capability lease this proposal will be charged against.
    /// `None` means budgets are not enforced for this call.
    pub lease: Option<CapabilityLease>,
    /// Resources this proposal consumes when it executes. Charged against
    /// `lease` if one is supplied — but only at `Allowed` / `Approved`
    /// time, never at `Pending`.
    pub charge: ResourceUse,
}

impl Proposal {
    /// Construct a proposal that does not enforce budgets.
    #[must_use]
    pub fn unbounded(
        action: Action,
        decision: Decision,
        constitution_rules: Vec<RuleRef>,
        provenance: Vec<ProvenanceEdge>,
    ) -> Self {
        Self {
            action,
            decision,
            constitution_rules,
            provenance,
            lease: None,
            charge: ResourceUse::ZERO,
        }
    }

    /// Construct a proposal that charges `charge` against `lease`.
    #[must_use]
    pub fn with_lease(
        action: Action,
        decision: Decision,
        constitution_rules: Vec<RuleRef>,
        provenance: Vec<ProvenanceEdge>,
        lease: CapabilityLease,
        charge: ResourceUse,
    ) -> Self {
        Self {
            action,
            decision,
            constitution_rules,
            provenance,
            lease: Some(lease),
            charge,
        }
    }
}

/// Operator's response to a previously-emitted `Pending` receipt.
///
/// The kernel does not store pending state. The caller is responsible for
/// holding both the original `Pending` receipt **and** the original
/// `Proposal` and resubmitting them when the operator decides. The kernel
/// verifies authenticity (signature + issuer match + decision == Pending +
/// action match) before honoring the response.
#[derive(Debug, Clone, PartialEq)]
pub struct Approval {
    /// The original `Pending` receipt this response resolves. Must be
    /// signed by **this** kernel's signing key.
    pub pending_receipt: Receipt,
    /// The original proposal that produced the pending receipt. Its action
    /// must match `pending_receipt.body.action`.
    pub original_proposal: Proposal,
    /// Operator's decision.
    pub response: ApprovalDecision,
}

/// All events the kernel currently handles.
///
/// Both variants are boxed so the enum stays small (one pointer either way)
/// and so adding new event variants of similar size doesn't bloat the
/// stack representation of every `KernelEvent` value.
#[derive(Debug, Clone, PartialEq)]
pub enum KernelEvent {
    /// Evaluate a proposal and emit a signed receipt.
    EvaluateProposal(alloc::boxed::Box<Proposal>),
    /// Resolve a previously-emitted `Pending` receipt with an operator
    /// decision. Mints a final `Approved` / `Denied` receipt that links
    /// to the pending one via a provenance edge.
    ResolveApproval(alloc::boxed::Box<Approval>),
    /// Record a completed Light Sleep cleanup pass (master plan §16.3.1).
    /// Mints a single receipt summarizing what each cleaner did, with one
    /// provenance edge per cleaner. The orchestration of the pass itself
    /// happens in `uniclaw-sleep::run_light_sleep`; the kernel only signs
    /// the audit receipt.
    RunLightSleep(alloc::boxed::Box<LightSleepReport>),
}

impl KernelEvent {
    /// Convenience constructor: `KernelEvent::evaluate(p)` instead of
    /// `KernelEvent::EvaluateProposal(Box::new(p))`.
    #[must_use]
    pub fn evaluate(p: Proposal) -> Self {
        Self::EvaluateProposal(alloc::boxed::Box::new(p))
    }

    /// Convenience constructor: `KernelEvent::resolve(a)` instead of
    /// `KernelEvent::ResolveApproval(Box::new(a))`.
    #[must_use]
    pub fn resolve(a: Approval) -> Self {
        Self::ResolveApproval(alloc::boxed::Box::new(a))
    }

    /// Convenience constructor:
    /// `KernelEvent::run_light_sleep(r)` instead of
    /// `KernelEvent::RunLightSleep(Box::new(r))`.
    #[must_use]
    pub fn run_light_sleep(report: LightSleepReport) -> Self {
        Self::RunLightSleep(alloc::boxed::Box::new(report))
    }
}
