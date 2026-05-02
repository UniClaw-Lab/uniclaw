//! Events the kernel state machine consumes.

use alloc::vec::Vec;

use uniclaw_approval::ApprovalDecision;
use uniclaw_budget::{CapabilityLease, ResourceUse};
use uniclaw_receipt::{Action, Decision, ProvenanceEdge, Receipt, RuleRef};
use uniclaw_sleep::{DeepSleepReport, LightSleepReport};
use uniclaw_tools::{ToolError, ToolOutput};

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

/// External tool execution result, submitted back to the kernel for
/// audit.
///
/// **Lifecycle.** A caller wanting to invoke a tool first submits a
/// `Proposal` whose `action.kind` starts with `"tool."` — the kernel
/// runs Constitution + Budget gates and (if not denied) mints an
/// `Allowed` receipt. The caller then runs the tool externally
/// (typically via [`uniclaw_tools::ToolHost`]), takes the
/// `Result<ToolOutput, ToolError>` back, and submits this struct to
/// the kernel as `KernelEvent::RecordToolExecution`. The kernel
/// runs an authenticity gate against the prior `Allowed` receipt and
/// mints a follow-on receipt with `action.kind = "$kernel/tool/executed"`.
///
/// Same shape as the [`Approval`] flow: the kernel is stateless and
/// synchronous, all external orchestration lives in the caller, the
/// kernel just verifies and anchors.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolExecution {
    /// The previously-`Allowed` proposal receipt that authorized this
    /// tool call. Must be signed by **this** kernel.
    pub allowed_receipt: Receipt,
    /// The original proposal that produced `allowed_receipt`. Its
    /// `action` must match the receipt's recorded action.
    pub original_proposal: Proposal,
    /// What the tool returned (or why it failed). Output bytes are
    /// **not** carried into the kernel — only the precomputed
    /// `output_hash` from the `ToolOutput` makes it into the receipt.
    pub result: Result<ToolOutput, ToolError>,
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
    /// Record a completed Deep Sleep integrity walk (master plan §16.3.3).
    /// Mints a single receipt summarizing each walker's outcome, with one
    /// provenance edge per walker. The orchestration happens in
    /// `uniclaw-sleep::run_deep_sleep`; the kernel only signs the audit
    /// receipt that proves the walk ran and what it found.
    RunDeepSleep(alloc::boxed::Box<DeepSleepReport>),
    /// Record an external tool execution against a previously-`Allowed`
    /// proposal receipt. Mints a `$kernel/tool/executed` receipt with
    /// the tool's input + output hashes in provenance. The actual
    /// tool runs **outside** the kernel; this event just anchors the
    /// result in the audit chain. See [`ToolExecution`].
    RecordToolExecution(alloc::boxed::Box<ToolExecution>),
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

    /// Convenience constructor:
    /// `KernelEvent::run_deep_sleep(r)` instead of
    /// `KernelEvent::RunDeepSleep(Box::new(r))`.
    #[must_use]
    pub fn run_deep_sleep(report: DeepSleepReport) -> Self {
        Self::RunDeepSleep(alloc::boxed::Box::new(report))
    }

    /// Convenience constructor:
    /// `KernelEvent::record_tool_execution(e)` instead of
    /// `KernelEvent::RecordToolExecution(Box::new(e))`.
    #[must_use]
    pub fn record_tool_execution(execution: ToolExecution) -> Self {
        Self::RecordToolExecution(alloc::boxed::Box::new(execution))
    }
}
