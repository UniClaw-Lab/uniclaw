//! Events the kernel state machine consumes.

use alloc::vec::Vec;

use uniclaw_budget::{CapabilityLease, ResourceUse};
use uniclaw_receipt::{Action, Decision, ProvenanceEdge, RuleRef};

/// A proposal awaiting kernel evaluation.
///
/// In the current sketch the caller pre-computes `decision`. The kernel
/// then resolves the **final** decision through a fixed pipeline:
///
/// 1. Constitution check (`Constitution::evaluate`) — may force `Denied`.
/// 2. Budget check (`CapabilityLease::try_charge`) — may force `Denied`.
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
    #[doc(hidden)] // documented at the field level via clippy/rustdoc
    pub lease: Option<CapabilityLease>,
    /// Resources this proposal consumes when it executes. Charged against
    /// `lease` if one is supplied.
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

/// All events the kernel currently handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    /// Evaluate a proposal and emit a signed receipt.
    EvaluateProposal(Proposal),
}
