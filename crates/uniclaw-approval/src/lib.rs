//! Approval engine types for Uniclaw.
//!
//! When a constitution rule fires with `RuleVerdict::RequireApproval`, the
//! kernel mints a `Decision::Pending` receipt and returns control. The
//! caller routes that pending receipt to an operator (via channel-aware
//! routing in a future step) and, when the operator decides, submits a
//! `KernelEvent::ResolveApproval` carrying the operator's
//! [`ApprovalDecision`].
//!
//! v0 ships only the response shape. The pluggable `ApprovalEngine` trait,
//! channel routing (master plan §21 #7), timeout handling, and adaptive
//! promotion (master plan §21 #3) arrive in subsequent steps.

#![cfg_attr(not(test), no_std)]

use serde::{Deserialize, Serialize};

/// Operator's response to a `Pending` receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Operator approved the action. Kernel re-checks budget and either
    /// mints a `Decision::Approved` receipt (action runs) or, if budget
    /// has been exhausted in the meantime, mints `Decision::Denied` with
    /// the existing budget reason.
    Approved,
    /// Operator denied the action. Kernel mints a `Decision::Denied`
    /// receipt with a virtual `$kernel/approval/denied_by_operator` rule
    /// in `constitution_rules` so the receipt is self-explaining.
    Denied,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_decision_serde_round_trips() {
        for d in [ApprovalDecision::Approved, ApprovalDecision::Denied] {
            let s = serde_json::to_string(&d).unwrap();
            let back: ApprovalDecision = serde_json::from_str(&s).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn approval_decision_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ApprovalDecision::Approved).unwrap(),
            r#""approved""#,
        );
        assert_eq!(
            serde_json::to_string(&ApprovalDecision::Denied).unwrap(),
            r#""denied""#,
        );
    }
}
