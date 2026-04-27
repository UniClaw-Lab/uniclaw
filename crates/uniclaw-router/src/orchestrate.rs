//! `evaluate_with_routing` — single-call helper that drives the full
//! `Pending` → `ResolveApproval` flow through an `ApprovalRouter`.

use uniclaw_constitution::Constitution;
use uniclaw_kernel::{
    Approval, Clock, Kernel, KernelError, KernelEvent, KernelOutcome, OutcomeKind, Proposal, Signer,
};

use crate::router::{ApprovalRouter, RouterError};

/// Aggregate failure type for `evaluate_with_routing`.
#[derive(Debug)]
pub enum OrchestrationError {
    /// Kernel rejected an event without minting a receipt — almost always
    /// a bad `ResolveApproval` (forged pending, mismatched issuer, etc.).
    Kernel(KernelError),
    /// Router could not produce a decision.
    Router(RouterError),
}

impl core::fmt::Display for OrchestrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kernel(e) => write!(f, "kernel: {e}"),
            Self::Router(e) => write!(f, "router: {e}"),
        }
    }
}

impl std::error::Error for OrchestrationError {}

impl From<KernelError> for OrchestrationError {
    fn from(e: KernelError) -> Self {
        Self::Kernel(e)
    }
}

impl From<RouterError> for OrchestrationError {
    fn from(e: RouterError) -> Self {
        Self::Router(e)
    }
}

/// Submit `proposal` to `kernel`. If the kernel responds with
/// `OutcomeKind::PendingApproval`, deliver the pending receipt to
/// `router`, then submit the operator's response back to the kernel.
/// Returns the **final** `KernelOutcome` either way.
///
/// If the proposal is approved/denied/budget-exhausted directly (no
/// `Pending` step), the router is **not** called.
///
/// # Errors
///
/// - `OrchestrationError::Kernel` — kernel refused to act on a forged
///   `ResolveApproval` (cannot occur in this flow with our own kernel-signed
///   pending receipts, but is possible if a caller hand-mutates state).
/// - `OrchestrationError::Router` — router could not produce a decision.
pub fn evaluate_with_routing<S, C, K, R>(
    kernel: &mut Kernel<S, C, K>,
    router: &mut R,
    proposal: Proposal,
) -> Result<KernelOutcome, OrchestrationError>
where
    S: Signer,
    C: Clock,
    K: Constitution,
    R: ApprovalRouter,
{
    // Submit the proposal. We clone in case the constitution requires
    // approval; we'll need the original for ResolveApproval.
    let outcome = kernel.handle(KernelEvent::evaluate(proposal.clone()))?;

    // Only the Pending path involves the router. Every other outcome —
    // Allowed, DeniedByConstitution, DeniedByBudget, AllowedAsDenied — is
    // already final and the router is not consulted.
    if outcome.kind != OutcomeKind::PendingApproval {
        return Ok(outcome);
    }

    let pending_receipt = outcome.receipt;
    let response = router.route(&pending_receipt, &proposal)?;

    let approval = Approval {
        pending_receipt,
        original_proposal: proposal,
        response,
    };
    let final_outcome = kernel.handle(KernelEvent::resolve(approval))?;
    Ok(final_outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniclaw_approval::ApprovalDecision;
    use uniclaw_constitution::EmptyConstitution;
    use uniclaw_receipt::{Action, Decision, Digest, RECEIPT_FORMAT_VERSION, Receipt, ReceiptBody};

    /// Test stub signer — produces structurally-valid receipts but with
    /// fake signatures. Adequate for unit tests that don't exercise
    /// signature verification (the kernel's `ResolveApproval` path *does*
    /// verify, so those tests live in `tests/round_trip.rs` with a real
    /// Ed25519 signer).
    struct StubSigner;
    impl Signer for StubSigner {
        fn sign(&self, body: ReceiptBody) -> Receipt {
            Receipt {
                version: RECEIPT_FORMAT_VERSION,
                body,
                issuer: uniclaw_receipt::PublicKey([0xAA; 32]),
                signature: uniclaw_receipt::Signature([0xBB; 64]),
            }
        }
        fn public_key(&self) -> uniclaw_receipt::PublicKey {
            uniclaw_receipt::PublicKey([0xAA; 32])
        }
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now_iso8601(&self) -> String {
            "2026-04-27T00:00:00Z".to_string()
        }
    }

    /// Mock router that always returns the same canned decision and
    /// records every call.
    struct MockRouter {
        canned: Result<ApprovalDecision, RouterError>,
        calls: u32,
    }
    impl ApprovalRouter for MockRouter {
        fn route(
            &mut self,
            _pending: &Receipt,
            _original: &Proposal,
        ) -> Result<ApprovalDecision, RouterError> {
            self.calls += 1;
            self.canned.clone()
        }
    }

    fn benign_proposal() -> Proposal {
        Proposal::unbounded(
            Action {
                kind: "http.fetch".into(),
                target: "https://example.com/".into(),
                input_hash: Digest([0u8; 32]),
            },
            Decision::Allowed,
            vec![],
            vec![],
        )
    }

    #[test]
    fn allowed_proposal_passes_through_without_calling_router() {
        let mut kernel = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let mut router = MockRouter {
            canned: Ok(ApprovalDecision::Approved),
            calls: 0,
        };
        let outcome = evaluate_with_routing(&mut kernel, &mut router, benign_proposal()).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Allowed);
        assert_eq!(
            router.calls, 0,
            "router must not be called for non-Pending outcomes"
        );
    }

    #[test]
    fn denied_proposal_passes_through_without_calling_router() {
        // Caller pre-proposes Denied; constitution doesn't fire; outcome
        // is AllowedAsDenied, no routing needed.
        let mut kernel = Kernel::new(StubSigner, FixedClock, EmptyConstitution);
        let mut router = MockRouter {
            canned: Ok(ApprovalDecision::Approved),
            calls: 0,
        };
        let mut p = benign_proposal();
        p.decision = Decision::Denied;
        let outcome = evaluate_with_routing(&mut kernel, &mut router, p).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::AllowedAsDenied);
        assert_eq!(router.calls, 0);
    }

    // The two Pending-path orchestrator tests cannot use StubSigner
    // because ResolveApproval verifies the pending receipt's Ed25519
    // signature. They live in `tests/round_trip.rs` with a real signer.
}
