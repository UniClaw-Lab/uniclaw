//! Integration tests: drive the orchestrator end-to-end with a real
//! Ed25519-signing kernel and a CLI router whose stdio is mocked.

use std::io::Cursor;

use ed25519_dalek::SigningKey;
use uniclaw_approval::ApprovalDecision;
use uniclaw_constitution::{
    EmptyConstitution, InMemoryConstitution, MatchClause, Rule, RuleVerdict,
};
use uniclaw_kernel::{Clock, Kernel, OutcomeKind, Proposal, Signer};
use uniclaw_receipt::{Action, Decision, Digest, Receipt, ReceiptBody, crypto};
use uniclaw_router::{ApprovalRouter, CliApprovalRouter, RouterError, evaluate_with_routing};

struct Ed25519Signer(SigningKey);
impl Signer for Ed25519Signer {
    fn sign(&self, body: ReceiptBody) -> Receipt {
        crypto::sign(body, &self.0)
    }
    fn public_key(&self) -> uniclaw_receipt::PublicKey {
        uniclaw_receipt::PublicKey(self.0.verifying_key().to_bytes())
    }
}

struct CountingClock(std::cell::Cell<u32>);
impl Clock for CountingClock {
    fn now_iso8601(&self) -> String {
        let n = self.0.get();
        self.0.set(n + 1);
        format!("2026-04-27T12:{:02}:{:02}Z", n / 60, n % 60)
    }
}

fn require_approval_constitution() -> InMemoryConstitution {
    InMemoryConstitution::from_rules(vec![Rule {
        id: "test/shell-needs-approval".into(),
        description: "shell needs review".into(),
        verdict: RuleVerdict::RequireApproval,
        match_clause: MatchClause {
            kind: Some("shell.exec".into()),
            target_contains: None,
        },
    }])
}

fn shell_proposal() -> Proposal {
    Proposal::unbounded(
        Action {
            kind: "shell.exec".into(),
            target: "ls -la".into(),
            input_hash: Digest([0u8; 32]),
        },
        Decision::Allowed,
        vec![],
        vec![],
    )
}

fn fresh_kernel<C: uniclaw_constitution::Constitution>(
    constitution: C,
) -> Kernel<Ed25519Signer, CountingClock, C> {
    Kernel::new(
        Ed25519Signer(SigningKey::from_bytes(&[7u8; 32])),
        CountingClock(std::cell::Cell::new(0)),
        constitution,
    )
}

#[test]
fn pending_then_operator_approves_yields_signed_approved_receipt() {
    let mut kernel = fresh_kernel(require_approval_constitution());
    let mut router = CliApprovalRouter::new(Cursor::new(b"y\n".to_vec()), Vec::<u8>::new());

    let outcome = evaluate_with_routing(&mut kernel, &mut router, shell_proposal())
        .expect("orchestration must succeed");

    // Final receipt: Approved + verifies cold.
    assert_eq!(outcome.receipt.body.decision, Decision::Approved);
    assert_eq!(outcome.kind, OutcomeKind::ApprovedAfterPending);
    crypto::verify(&outcome.receipt).expect("final receipt signed");

    // Provenance edge confirms the receipt links back to the pending one.
    assert!(
        outcome
            .receipt
            .body
            .provenance
            .iter()
            .any(|e| e.kind == "approval_response" && e.from.starts_with("receipt:")),
        "final receipt must record approval_response provenance edge",
    );

    // Operator's prompt reached stdout via the router.
    let stdout = String::from_utf8(router.output().clone()).unwrap();
    assert!(stdout.contains("Pending action requires your approval"));
    assert!(stdout.contains("shell.exec"));
    assert!(stdout.contains("ls -la"));
    assert!(stdout.contains("→ approved"));
}

#[test]
fn pending_then_operator_denies_yields_signed_denied_receipt() {
    let mut kernel = fresh_kernel(require_approval_constitution());
    let mut router = CliApprovalRouter::new(Cursor::new(b"n\n".to_vec()), Vec::<u8>::new());

    let outcome = evaluate_with_routing(&mut kernel, &mut router, shell_proposal())
        .expect("orchestration must succeed");

    assert_eq!(outcome.receipt.body.decision, Decision::Denied);
    assert_eq!(outcome.kind, OutcomeKind::DeniedByOperator);
    crypto::verify(&outcome.receipt).expect("final receipt signed");

    // Receipt is self-explaining: virtual operator-denied rule appears.
    let ids: Vec<&str> = outcome
        .receipt
        .body
        .constitution_rules
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert!(ids.contains(&"$kernel/approval/denied_by_operator"));
}

#[test]
fn allowed_proposal_does_not_invoke_router_at_all() {
    // Use EmptyConstitution so the proposal goes straight to Allowed.
    let mut kernel = fresh_kernel(EmptyConstitution);

    // Router with EOF stdin — would error if called.
    let mut router = CliApprovalRouter::new(Cursor::new(Vec::<u8>::new()), Vec::<u8>::new());

    let outcome = evaluate_with_routing(
        &mut kernel,
        &mut router,
        Proposal::unbounded(
            Action {
                kind: "http.fetch".into(),
                target: "https://example.com/".into(),
                input_hash: Digest([0u8; 32]),
            },
            Decision::Allowed,
            vec![],
            vec![],
        ),
    )
    .expect("ok");

    assert_eq!(outcome.kind, OutcomeKind::Allowed);
    // Stdout must be empty: router was never called.
    assert!(router.output().is_empty(), "router must not be called");
}

#[test]
fn router_error_on_pending_propagates_as_orchestration_error() {
    /// Always-fail router.
    struct FailingRouter;
    impl ApprovalRouter for FailingRouter {
        fn route(
            &mut self,
            _pending: &Receipt,
            _original: &Proposal,
        ) -> Result<ApprovalDecision, RouterError> {
            Err(RouterError::Cancelled)
        }
    }

    let mut kernel = fresh_kernel(require_approval_constitution());
    let mut router = FailingRouter;
    let err = evaluate_with_routing(&mut kernel, &mut router, shell_proposal())
        .expect_err("router error must propagate");
    assert!(format!("{err}").contains("router cancelled"));
}
