//! Cold receipt explainer for Uniclaw.
//!
//! Given a `Receipt` — and **only** a receipt; no kernel state, no local
//! `KernelOutcome` — produce a human-readable decision tree:
//!
//! - Is the signature authentic?
//! - What action was proposed?
//! - What was the kernel's decision?
//! - Which rules drove that decision (real constitution rules, virtual
//!   `$kernel/budget/*` rules synthesized by the kernel when a capability
//!   lease exhausts, or unknown `$kernel/*` rules from a future runtime)?
//! - What's the receipt's position in the Merkle audit chain?
//!
//! All evidence comes from `Receipt.body.constitution_rules` plus the
//! signature check. This is the cold-verification path: anyone can run
//! `uniclaw-explain` on any receipt without trusting the runtime that
//! produced it.

mod render;

use serde::{Deserialize, Serialize};
use uniclaw_budget::BudgetError;
use uniclaw_receipt::{Action, Decision, MerkleLeaf, Receipt, RuleRef, VerifyError, crypto};

pub use render::{render_json, render_text};

/// A structured explanation of a single receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Explanation {
    /// Lowercase-hex BLAKE3 of the canonical body.
    pub receipt_id: String,
    /// Canonical addressable URL — `uniclaw://receipt/<id>`.
    pub canonical_url: String,
    /// Lowercase-hex Ed25519 issuer public key.
    pub issuer: String,
    /// RFC 3339 issuance timestamp from the receipt body.
    pub issued_at: String,
    /// Did the signature verify?
    pub signature: SignatureStatus,
    /// What the agent tried.
    pub action: ActionInfo,
    /// What the receipt body claims as the decision.
    pub decision: Decision,
    /// Every rule the receipt records, classified.
    pub rules: Vec<RuleEntry>,
    /// The explainer's interpretation of why the decision was reached.
    pub verdict: Verdict,
    /// Position in the Merkle audit chain.
    pub merkle: MerkleInfo,
    /// Optional provenance edges from the receipt.
    pub provenance: Vec<ProvenanceInfo>,
}

/// Outcome of the signature verification step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum SignatureStatus {
    /// The signature verified against the embedded issuer public key.
    Verified,
    /// The signature did not verify. Body should be treated as untrusted.
    Failed(String),
}

/// Compact view of the receipt body's `Action`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionInfo {
    pub kind: String,
    pub target: String,
    pub input_hash: String,
}

impl ActionInfo {
    fn from_action(a: &Action) -> Self {
        Self {
            kind: a.kind.clone(),
            target: a.target.clone(),
            input_hash: hex(&a.input_hash.0),
        }
    }
}

/// One entry in the receipt's `constitution_rules` array, classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEntry {
    /// Stable identifier as recorded in the receipt.
    pub id: String,
    /// Did this rule fire? Reflects `RuleRef.matched`.
    pub matched: bool,
    /// What kind of rule this is.
    pub kind: RuleKind,
}

/// How the explainer interprets a rule's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleKind {
    /// Operator-authored constitution rule (no `$` prefix).
    Constitution,
    /// Virtual rule synthesized by the kernel because a capability lease
    /// exhausted or was revoked.
    KernelBudget { reason: BudgetReasonInfo },
    /// `$kernel/...` rule whose suffix this version of the explainer
    /// doesn't recognize. The runtime that emitted it is newer than this
    /// explainer or uses an extension we haven't catalogued.
    UnknownKernel,
}

/// Decoded view of a `$kernel/budget/<reason>` rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReasonInfo {
    /// Stable short name from `BudgetError::short_name`.
    pub short_name: String,
    /// Human-readable phrase via `BudgetError::Display`. Empty for
    /// unrecognized short names from a newer runtime.
    pub display: String,
}

/// The explainer's interpretation of *why* the kernel decided what it did.
///
/// Distinct from `Decision`: `Decision` is what the receipt body claims;
/// `Verdict` is the explainer's classification of how it got there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verdict {
    /// `Decision::Allowed`. No rule fired and (if a lease was supplied) it
    /// had budget left.
    Allowed { rules_consulted: usize },
    /// `Decision::Denied` driven by an operator-authored constitution rule.
    DeniedByConstitution { rule_id: String },
    /// `Decision::Denied` driven by a `$kernel/budget/*` virtual rule.
    DeniedByBudget { reason: BudgetReasonInfo },
    /// `Decision::Denied` with no matched rules — caller proposed Denied.
    DeniedAsProposed,
    /// `Decision::Approved`. Reserved for the upcoming approval engine.
    Approved,
    /// `Decision::Pending`. Reserved for the upcoming approval engine.
    Pending,
}

/// Summary of the receipt's Merkle leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleInfo {
    pub sequence: u64,
    pub leaf_hash: String,
    pub prev_hash: String,
    /// True when `prev_hash` is all zeros (genesis position).
    pub is_genesis: bool,
}

impl MerkleInfo {
    fn from_leaf(l: &MerkleLeaf) -> Self {
        Self {
            sequence: l.sequence,
            leaf_hash: hex(&l.leaf_hash.0),
            prev_hash: hex(&l.prev_hash.0),
            is_genesis: l.prev_hash.0.iter().all(|b| *b == 0),
        }
    }
}

/// One typed provenance edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceInfo {
    pub from: String,
    pub to: String,
    pub kind: String,
}

/// Build a structured explanation for a receipt.
///
/// Always returns an `Explanation`; signature-failure is reported via the
/// `signature` field rather than as an error so callers can still inspect
/// the body when debugging.
#[must_use]
pub fn explain(receipt: &Receipt) -> Explanation {
    let signature = match crypto::verify(receipt) {
        Ok(()) => SignatureStatus::Verified,
        Err(e) => SignatureStatus::Failed(format_verify_error(&e)),
    };

    let body = &receipt.body;
    let rules: Vec<RuleEntry> = body.constitution_rules.iter().map(classify_rule).collect();
    let verdict = compute_verdict(body.decision, &rules);
    let receipt_id = hex(&receipt.content_id().0);

    Explanation {
        canonical_url: format!("uniclaw://receipt/{receipt_id}"),
        receipt_id,
        issuer: hex(&receipt.issuer.0),
        issued_at: body.issued_at.clone(),
        signature,
        action: ActionInfo::from_action(&body.action),
        decision: body.decision,
        rules,
        verdict,
        merkle: MerkleInfo::from_leaf(&body.merkle_leaf),
        provenance: body
            .provenance
            .iter()
            .map(|e| ProvenanceInfo {
                from: e.from.clone(),
                to: e.to.clone(),
                kind: e.kind.clone(),
            })
            .collect(),
    }
}

/// Classify a single `RuleRef`.
fn classify_rule(r: &RuleRef) -> RuleEntry {
    let kind = if let Some(rest) = r.id.strip_prefix("$kernel/budget/") {
        let info = BudgetError::from_short_name(rest).map_or_else(
            || BudgetReasonInfo {
                short_name: rest.to_string(),
                display: String::new(),
            },
            |e| BudgetReasonInfo {
                short_name: rest.to_string(),
                display: format!("{e}"),
            },
        );
        RuleKind::KernelBudget { reason: info }
    } else if r.id.starts_with('$') {
        RuleKind::UnknownKernel
    } else {
        RuleKind::Constitution
    };
    RuleEntry {
        id: r.id.clone(),
        matched: r.matched,
        kind,
    }
}

/// Decide which `Verdict` best describes how the kernel arrived at `decision`.
fn compute_verdict(decision: Decision, rules: &[RuleEntry]) -> Verdict {
    match decision {
        Decision::Allowed => Verdict::Allowed {
            rules_consulted: rules.len(),
        },
        Decision::Denied => {
            // Look for a matched budget rule first — most specific.
            for r in rules.iter().rev() {
                if r.matched
                    && let RuleKind::KernelBudget { reason } = &r.kind
                {
                    return Verdict::DeniedByBudget {
                        reason: reason.clone(),
                    };
                }
            }
            // Else, the first matched constitution rule.
            for r in rules {
                if r.matched && matches!(r.kind, RuleKind::Constitution) {
                    return Verdict::DeniedByConstitution {
                        rule_id: r.id.clone(),
                    };
                }
            }
            // Nothing matched — caller proposed Denied.
            Verdict::DeniedAsProposed
        }
        Decision::Approved => Verdict::Approved,
        Decision::Pending => Verdict::Pending,
    }
}

fn format_verify_error(e: &VerifyError) -> String {
    format!("{e}")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(nib(b >> 4));
        s.push(nib(b & 0xf));
    }
    s
}

const fn nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use uniclaw_receipt::{
        Digest, ProvenanceEdge, RECEIPT_FORMAT_VERSION, ReceiptBody, RuleRef, crypto,
    };

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn body() -> ReceiptBody {
        ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at: "2026-04-26T12:00:00Z".into(),
            action: Action {
                kind: "http.fetch".into(),
                target: "https://example.com/foo".into(),
                input_hash: Digest([0u8; 32]),
            },
            decision: Decision::Allowed,
            constitution_rules: vec![],
            provenance: vec![ProvenanceEdge {
                from: "user".into(),
                to: "model".into(),
                kind: "request".into(),
            }],
            redactor_stack_hash: None,
            merkle_leaf: MerkleLeaf {
                sequence: 0,
                leaf_hash: Digest([0xAB; 32]),
                prev_hash: Digest([0u8; 32]),
            },
        }
    }

    #[test]
    fn classify_picks_constitution_for_normal_id() {
        let r = RuleRef {
            id: "solo-dev/no-shell".into(),
            matched: true,
        };
        let e = classify_rule(&r);
        assert!(matches!(e.kind, RuleKind::Constitution));
    }

    #[test]
    fn classify_picks_kernel_budget_for_known_short_name() {
        let r = RuleRef {
            id: "$kernel/budget/net_bytes_exhausted".into(),
            matched: true,
        };
        let e = classify_rule(&r);
        let RuleKind::KernelBudget { reason } = e.kind else {
            panic!("expected KernelBudget");
        };
        assert_eq!(reason.short_name, "net_bytes_exhausted");
        assert!(reason.display.contains("net_bytes"));
    }

    #[test]
    fn classify_falls_back_to_unknown_kernel_for_alien_dollar_id() {
        let r = RuleRef {
            id: "$kernel/approval/required".into(),
            matched: true,
        };
        let e = classify_rule(&r);
        assert!(matches!(e.kind, RuleKind::UnknownKernel));
    }

    #[test]
    fn classify_kernel_budget_with_unrecognized_reason_keeps_short_name() {
        let r = RuleRef {
            id: "$kernel/budget/invented_in_the_future".into(),
            matched: true,
        };
        let e = classify_rule(&r);
        let RuleKind::KernelBudget { reason } = e.kind else {
            panic!("expected KernelBudget");
        };
        assert_eq!(reason.short_name, "invented_in_the_future");
        assert!(reason.display.is_empty());
    }

    #[test]
    fn verdict_allowed_when_decision_is_allowed() {
        let v = compute_verdict(Decision::Allowed, &[]);
        assert_eq!(v, Verdict::Allowed { rules_consulted: 0 });
    }

    #[test]
    fn verdict_denied_by_constitution_picks_first_matched_constitution_rule() {
        let rules = vec![
            RuleEntry {
                id: "solo-dev/no-shell".into(),
                matched: true,
                kind: RuleKind::Constitution,
            },
            RuleEntry {
                id: "solo-dev/no-other".into(),
                matched: true,
                kind: RuleKind::Constitution,
            },
        ];
        let v = compute_verdict(Decision::Denied, &rules);
        assert_eq!(
            v,
            Verdict::DeniedByConstitution {
                rule_id: "solo-dev/no-shell".into(),
            },
        );
    }

    #[test]
    fn verdict_denied_by_budget_takes_priority_over_constitution() {
        // If both kinds fire on a Denied receipt, budget wins because it's
        // the more specific reason (kernel synthesized it after a real
        // charge attempt). In practice the kernel short-circuits, so this
        // case doesn't happen, but the explainer must still pick deterministically.
        let rules = vec![
            RuleEntry {
                id: "solo-dev/no-shell".into(),
                matched: true,
                kind: RuleKind::Constitution,
            },
            RuleEntry {
                id: "$kernel/budget/net_bytes_exhausted".into(),
                matched: true,
                kind: RuleKind::KernelBudget {
                    reason: BudgetReasonInfo {
                        short_name: "net_bytes_exhausted".into(),
                        display: "net_bytes budget exhausted".into(),
                    },
                },
            },
        ];
        let v = compute_verdict(Decision::Denied, &rules);
        let Verdict::DeniedByBudget { reason } = v else {
            panic!("expected DeniedByBudget");
        };
        assert_eq!(reason.short_name, "net_bytes_exhausted");
    }

    #[test]
    fn verdict_denied_as_proposed_when_no_matched_rules() {
        let v = compute_verdict(Decision::Denied, &[]);
        assert_eq!(v, Verdict::DeniedAsProposed);
    }

    #[test]
    fn explain_full_pipeline_on_signed_allowed_receipt() {
        let r = crypto::sign(body(), &key());
        let exp = explain(&r);
        assert!(matches!(exp.signature, SignatureStatus::Verified));
        assert_eq!(exp.decision, Decision::Allowed);
        assert!(matches!(exp.verdict, Verdict::Allowed { .. }));
        assert!(exp.canonical_url.starts_with("uniclaw://receipt/"));
        assert_eq!(exp.merkle.sequence, 0);
        assert!(exp.merkle.is_genesis);
        assert_eq!(exp.provenance.len(), 1);
    }

    #[test]
    fn explain_reports_signature_failed_for_tampered_body() {
        let mut r = crypto::sign(body(), &key());
        r.body.action.target = "https://evil.example/".into();
        let exp = explain(&r);
        assert!(matches!(exp.signature, SignatureStatus::Failed(_)));
        // Decision and verdict still reflect the (untrusted) body — the
        // signature field is the "do not trust" flag.
        assert_eq!(exp.decision, Decision::Allowed);
    }
}
