//! Renderers — turn an `Explanation` into terminal text or pretty JSON.

use std::fmt::Write;

use uniclaw_receipt::Decision;

use crate::{Explanation, RuleEntry, RuleKind, SignatureStatus, Verdict};

/// Render the explanation as multi-line plain text.
///
/// No ANSI color, no Unicode beyond box-drawing dashes. Stable enough to
/// snapshot in tests.
#[must_use]
pub fn render_text(e: &Explanation) -> String {
    let mut out = String::new();

    out.push_str("─── Uniclaw Explain ─────────────────────────────────────────\n");
    let _ = writeln!(out, "Receipt    {}", e.canonical_url);
    let _ = writeln!(out, "Issued at  {}", e.issued_at);
    let _ = writeln!(out, "Issuer     {}", e.issuer);
    let _ = writeln!(out, "Signature  {}", render_sig_line(&e.signature));
    out.push('\n');

    if matches!(e.signature, SignatureStatus::Failed(_)) {
        out.push_str("[!] SIGNATURE INVALID — fields below are NOT trustworthy.\n\n");
    }

    let _ = writeln!(out, "Action     {} -> {}", e.action.kind, e.action.target);
    let _ = writeln!(out, "Decision   {}", render_decision(e.decision));
    out.push('\n');

    let _ = writeln!(out, "Rules ({})", e.rules.len());
    if e.rules.is_empty() {
        out.push_str("  (no rules consulted)\n");
    } else {
        for r in &e.rules {
            let _ = writeln!(out, "{}", render_rule_line(r));
        }
    }
    out.push('\n');

    out.push_str("Why\n");
    out.push_str(&render_verdict(&e.verdict));
    out.push('\n');

    if !e.provenance.is_empty() {
        out.push_str("\nProvenance\n");
        for p in &e.provenance {
            let _ = writeln!(out, "  {} -> {}  [{}]", p.from, p.to, p.kind);
        }
    }

    out.push_str("\nMerkle position\n");
    let _ = writeln!(out, "  sequence  {}", e.merkle.sequence);
    let _ = writeln!(out, "  leaf_hash {}", short_hex(&e.merkle.leaf_hash));
    if e.merkle.is_genesis {
        out.push_str("  prev_hash 00...00 (genesis)\n");
    } else {
        let _ = writeln!(out, "  prev_hash {}", short_hex(&e.merkle.prev_hash));
    }

    out
}

/// Render the explanation as pretty-printed JSON. Stable enough to snapshot.
#[must_use]
pub fn render_json(e: &Explanation) -> String {
    serde_json::to_string_pretty(e).expect("Explanation is always serializable")
}

fn render_sig_line(s: &SignatureStatus) -> String {
    match s {
        SignatureStatus::Verified => "verified".into(),
        SignatureStatus::Failed(detail) => format!("FAILED ({detail})"),
    }
}

const fn render_decision(d: Decision) -> &'static str {
    match d {
        Decision::Allowed => "ALLOWED",
        Decision::Denied => "DENIED",
        Decision::Approved => "APPROVED",
        Decision::Pending => "PENDING",
    }
}

fn render_rule_line(r: &RuleEntry) -> String {
    let mark = if r.matched { '+' } else { '-' };
    let tag = match &r.kind {
        RuleKind::Constitution => "constitution".into(),
        RuleKind::KernelBudget { reason } => {
            if reason.display.is_empty() {
                format!("kernel-budget: {}", reason.short_name)
            } else {
                format!("kernel-budget: {}", reason.display)
            }
        }
        RuleKind::KernelApproval { reason } => {
            if reason.display.is_empty() {
                format!("kernel-approval: {}", reason.short_name)
            } else {
                format!("kernel-approval: {}", reason.display)
            }
        }
        RuleKind::UnknownKernel => "kernel-internal".into(),
    };
    let state = if r.matched { "matched" } else { "not matched" };
    format!("  [{mark}] {}  ({tag}, {state})", r.id)
}

fn render_verdict(v: &Verdict) -> String {
    match v {
        Verdict::Allowed { rules_consulted } => {
            if *rules_consulted == 0 {
                "  No rules consulted; no budget exhausted. Action allowed.\n".into()
            } else {
                format!(
                    "  No matched rule blocked the action and no budget was exhausted.\n  ({rules_consulted} rule(s) consulted, none matched.) Action allowed.\n",
                )
            }
        }
        Verdict::DeniedByConstitution { rule_id } => {
            format!("  Denied because constitution rule \"{rule_id}\" matched.\n")
        }
        Verdict::DeniedByBudget { reason } => {
            let phrase = if reason.display.is_empty() {
                format!("budget exhausted ({})", reason.short_name)
            } else {
                reason.display.clone()
            };
            format!("  Denied because the capability lease was exhausted: {phrase}.\n")
        }
        Verdict::DeniedAsProposed => {
            "  Caller proposed Denied; no rule fired and no budget was exhausted.\n  The kernel recorded the proposed decision.\n"
                .into()
        }
        Verdict::Approved => {
            "  Operator approved a previously-pending action.\n  The budget re-check at approve time succeeded; action was Approved.\n".into()
        }
        Verdict::Pending { rules_consulted } => {
            format!(
                "  Constitution required operator review ({rules_consulted} rule(s) consulted).\n  Awaiting a ResolveApproval event to finalize.\n",
            )
        }
        Verdict::DeniedByOperator => {
            "  Operator denied a previously-pending action.\n".into()
        }
    }
}

fn short_hex(s: &str) -> String {
    if s.len() <= 16 {
        s.into()
    } else {
        format!("{}...{}", &s[..8], &s[s.len() - 8..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionInfo, ApprovalReasonInfo, BudgetReasonInfo, MerkleInfo};

    fn sample_explanation(decision: Decision, rules: Vec<RuleEntry>) -> Explanation {
        Explanation {
            receipt_id: "abcdef0123456789".repeat(4),
            canonical_url: "uniclaw://receipt/abc".into(),
            issuer: "f".repeat(64),
            issued_at: "2026-04-26T12:00:00Z".into(),
            signature: SignatureStatus::Verified,
            action: ActionInfo {
                kind: "http.fetch".into(),
                target: "https://example.com/".into(),
                input_hash: "0".repeat(64),
            },
            decision,
            verdict: super::super::compute_verdict(decision, &rules),
            rules,
            merkle: MerkleInfo {
                sequence: 0,
                leaf_hash: "1".repeat(64),
                prev_hash: "0".repeat(64),
                is_genesis: true,
            },
            provenance: vec![],
        }
    }

    #[test]
    fn text_render_for_allowed_contains_action_and_verdict() {
        let e = sample_explanation(Decision::Allowed, vec![]);
        let out = render_text(&e);
        assert!(out.contains("ALLOWED"));
        assert!(out.contains("http.fetch -> https://example.com/"));
        assert!(out.contains("Action allowed"));
        assert!(out.contains("(genesis)"));
    }

    #[test]
    fn text_render_for_denied_by_constitution_names_rule() {
        let rules = vec![RuleEntry {
            id: "solo-dev/no-shell".into(),
            matched: true,
            kind: RuleKind::Constitution,
        }];
        let e = sample_explanation(Decision::Denied, rules);
        let out = render_text(&e);
        assert!(out.contains("DENIED"));
        assert!(out.contains("solo-dev/no-shell"));
        assert!(out.contains("constitution rule"));
    }

    #[test]
    fn text_render_for_denied_by_budget_names_resource() {
        let rules = vec![RuleEntry {
            id: "$kernel/budget/net_bytes_exhausted".into(),
            matched: true,
            kind: RuleKind::KernelBudget {
                reason: BudgetReasonInfo {
                    short_name: "net_bytes_exhausted".into(),
                    display: "net_bytes budget exhausted".into(),
                },
            },
        }];
        let e = sample_explanation(Decision::Denied, rules);
        let out = render_text(&e);
        assert!(out.contains("DENIED"));
        assert!(out.contains("capability lease"));
        assert!(out.contains("net_bytes budget exhausted"));
    }

    #[test]
    fn text_render_marks_invalid_signature_prominently() {
        let mut e = sample_explanation(Decision::Allowed, vec![]);
        e.signature = SignatureStatus::Failed("bad sig".into());
        let out = render_text(&e);
        assert!(out.contains("SIGNATURE INVALID"));
        assert!(out.contains("FAILED"));
        assert!(out.contains("bad sig"));
    }

    #[test]
    fn json_render_round_trips() {
        let e = sample_explanation(Decision::Allowed, vec![]);
        let json = render_json(&e);
        let back: Explanation = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    #[test]
    fn text_render_for_pending_explains_awaiting_approval() {
        let rules = vec![RuleEntry {
            id: "solo-dev/shell-needs-approval".into(),
            matched: true,
            kind: RuleKind::Constitution,
        }];
        let e = sample_explanation(Decision::Pending, rules);
        let out = render_text(&e);
        assert!(out.contains("PENDING"));
        assert!(out.contains("Awaiting"));
        assert!(out.contains("operator review"));
    }

    #[test]
    fn text_render_for_approved_explains_operator_approval() {
        let rules = vec![RuleEntry {
            id: "solo-dev/shell-needs-approval".into(),
            matched: true,
            kind: RuleKind::Constitution,
        }];
        let e = sample_explanation(Decision::Approved, rules);
        let out = render_text(&e);
        assert!(out.contains("APPROVED"));
        assert!(out.contains("Operator approved"));
    }

    #[test]
    fn text_render_for_denied_by_operator_names_operator() {
        let rules = vec![RuleEntry {
            id: "$kernel/approval/denied_by_operator".into(),
            matched: true,
            kind: RuleKind::KernelApproval {
                reason: ApprovalReasonInfo {
                    short_name: "denied_by_operator".into(),
                    display: "operator denied this action".into(),
                },
            },
        }];
        let e = sample_explanation(Decision::Denied, rules);
        let out = render_text(&e);
        assert!(out.contains("DENIED"));
        assert!(out.contains("Operator denied"));
        assert!(out.contains("kernel-approval"));
    }
}
