//! Rule types — the data shape of a constitution loaded from TOML.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use uniclaw_receipt::Action;

/// Top-level structure of a constitution TOML file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionDoc {
    /// Human-readable name of the constitution.
    pub title: String,
    /// Schema version of the constitution document.
    pub version: u32,
    /// Ordered list of rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// A single constitution rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable identifier, e.g. `"solo-dev/no-shell"`.
    pub id: String,
    /// One-line description suitable for receipts and explain output.
    pub description: String,
    /// What this rule does when its match clause fires.
    pub verdict: RuleVerdict,
    /// Conditions that must all be true for the rule to fire.
    #[serde(rename = "match", default)]
    pub match_clause: MatchClause,
}

/// Outcome a rule asserts when it matches.
///
/// v0 ships `Deny` and `RequireApproval`. `Allow` (whitelist) arrives if
/// concrete demand for it surfaces — most rule libraries are deny-list
/// shaped, so allow-list verdicts have not been needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    /// Force `Decision::Denied` for this action. Strongest verdict —
    /// always wins over `RequireApproval` if both fire on the same action.
    Deny,
    /// Force `Decision::Pending` so an operator must respond via a
    /// `ResolveApproval` event before the action proceeds. Yields to
    /// `Deny` if a deny rule also fires (safe-by-default).
    RequireApproval,
}

/// Match conditions. **All present fields must match** for the rule to fire.
/// An empty match clause matches every action.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MatchClause {
    /// Exact-match against `action.kind` (e.g. `"shell.exec"`, `"http.post"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Substring that must appear in `action.target`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_contains: Option<String>,
}

impl MatchClause {
    /// Does this clause match the given action?
    #[must_use]
    pub fn matches(&self, action: &Action) -> bool {
        if let Some(kind) = &self.kind
            && action.kind != *kind
        {
            return false;
        }
        if let Some(needle) = &self.target_contains
            && !action.target.contains(needle.as_str())
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniclaw_receipt::Digest;

    fn action(kind: &str, target: &str) -> Action {
        Action {
            kind: kind.into(),
            target: target.into(),
            input_hash: Digest([0u8; 32]),
        }
    }

    #[test]
    fn empty_clause_matches_everything() {
        let clause = MatchClause::default();
        assert!(clause.matches(&action("shell.exec", "ls")));
        assert!(clause.matches(&action("http.post", "https://example.com/")));
    }

    #[test]
    fn kind_filter_is_exact() {
        let clause = MatchClause {
            kind: Some("shell.exec".into()),
            target_contains: None,
        };
        assert!(clause.matches(&action("shell.exec", "anything")));
        assert!(!clause.matches(&action("shell.eval", "anything"))); // not a prefix match
        assert!(!clause.matches(&action("http.post", "anything")));
    }

    #[test]
    fn target_contains_is_substring() {
        let clause = MatchClause {
            kind: None,
            target_contains: Some("stripe.com".into()),
        };
        assert!(clause.matches(&action("http.post", "https://api.stripe.com/v1/charges")));
        assert!(clause.matches(&action("any", "stripe.com")));
        assert!(!clause.matches(&action("any", "https://api.example.com/")));
    }

    #[test]
    fn both_fields_must_match_when_present() {
        let clause = MatchClause {
            kind: Some("http.post".into()),
            target_contains: Some("stripe.com".into()),
        };
        // both match
        assert!(clause.matches(&action("http.post", "https://api.stripe.com/v1")));
        // kind matches, target doesn't
        assert!(!clause.matches(&action("http.post", "https://example.com/")));
        // target matches, kind doesn't
        assert!(!clause.matches(&action("http.get", "https://api.stripe.com/v1")));
    }
}
