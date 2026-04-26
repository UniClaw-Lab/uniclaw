//! Concrete `Constitution` implementations.

use alloc::vec::Vec;

use uniclaw_receipt::{Action, Decision, RuleRef};

use crate::rule::{ConstitutionDoc, Rule, RuleVerdict};
use crate::verdict::{Constitution, ConstitutionVerdict};

/// No-rules constitution. Equivalent to: every action passes unchallenged.
///
/// Useful for tests, bare-bones deployments, and as an explicit signal
/// that the runtime has no policy of its own. Even `EmptyConstitution`
/// goes through `Kernel::handle` so receipts always carry an explicit
/// "constitution consulted, nothing matched" record.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyConstitution;

impl Constitution for EmptyConstitution {
    fn evaluate(&self, _action: &Action) -> ConstitutionVerdict {
        ConstitutionVerdict::empty()
    }
}

/// A constitution backed by a `Vec<Rule>` evaluated in document order.
#[derive(Debug, Clone)]
pub struct InMemoryConstitution {
    rules: Vec<Rule>,
}

impl InMemoryConstitution {
    /// Construct from a parsed `ConstitutionDoc`.
    #[must_use]
    pub fn from_doc(doc: ConstitutionDoc) -> Self {
        Self { rules: doc.rules }
    }

    /// Construct from a raw rule list.
    #[must_use]
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Inspect the rules. Useful for explain-style introspection tooling.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Constitution for InMemoryConstitution {
    fn evaluate(&self, action: &Action) -> ConstitutionVerdict {
        let mut matched = Vec::new();
        let mut force_deny = false;
        let mut require_approval = false;

        for rule in &self.rules {
            if !rule.match_clause.matches(action) {
                continue;
            }
            matched.push(RuleRef {
                id: rule.id.clone(),
                matched: true,
            });
            match rule.verdict {
                RuleVerdict::Deny => force_deny = true,
                RuleVerdict::RequireApproval => require_approval = true,
            }
        }

        // Precedence: Deny > RequireApproval > pass-through. Deny is the
        // safe-by-default choice: if any rule wants the action stopped
        // outright, that wins over a request for human review.
        let override_decision = if force_deny {
            Some(Decision::Denied)
        } else if require_approval {
            Some(Decision::Pending)
        } else {
            None
        };

        ConstitutionVerdict {
            matched_rules: matched,
            override_decision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use uniclaw_receipt::Digest;

    use crate::rule::{MatchClause, Rule, RuleVerdict};

    fn action(kind: &str, target: &str) -> Action {
        Action {
            kind: kind.into(),
            target: target.into(),
            input_hash: Digest([0u8; 32]),
        }
    }

    fn deny_rule(id: &str, kind: Option<&str>, contains: Option<&str>) -> Rule {
        Rule {
            id: id.into(),
            description: "test rule".into(),
            verdict: RuleVerdict::Deny,
            match_clause: MatchClause {
                kind: kind.map(Into::into),
                target_contains: contains.map(Into::into),
            },
        }
    }

    #[test]
    fn empty_constitution_never_matches() {
        let v = EmptyConstitution.evaluate(&action("shell.exec", "rm -rf /"));
        assert_eq!(v, ConstitutionVerdict::empty());
    }

    #[test]
    fn in_memory_passes_through_when_no_rule_fires() {
        let c = InMemoryConstitution::from_rules(vec![deny_rule(
            "block-shell",
            Some("shell.exec"),
            None,
        )]);
        let v = c.evaluate(&action("http.get", "https://example.com/"));
        assert!(v.matched_rules.is_empty());
        assert_eq!(v.override_decision, None);
    }

    #[test]
    fn in_memory_forces_denied_when_rule_fires() {
        let c = InMemoryConstitution::from_rules(vec![deny_rule(
            "block-shell",
            Some("shell.exec"),
            None,
        )]);
        let v = c.evaluate(&action("shell.exec", "rm -rf /"));
        assert_eq!(v.override_decision, Some(Decision::Denied));
        assert_eq!(v.matched_rules.len(), 1);
        assert_eq!(v.matched_rules[0].id, "block-shell");
        assert!(v.matched_rules[0].matched);
    }

    #[test]
    fn multiple_rules_all_recorded_in_order() {
        let c = InMemoryConstitution::from_rules(vec![
            deny_rule("first", Some("shell.exec"), None),
            deny_rule("second", None, Some("rm")),
        ]);
        let v = c.evaluate(&action("shell.exec", "rm -rf /"));
        assert_eq!(v.matched_rules.len(), 2);
        assert_eq!(v.matched_rules[0].id, "first");
        assert_eq!(v.matched_rules[1].id, "second");
        assert_eq!(v.override_decision, Some(Decision::Denied));
    }

    #[test]
    fn rule_with_empty_match_clause_matches_every_action() {
        let c = InMemoryConstitution::from_rules(vec![Rule {
            id: "panic-mode".into(),
            description: "deny everything".into(),
            verdict: RuleVerdict::Deny,
            match_clause: MatchClause::default(),
        }]);
        let v1 = c.evaluate(&action("shell.exec", "ls"));
        let v2 = c.evaluate(&action("http.get", "https://example.com/"));
        assert_eq!(v1.override_decision, Some(Decision::Denied));
        assert_eq!(v2.override_decision, Some(Decision::Denied));
    }

    fn require_approval_rule(id: &str, kind: &str) -> Rule {
        Rule {
            id: id.into(),
            description: "needs operator review".into(),
            verdict: RuleVerdict::RequireApproval,
            match_clause: MatchClause {
                kind: Some(kind.into()),
                target_contains: None,
            },
        }
    }

    #[test]
    fn require_approval_rule_yields_pending_decision() {
        let c = InMemoryConstitution::from_rules(vec![require_approval_rule(
            "needs-review",
            "shell.exec",
        )]);
        let v = c.evaluate(&action("shell.exec", "ls"));
        assert_eq!(v.override_decision, Some(Decision::Pending));
        assert_eq!(v.matched_rules.len(), 1);
        assert_eq!(v.matched_rules[0].id, "needs-review");
    }

    #[test]
    fn deny_takes_precedence_over_require_approval_on_same_action() {
        // If both verdicts match, Deny wins — safe-by-default.
        let c = InMemoryConstitution::from_rules(vec![
            require_approval_rule("might-be-ok", "shell.exec"),
            deny_rule("absolutely-not", Some("shell.exec"), None),
        ]);
        let v = c.evaluate(&action("shell.exec", "rm -rf /"));
        assert_eq!(v.override_decision, Some(Decision::Denied));
        // Both rules are still recorded in the receipt's audit trail.
        assert_eq!(v.matched_rules.len(), 2);
    }

    #[test]
    fn require_approval_passes_through_when_no_rule_fires() {
        let c = InMemoryConstitution::from_rules(vec![require_approval_rule(
            "shell-needs-review",
            "shell.exec",
        )]);
        let v = c.evaluate(&action("http.get", "https://example.com/"));
        assert!(v.matched_rules.is_empty());
        assert_eq!(v.override_decision, None);
    }
}
