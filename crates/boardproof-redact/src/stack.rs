//! [`RedactorStack`] — apply N redactors in sequence; aggregate.

use std::sync::Arc;

use boardproof_receipt::{Digest, RedactionReport, RuleMatch};

use crate::redactor::{RedactionResult, Redactor};

/// Composition of multiple [`Redactor`]s. Applied in order;
/// each successor sees the output of the previous one.
///
/// The stack itself is a [`Redactor`] — composition is
/// recursive. Nested stacks work, though the only common
/// pattern is a single flat stack.
///
/// # Stack hash convention
///
/// `stack_hash` commits to the ordered list of redactor IDs:
/// BLAKE3 over `id1 + "\n" + id2 + "\n" + …`. Two stacks with
/// the same redactor IDs in the same order produce the same
/// hash regardless of which concrete [`Redactor`] impl backs
/// each ID — this means audit-side correlation between
/// `redactor_stack_hash` and the operator's published config
/// works at the level of "ID list," not "rule list." Operators
/// who want stricter commitments should encode rule details
/// into the redactor ID itself (e.g. `"default-2026-05-08"`).
pub struct RedactorStack {
    id: String,
    redactors: Vec<Arc<dyn Redactor>>,
}

impl core::fmt::Debug for RedactorStack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedactorStack")
            .field("id", &self.id)
            .field(
                "redactors",
                &self.redactors.iter().map(|r| r.id()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl RedactorStack {
    /// Build a stack with explicit redactors. The list order is
    /// the application order.
    pub fn new(id: impl Into<String>, redactors: Vec<Arc<dyn Redactor>>) -> Self {
        Self {
            id: id.into(),
            redactors,
        }
    }

    /// Number of redactors in the stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.redactors.len()
    }

    /// True when the stack has no redactors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.redactors.is_empty()
    }

    /// Stable hash committing to the ordered list of redactor IDs.
    /// This is what populates [`boardproof_receipt::RedactionReport::stack_hash`]
    /// when the stack runs.
    #[must_use]
    pub fn stack_hash(&self) -> Digest {
        let mut canonical = String::with_capacity(self.id.len() + self.redactors.len() * 16);
        canonical.push_str(&self.id);
        canonical.push('\n');
        for r in &self.redactors {
            canonical.push_str(r.id());
            canonical.push('\n');
        }
        Digest(*blake3::hash(canonical.as_bytes()).as_bytes())
    }
}

impl Redactor for RedactorStack {
    fn id(&self) -> &str {
        &self.id
    }

    fn redact(&self, bytes: &[u8]) -> RedactionResult {
        let stack_hash = self.stack_hash();

        // Walk the stack. Each successor operates on the
        // previous result's redacted_bytes.
        let mut current_bytes: Vec<u8> = bytes.to_vec();
        let mut all_matches: Vec<RuleMatch> = Vec::new();

        for r in &self.redactors {
            let res = r.redact(&current_bytes);
            current_bytes = res.redacted_bytes;
            all_matches.extend(res.report.matches);
        }

        let redacted_output_hash = Digest(*blake3::hash(&current_bytes).as_bytes());

        RedactionResult {
            redacted_bytes: current_bytes,
            report: RedactionReport {
                redacted_output_hash,
                matches: all_matches,
                stack_hash,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::PatternRedactor;

    #[test]
    fn empty_stack_passes_input_through() {
        let stack = RedactorStack::new("empty", vec![]);
        let result = stack.redact(b"hello");
        assert_eq!(result.redacted_bytes, b"hello");
        assert!(result.report.matches.is_empty());
    }

    #[test]
    fn single_redactor_stack_aggregates_matches() {
        let inner: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("default"));
        let stack = RedactorStack::new("v0", vec![inner]);
        let input = b"k=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = stack.redact(input);
        assert_eq!(result.report.matches.len(), 1);
        assert!(result.report.matches[0].rule_id.ends_with("::github_pat"));
    }

    #[test]
    fn stack_hash_includes_stack_id() {
        let r: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("default"));
        let s1 = RedactorStack::new("v0", vec![Arc::clone(&r)]);
        let s2 = RedactorStack::new("v1", vec![Arc::clone(&r)]);
        assert_ne!(s1.stack_hash(), s2.stack_hash());
    }

    #[test]
    fn stack_hash_includes_redactor_order() {
        let a: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("a"));
        let b: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("b"));
        let s1 = RedactorStack::new("v0", vec![Arc::clone(&a), Arc::clone(&b)]);
        let s2 = RedactorStack::new("v0", vec![Arc::clone(&b), Arc::clone(&a)]);
        assert_ne!(s1.stack_hash(), s2.stack_hash());
    }

    #[test]
    fn stack_hash_uses_redactor_ids_not_pointer_identity() {
        // Two structurally-identical PatternRedactors with the
        // same id should produce the same stack hash, even if
        // they're separate allocations.
        let a: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("default"));
        let b: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("default"));
        let s1 = RedactorStack::new("v0", vec![a]);
        let s2 = RedactorStack::new("v0", vec![b]);
        assert_eq!(s1.stack_hash(), s2.stack_hash());
    }

    #[test]
    fn stack_redactor_id_is_used_in_redact_output() {
        // The stack's redact() returns a report whose stack_hash
        // matches stack_hash() (sanity).
        let r: Arc<dyn Redactor> = Arc::new(PatternRedactor::with_defaults("default"));
        let stack = RedactorStack::new("v0", vec![r]);
        let result = stack.redact(b"hello");
        assert_eq!(result.report.stack_hash, stack.stack_hash());
    }

    #[test]
    fn second_redactor_sees_first_redactors_output() {
        // First redactor: matches `foo`, replaces with literal
        // `MARKER_FROM_FIRST` (no `[REDACTED:` shape so the
        // second redactor's marker-detector rule sees it cleanly).
        // Second redactor: matches `bar`, AND also matches
        // `MARKER_FROM_FIRST` — proving it sees the post-first
        // state. The second redactor's match count for the
        // marker rule is the proof.
        let first = PatternRedactor::with_rules(
            "first",
            vec![
                crate::pattern::PatternRule::new("foo_rule", r"foo", "MARKER_FROM_FIRST").unwrap(),
            ],
        );
        let second = PatternRedactor::with_rules(
            "second",
            vec![
                pattern_rule_default("bar_rule", r"bar"),
                pattern_rule_default("from_first_observer", r"MARKER_FROM_FIRST"),
            ],
        );
        let stack = RedactorStack::new("v0", vec![Arc::new(first), Arc::new(second)]);

        let input = b"foo and bar are friends";
        let result = stack.redact(input);
        let out = String::from_utf8(result.redacted_bytes).unwrap();

        // Original-shape tokens are gone (looking at the input
        // context — `bar` followed by ` are` proves the literal
        // got replaced). Doing a plain `!out.contains("bar")`
        // fails because the rule_id `bar_rule` itself contains
        // `bar` and lands in the replacement marker.
        assert!(!out.contains("foo and"));
        assert!(!out.contains("bar are"));
        // The first redactor's marker is gone too — the second
        // redactor saw it and replaced it.
        assert!(!out.contains("MARKER_FROM_FIRST"));

        // All three rule matches recorded.
        let ids: Vec<&str> = result
            .report
            .matches
            .iter()
            .map(|m| m.rule_id.as_str())
            .collect();
        assert!(ids.iter().any(|id| id.ends_with("::foo_rule")));
        assert!(ids.iter().any(|id| id.ends_with("::bar_rule")));
        assert!(ids.iter().any(|id| id.ends_with("::from_first_observer")));
    }

    fn pattern_rule_default(id: &str, pattern: &str) -> crate::pattern::PatternRule {
        crate::pattern::PatternRule::with_default_replacement(id, pattern).unwrap()
    }
}
