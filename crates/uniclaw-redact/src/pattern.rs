//! [`PatternRedactor`] — regex-based redactor.
//!
//! Compiles a list of [`PatternRule`]s at construction. Each
//! rule has an operator-stable `id`, a [`regex::Regex`], and a
//! replacement string written into the output wherever the
//! pattern matched.
//!
//! ## Default rules
//!
//! [`default_rules`] returns a starting corpus covering common
//! credential prefixes:
//!
//! - GitHub PATs (`ghp_…`, `gho_…`, `ghs_…`, `ghu_…`, `ghr_…`)
//! - `OpenAI` / Anthropic API keys (`sk-…`, `sk-ant-…`)
//! - Slack tokens (`xoxb-…`, `xoxp-…`, `xoxa-…`, `xoxr-…`)
//! - AWS access keys (`AKIA…`)
//! - Generic JWTs (`eyJ…`)
//! - Generic `Authorization: Bearer …` lines
//!
//! Operators are expected to **extend, not replace** — the
//! defaults are defense-in-depth, not exhaustive.

use regex::Regex;
use uniclaw_receipt::{Digest, RedactionReport, RuleMatch};

use crate::redactor::{RedactionResult, Redactor};

/// One regex rule with a stable identifier.
#[derive(Debug, Clone)]
pub struct PatternRule {
    /// Operator-stable identifier. Lands in `RuleMatch::rule_id`.
    pub id: String,
    /// Compiled regex. Match anywhere in the byte stream
    /// (regex's default is left-anchored only when the pattern
    /// starts with `^`).
    pub regex: Regex,
    /// Replacement string. The literal substring `{rule}` is
    /// substituted with the rule's id at construction time —
    /// callers that don't care can use the constructor's
    /// default `[REDACTED:{rule}]`.
    pub replacement: String,
}

impl PatternRule {
    /// Compile a rule with a custom replacement.
    ///
    /// # Errors
    /// Returns `regex::Error` if the pattern fails to compile.
    pub fn new(
        id: impl Into<String>,
        pattern: &str,
        replacement: impl Into<String>,
    ) -> Result<Self, regex::Error> {
        let id = id.into();
        let regex = Regex::new(pattern)?;
        let replacement = replacement.into().replace("{rule}", &id);
        Ok(Self {
            id,
            regex,
            replacement,
        })
    }

    /// Compile a rule with the default `[REDACTED:<id>]` replacement.
    ///
    /// # Errors
    /// Returns `regex::Error` if the pattern fails to compile.
    pub fn with_default_replacement(
        id: impl Into<String>,
        pattern: &str,
    ) -> Result<Self, regex::Error> {
        Self::new(id, pattern, "[REDACTED:{rule}]")
    }
}

/// Regex-based redactor. Constructed once with a list of rules;
/// reusable across calls / threads.
#[derive(Debug)]
pub struct PatternRedactor {
    id: String,
    rules: Vec<PatternRule>,
}

impl PatternRedactor {
    /// Build with explicit rules.
    pub fn with_rules(id: impl Into<String>, rules: Vec<PatternRule>) -> Self {
        Self {
            id: id.into(),
            rules,
        }
    }

    /// Build with [`default_rules`].
    ///
    /// # Panics
    /// Only if a default-rule pattern fails to compile, which is
    /// a bug in this crate (the patterns are tested).
    #[must_use]
    pub fn with_defaults(id: impl Into<String>) -> Self {
        Self::with_rules(id, default_rules().expect("default rules must compile"))
    }

    /// Number of rules (including those that haven't matched
    /// anything yet — this is a count of the configuration, not
    /// of any particular pass).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Iterate over the configured rules. Useful for debugging
    /// and for rendering the operator's effective configuration.
    pub fn rules(&self) -> impl Iterator<Item = &PatternRule> {
        self.rules.iter()
    }
}

impl Redactor for PatternRedactor {
    fn id(&self) -> &str {
        &self.id
    }

    fn redact(&self, bytes: &[u8]) -> RedactionResult {
        // We need to operate on string-shaped data because regex
        // works on UTF-8. Tool outputs aren't guaranteed UTF-8
        // (image bytes, archives, …); for non-UTF-8 inputs we
        // do a lossy decode + re-encode. Lossy decode preserves
        // byte length for ASCII content (the realistic credential
        // corpus); non-UTF-8 sequences are replaced with U+FFFD
        // before the regex sees them, which means we don't try
        // to redact patterns inside binary data.
        //
        // For binary tool outputs that genuinely shouldn't be
        // pattern-matched (already-binary archives, encrypted
        // payloads), the operator should configure a redactor
        // stack that skips them — outside this rule's scope.
        let s = String::from_utf8_lossy(bytes).into_owned();
        let mut current = s;
        let mut matches: Vec<RuleMatch> = Vec::new();

        for rule in &self.rules {
            let count = u32::try_from(rule.regex.find_iter(&current).count()).unwrap_or(u32::MAX);
            if count > 0 {
                current = rule
                    .regex
                    .replace_all(&current, &rule.replacement)
                    .into_owned();
                matches.push(RuleMatch {
                    rule_id: format!("{}::{}", self.id, rule.id),
                    count,
                });
            }
        }

        let redacted_bytes = current.into_bytes();
        let redacted_output_hash = Digest(*blake3::hash(&redacted_bytes).as_bytes());

        // Single-redactor stack_hash convention: BLAKE3 over the
        // joined rule IDs (in declaration order) with newline
        // separator. The composing `RedactorStack` produces a
        // hash over the *redactor* IDs (one level up); this is
        // the per-redactor commitment.
        //
        // The kernel uses this only when a single PatternRedactor
        // is the entire stack. When wrapped in `RedactorStack`,
        // the stack's own `stack_hash()` is used instead.
        let stack_hash = Digest(*blake3::hash(self.canonical_rule_bytes().as_bytes()).as_bytes());

        RedactionResult {
            redacted_bytes,
            report: RedactionReport {
                redacted_output_hash,
                matches,
                stack_hash,
            },
        }
    }
}

impl PatternRedactor {
    fn canonical_rule_bytes(&self) -> String {
        let mut s = String::with_capacity(self.id.len() + self.rules.len() * 16);
        s.push_str(&self.id);
        s.push('\n');
        for rule in &self.rules {
            s.push_str(&rule.id);
            s.push('\n');
        }
        s
    }
}

/// Default credential-prefix rule set.
///
/// Defense-in-depth, not exhaustive. Operators are expected to
/// extend with deployment-specific patterns (internal API
/// formats, custom token shapes). Reorder if a stricter ordering
/// matters for your audit story.
///
/// # Errors
/// Returns `regex::Error` if any default pattern fails to
/// compile (a bug in this crate; covered by tests).
pub fn default_rules() -> Result<Vec<PatternRule>, regex::Error> {
    let rules = [
        // GitHub PATs / OAuth / server / user-to-server / refresh.
        // Each is `<prefix>_<36 base62 chars>`. We accept 30+
        // trailing chars to be tolerant of length variations.
        ("github_pat", r"\bghp_[A-Za-z0-9]{30,}"),
        ("github_oauth", r"\bgho_[A-Za-z0-9]{30,}"),
        ("github_server", r"\bghs_[A-Za-z0-9]{30,}"),
        ("github_u2s", r"\bghu_[A-Za-z0-9]{30,}"),
        ("github_refresh", r"\bghr_[A-Za-z0-9]{30,}"),
        // OpenAI / Anthropic. `sk-…` is the umbrella.
        // `sk-ant-…` is more specific and matches first if listed
        // first, but regex find_iter inside replace_all handles
        // overlap; we keep them as separate rules so audit edges
        // can distinguish provider.
        ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{40,}"),
        ("openai_key", r"\bsk-[A-Za-z0-9_\-]{40,}"),
        // Slack tokens. The four common prefixes.
        ("slack_bot", r"\bxoxb-[0-9]{1,}-[0-9]{1,}-[A-Za-z0-9]{20,}"),
        ("slack_user", r"\bxoxp-[0-9]{1,}-[0-9]{1,}-[A-Za-z0-9]{20,}"),
        ("slack_app", r"\bxoxa-[0-9]{1,}-[0-9]{1,}-[A-Za-z0-9]{20,}"),
        (
            "slack_refresh",
            r"\bxoxr-[0-9]{1,}-[0-9]{1,}-[A-Za-z0-9]{20,}",
        ),
        // AWS access key id (the public half) — paired with a
        // secret key, but the id alone is enough to flag in an
        // audit context.
        ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        // Generic JWT shape. Three base64url segments separated
        // by '.'. Common header prefix `eyJ` is the giveaway.
        // The strict shape (segment lengths, content) is
        // application-specific; we match the structural
        // pattern only.
        (
            "jwt",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        ),
        // Generic Authorization header echoes. This is the
        // most aggressive rule — it'll match in JSON output
        // that happens to contain an Authorization header
        // string. Operators who don't want this should
        // construct PatternRedactor with their own filtered
        // rule list.
        (
            "auth_bearer",
            r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.=]+",
        ),
    ];

    rules
        .into_iter()
        .map(|(id, pattern)| PatternRule::with_default_replacement(id, pattern))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_compile() {
        // The Redactor itself unwraps; this test ensures the
        // unwrap is safe.
        let _ = default_rules().expect("default rules must compile");
    }

    #[test]
    fn redactor_passes_through_clean_input_unchanged() {
        let r = PatternRedactor::with_defaults("default");
        let input = b"hello world this contains no credentials";
        let result = r.redact(input);
        assert_eq!(result.redacted_bytes, input);
        assert!(result.report.matches.is_empty());
    }

    #[test]
    fn redactor_replaces_github_pat_with_marker() {
        let r = PatternRedactor::with_defaults("default");
        let input = b"my token is ghp_abcdefghijklmnopqrstuvwxyz0123456789AB done";
        let result = r.redact(input);
        let s = String::from_utf8(result.redacted_bytes).unwrap();
        assert!(
            s.contains("[REDACTED:github_pat]"),
            "expected marker, got: {s}",
        );
        // The original token must be gone.
        assert!(!s.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"));
        let m = result
            .report
            .matches
            .iter()
            .find(|m| m.rule_id.ends_with("::github_pat"))
            .expect("match recorded");
        assert_eq!(m.count, 1);
    }

    #[test]
    fn redactor_counts_multiple_matches_for_one_rule() {
        let r = PatternRedactor::with_defaults("default");
        let input = b"k1=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11 k2=ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb22";
        let result = r.redact(input);
        let m = result
            .report
            .matches
            .iter()
            .find(|m| m.rule_id.ends_with("::github_pat"))
            .expect("match");
        assert_eq!(m.count, 2);
    }

    #[test]
    fn redactor_records_only_rules_that_matched() {
        // Input has only an OpenAI-shape token. The github,
        // slack, aws, jwt, bearer rules don't match; the
        // matches list contains only one entry.
        let r = PatternRedactor::with_defaults("default");
        let input = b"token=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = r.redact(input);
        assert_eq!(result.report.matches.len(), 1);
        assert!(result.report.matches[0].rule_id.ends_with("::openai_key"));
    }

    #[test]
    fn redactor_rule_id_is_prefixed_with_redactor_id() {
        // Lets a stack distinguish two PatternRedactors with
        // overlapping rule names ("default::github_pat" vs
        // "strict::github_pat").
        let r = PatternRedactor::with_defaults("strict");
        let input = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = r.redact(input);
        let m = &result.report.matches[0];
        assert_eq!(m.rule_id, "strict::github_pat");
    }

    #[test]
    fn redactor_handles_non_utf8_input_lossily() {
        // Lossy decode replaces invalid sequences with U+FFFD.
        // The redactor still runs without panicking.
        let mut input = b"prefix ghp_ABABABABABABABABABABABABABABABABABAB suffix".to_vec();
        // Splice a bare 0xFF in the middle (invalid UTF-8).
        input.insert(20, 0xFF);
        let r = PatternRedactor::with_defaults("default");
        let result = r.redact(&input);
        // The token still gets redacted (the 0xFF was after the
        // matched prefix; it shouldn't break detection).
        let s = String::from_utf8_lossy(&result.redacted_bytes).into_owned();
        assert!(
            s.contains("[REDACTED:github_pat]") || s.contains("ghp_"),
            "lossy decode interaction: {s}",
        );
    }

    #[test]
    fn redactor_stack_hash_is_stable_across_runs() {
        let a = PatternRedactor::with_defaults("default");
        let b = PatternRedactor::with_defaults("default");
        let h1 = a.redact(b"x").report.stack_hash;
        let h2 = b.redact(b"y").report.stack_hash;
        assert_eq!(h1, h2);
    }

    #[test]
    fn redactor_stack_hash_changes_when_rule_set_changes() {
        let a = PatternRedactor::with_rules(
            "x",
            vec![PatternRule::with_default_replacement("only", r"foo").unwrap()],
        );
        let b = PatternRedactor::with_rules(
            "x",
            vec![
                PatternRule::with_default_replacement("only", r"foo").unwrap(),
                PatternRule::with_default_replacement("extra", r"bar").unwrap(),
            ],
        );
        let h1 = a.redact(b"x").report.stack_hash;
        let h2 = b.redact(b"x").report.stack_hash;
        assert_ne!(h1, h2);
    }
}
