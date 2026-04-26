//! Load constitutions from TOML.

use alloc::string::String;
use alloc::string::ToString;

use crate::evaluator::InMemoryConstitution;
use crate::rule::ConstitutionDoc;

/// Why a constitution failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable reason. Today: thin pass-through of the underlying
    /// TOML deserializer message.
    pub message: String,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "constitution parse error: {}", self.message)
    }
}

impl core::error::Error for ParseError {}

/// Parse a TOML document into an `InMemoryConstitution`.
///
/// # Errors
///
/// Returns `ParseError` if `s` is not valid TOML or if the schema does not
/// match `ConstitutionDoc` (missing `title`, unknown verdict, etc.).
pub fn parse_toml(s: &str) -> Result<InMemoryConstitution, ParseError> {
    let doc: ConstitutionDoc = toml::from_str(s).map_err(|e| ParseError {
        message: e.to_string(),
    })?;
    Ok(InMemoryConstitution::from_doc(doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniclaw_receipt::{Action, Decision, Digest};

    use crate::Constitution;

    fn action(kind: &str, target: &str) -> Action {
        Action {
            kind: kind.into(),
            target: target.into(),
            input_hash: Digest([0u8; 32]),
        }
    }

    #[test]
    fn parses_minimal_constitution() {
        let toml_src = r#"
            title = "Tiny"
            version = 1
        "#;
        let c = parse_toml(toml_src).expect("must parse");
        assert!(c.rules().is_empty());
    }

    #[test]
    fn parses_solo_dev_shape() {
        let toml_src = r#"
            title = "Solo Developer Mode"
            version = 1

            [[rules]]
            id = "solo-dev/no-shell"
            description = "No shell execution in solo-dev mode."
            verdict = "deny"
            match.kind = "shell.exec"

            [[rules]]
            id = "solo-dev/no-finance-stripe"
            description = "Block POSTs to stripe.com."
            verdict = "deny"
            match.kind = "http.post"
            match.target_contains = "stripe.com"
        "#;
        let c = parse_toml(toml_src).expect("must parse");
        assert_eq!(c.rules().len(), 2);

        // shell action denied
        let v1 = c.evaluate(&action("shell.exec", "rm -rf /"));
        assert_eq!(v1.override_decision, Some(Decision::Denied));
        assert_eq!(v1.matched_rules[0].id, "solo-dev/no-shell");

        // benign GET passes
        let v2 = c.evaluate(&action("http.get", "https://example.com/"));
        assert!(v2.matched_rules.is_empty());
        assert_eq!(v2.override_decision, None);

        // stripe POST denied
        let v3 = c.evaluate(&action("http.post", "https://api.stripe.com/v1/charges"));
        assert_eq!(v3.override_decision, Some(Decision::Denied));
        assert_eq!(v3.matched_rules[0].id, "solo-dev/no-finance-stripe");
    }

    #[test]
    fn rejects_invalid_toml() {
        let err = parse_toml("not = valid = toml").expect_err("must fail");
        assert!(err.message.to_lowercase().contains("expected"));
    }

    #[test]
    fn rejects_unknown_verdict() {
        let toml_src = r#"
            title = "Bogus"
            version = 1

            [[rules]]
            id = "x"
            description = "y"
            verdict = "magic"
        "#;
        let err = parse_toml(toml_src).expect_err("must fail");
        assert!(err.message.contains("unknown variant"));
    }
}
