//! The trait every constitution implementation honors, plus the verdict it returns.

use alloc::vec::Vec;

use uniclaw_receipt::{Action, Decision, RuleRef};

/// Result of consulting a constitution about an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstitutionVerdict {
    /// All rules that matched this action, in document order.
    ///
    /// Recorded verbatim in `Receipt.body.constitution_rules` so an auditor
    /// can replay the decision tree.
    pub matched_rules: Vec<RuleRef>,
    /// If `Some`, the kernel **must** override the proposed decision with
    /// this value. v0 only ever sets `Some(Decision::Denied)` — the
    /// constitution is safe-by-default and never grants `Allowed`.
    pub override_decision: Option<Decision>,
}

impl ConstitutionVerdict {
    /// Empty verdict: no rules matched, no override.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            matched_rules: Vec::new(),
            override_decision: None,
        }
    }
}

/// Anything the kernel can consult to judge an action.
///
/// Implementations:
/// - `EmptyConstitution` — no rules, useful for tests and bare runtimes.
/// - `InMemoryConstitution` — rules loaded from TOML or built in-process.
/// - (future) `LayeredConstitution` — composes operator + project + tenant
///   constitutions.
pub trait Constitution {
    /// Evaluate `action` against the constitution.
    fn evaluate(&self, action: &Action) -> ConstitutionVerdict;
}
