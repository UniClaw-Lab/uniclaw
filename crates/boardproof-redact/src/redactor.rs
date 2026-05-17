//! [`Redactor`] trait + [`RedactionResult`].

use boardproof_receipt::RedactionReport;

/// One pass of byte redaction.
///
/// Implementations are typically `Send + Sync` so a single
/// redactor can be cloned across threads via `Arc<dyn Redactor>`.
/// The reference impls in this crate satisfy that.
pub trait Redactor: Send + Sync + core::fmt::Debug {
    /// Stable identifier. Goes into the
    /// [`boardproof_receipt::RedactionReport::stack_hash`] computation
    /// and into per-rule match edges as part of `rule_id`. The
    /// convention for [`crate::PatternRedactor`] is the redactor's
    /// own ID prefixed onto each rule's ID
    /// (`"<redactor-id>::<rule-id>"`), so the `stack_hash` and
    /// edges still distinguish rules across two redactors with
    /// overlapping rule names.
    fn id(&self) -> &str;

    /// Apply this redactor's rules to `bytes`. Returns the
    /// redacted bytes plus the audit report. If nothing matched,
    /// `result.report.matches` is empty and `result.redacted_bytes`
    /// is byte-identical to the input.
    fn redact(&self, bytes: &[u8]) -> RedactionResult;
}

/// Output of a [`Redactor::redact`] call.
///
/// The redacted bytes go to whoever owns them next (the tool's
/// caller). The `report` is what the kernel records — see
/// [`boardproof_receipt::RedactionReport`] for the semantics of each
/// field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// Bytes after redaction. Byte-identical to the input if
    /// nothing matched.
    pub redacted_bytes: Vec<u8>,
    /// Audit report — fed to the kernel via `ToolExecution::redaction`.
    pub report: RedactionReport,
}
