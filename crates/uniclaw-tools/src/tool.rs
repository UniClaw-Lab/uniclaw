//! The [`Tool`] trait and the call/output/error/manifest shapes around it.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use uniclaw_receipt::Digest;

use crate::capability::Capability;

/// Whether a tool's caller must obtain operator approval before the
/// kernel will mint an `Allowed` proposal receipt for a call.
///
/// This complements — and does **not** replace — the constitution. The
/// constitution can promote *any* action to `RequireApproval`; a tool's
/// `ApprovalPolicy` is a *minimum* the tool itself declares. If both
/// are set, the more cautious wins (approval is required if either
/// asks for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalPolicy {
    /// No approval needed. Suitable for read-only, idempotent tools
    /// over public data.
    Never,
    /// Decided per call by the tool itself. The tool inspects the
    /// `ToolCall` and returns a refined policy from
    /// [`Tool::approval_policy`].
    Discretionary,
    /// Always requires approval. Suitable for any tool that mutates
    /// external state or spends a real-world resource.
    Always,
}

/// What a tool declares about itself.
///
/// The kernel does not invoke the tool's code through the manifest;
/// the manifest is just the static, auditable description. The actual
/// behavior is in [`Tool::call`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManifest {
    /// Stable tool name. Used for routing in [`crate::ToolHost`] and
    /// to namespace the action kind on receipts.
    pub name: String,

    /// One-line human description. Goes into receipts and operator
    /// approval prompts.
    pub description: String,

    /// The `action.kind` prefix every call to this tool will use. By
    /// convention `tool.<name>` — e.g. `"tool.echo"`, `"tool.http_fetch"`.
    /// The constitution can target this kind directly (`Deny` or
    /// `RequireApproval`).
    pub action_kind: String,

    /// Capabilities this tool may exercise during a call. Declared
    /// upfront; the host enforces at execution time. A tool that uses
    /// a capability not on this list is a programming error caught by
    /// the host's defense-in-depth check, not by the kernel.
    pub declared_capabilities: Vec<Capability>,

    /// The default approval policy for this tool. Tools whose policy
    /// depends on the call should set this to `Discretionary` and
    /// override per call in [`Tool::approval_policy`].
    pub default_approval: ApprovalPolicy,
}

/// A single invocation of a tool.
///
/// Both the input bytes and a precomputed [`Digest`] of those bytes
/// are carried so the kernel can record the input hash in the
/// resulting receipt without re-hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// Tool name (matches a [`ToolManifest::name`]).
    pub tool_name: String,

    /// Free-form description of *what* this call is doing — typically
    /// the same string used in `Action::target` for the proposal
    /// receipt that authorized this call. Used in receipt provenance,
    /// not for routing.
    pub target: String,

    /// Raw input bytes the tool will consume. Format is
    /// tool-specific (JSON, `MessagePack`, raw bytes, …).
    pub input: Vec<u8>,

    /// BLAKE3 hash of `input`. Callers compute this once at call-site
    /// time so it's already in the right form for receipt minting.
    pub input_hash: Digest,
}

/// The output of a successful tool call.
///
/// Same input/output-hash treatment as [`ToolCall`]: bytes plus a
/// precomputed BLAKE3 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Raw output bytes the tool produced.
    pub bytes: Vec<u8>,
    /// BLAKE3 hash of `bytes`. Computed once by the tool (or its
    /// adapter); the kernel uses it directly in the receipt.
    pub output_hash: Digest,
}

/// Why a tool call failed.
///
/// All variants carry an owned `String` to keep the trait surface
/// flexible across backends. The kernel records the human-readable
/// message in the failed-execution receipt's provenance edge; the
/// `OutcomeKind` carries only an `input_hash` discriminator (so it
/// can stay `Copy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// The host doesn't know about this tool name.
    NotFound { tool_name: String },
    /// The input failed the tool's own validation.
    InvalidInput(String),
    /// The tool ran but reported failure.
    Failed(String),
    /// The tool exceeded its time budget.
    Timeout,
    /// The tool tried to use a capability it didn't declare in its
    /// manifest. Caught at the host boundary as defense-in-depth; the
    /// constitution should typically catch this earlier as a `Deny`.
    CapabilityDenied {
        /// The capability the tool tried to use.
        attempted: Capability,
    },
}

impl ToolError {
    /// Short, stable identifier for this error variant. Used in
    /// receipt provenance edges so audit readers can filter by error
    /// kind without parsing the message.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            ToolError::NotFound { .. } => "not_found",
            ToolError::InvalidInput(_) => "invalid_input",
            ToolError::Failed(_) => "failed",
            ToolError::Timeout => "timeout",
            ToolError::CapabilityDenied { .. } => "capability_denied",
        }
    }

    /// Best-effort human message, suitable for embedding in a
    /// receipt provenance edge.
    #[must_use]
    pub fn message(&self) -> String {
        use core::fmt::Write;
        let mut out = String::new();
        match self {
            ToolError::NotFound { tool_name } => {
                let _ = write!(&mut out, "tool not found: {tool_name}");
            }
            ToolError::InvalidInput(m) | ToolError::Failed(m) => {
                let _ = write!(&mut out, "{m}");
            }
            ToolError::Timeout => {
                out.push_str("timeout");
            }
            ToolError::CapabilityDenied { attempted } => {
                let _ = write!(&mut out, "capability denied: {}", attempted.variant_name());
            }
        }
        out
    }
}

/// A tool implementation.
///
/// Backends (WASM, container, MCP, native) implement this trait; the
/// host registry stores `Box<dyn Tool>` and routes calls by name.
///
/// # Synchronicity
///
/// `call` is synchronous. Async runtimes wrap a sync `Tool` impl in
/// their own scheduling (e.g. `tokio::task::spawn_blocking` for a
/// long-running WASM call). The kernel itself doesn't drive tool
/// execution; orchestration happens outside, then results come back to
/// the kernel via `KernelEvent::RecordToolExecution`.
///
/// # Lifecycle
///
/// 1. Caller submits a `Proposal` with `action.kind = manifest.action_kind`.
/// 2. Kernel runs constitution + budget gates → mints a proposal receipt.
/// 3. If `decision == Allowed`, the caller invokes [`Tool::call`] (typically
///    via [`crate::ToolHost::call`]).
/// 4. Caller submits `KernelEvent::RecordToolExecution` with the result.
/// 5. Kernel runs the authenticity gate against the proposal receipt,
///    then mints the execution receipt with `input_hash` + `output_hash`
///    in provenance.
pub trait Tool {
    /// Stable tool name (matches `manifest().name`).
    fn name(&self) -> &str;

    /// Self-description: action kind owned, capabilities declared,
    /// default approval policy.
    fn manifest(&self) -> &ToolManifest;

    /// Per-call approval policy. Default delegates to
    /// `manifest().default_approval`. Override when the policy depends
    /// on the call's contents (e.g. `shell.exec ls` is `Never` but
    /// `shell.exec rm -rf /` is `Always`).
    fn approval_policy(&self, _call: &ToolCall) -> ApprovalPolicy {
        self.manifest().default_approval
    }

    /// Execute the call. Synchronous. Returns either a
    /// [`ToolOutput`] (with output bytes and pre-computed hash) or a
    /// [`ToolError`] describing why the call failed.
    ///
    /// # Errors
    ///
    /// Implementation-defined; see [`ToolError`] for the typed shape.
    fn call(&self, call: &ToolCall) -> Result<ToolOutput, ToolError>;
}

// `Tool` is auto-impl'd for `Box<dyn Tool>` via the standard impl
// elaboration; we don't need an explicit blanket impl. (Rust handles
// `Box<dyn Trait>: Trait` automatically.)
//
// We do, however, want trait-objects to be `Send + Sync` for the
// future async-runtime case where a host is shared across threads.
// We don't bake that into the trait itself (keeps the trait usable in
// no_std single-threaded contexts); the host wraps `Box<dyn Tool + Send + Sync>`.

/// Convenience: `Box<dyn Tool>` with the `Send + Sync` bounds the host
/// uses. Type alias kept here so callers don't have to spell it out.
pub type BoxedTool = Box<dyn Tool + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::GlobPattern;
    use alloc::string::ToString;
    use alloc::vec;

    fn manifest() -> ToolManifest {
        ToolManifest {
            name: "echo".to_string(),
            description: "Identity tool".to_string(),
            action_kind: "tool.echo".to_string(),
            declared_capabilities: vec![],
            default_approval: ApprovalPolicy::Never,
        }
    }

    #[test]
    fn approval_policy_variants_are_distinct() {
        assert_ne!(ApprovalPolicy::Never, ApprovalPolicy::Discretionary);
        assert_ne!(ApprovalPolicy::Discretionary, ApprovalPolicy::Always);
        assert_ne!(ApprovalPolicy::Never, ApprovalPolicy::Always);
    }

    #[test]
    fn manifest_round_trips_through_clone() {
        let m1 = manifest();
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }

    #[test]
    fn tool_error_variant_names_are_stable() {
        assert_eq!(
            ToolError::NotFound {
                tool_name: "x".to_string()
            }
            .variant_name(),
            "not_found"
        );
        assert_eq!(
            ToolError::InvalidInput("x".to_string()).variant_name(),
            "invalid_input"
        );
        assert_eq!(ToolError::Failed("x".to_string()).variant_name(), "failed");
        assert_eq!(ToolError::Timeout.variant_name(), "timeout");
        assert_eq!(
            ToolError::CapabilityDenied {
                attempted: Capability::NetConnect(GlobPattern::new("x"))
            }
            .variant_name(),
            "capability_denied"
        );
    }

    #[test]
    fn tool_error_message_includes_useful_text() {
        assert!(
            ToolError::NotFound {
                tool_name: "echo".to_string()
            }
            .message()
            .contains("echo")
        );
        assert!(
            ToolError::Failed("disk full".to_string())
                .message()
                .contains("disk full")
        );
        assert!(
            ToolError::CapabilityDenied {
                attempted: Capability::ShellExec(GlobPattern::new("rm -rf /"))
            }
            .message()
            .contains("shell_exec")
        );
    }
}
