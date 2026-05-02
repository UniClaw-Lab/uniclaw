//! [`NoopTool`] — the identity tool. Useful for tests and as a
//! placeholder in deployments that haven't registered any real tool yet.

use alloc::string::ToString;
use alloc::vec::Vec;

use uniclaw_receipt::Digest;

use crate::tool::{ApprovalPolicy, Tool, ToolCall, ToolError, ToolManifest, ToolOutput};

/// A tool that returns its input bytes verbatim as output.
///
/// Declares no capabilities (it doesn't call out, doesn't touch the
/// filesystem, doesn't run anything). Default approval policy is
/// `Never` — there's nothing to approve.
///
/// `NoopTool` is the only `Tool` impl that ships in this crate. Real
/// tools (HTTP fetch, file read, shell exec) live in their own crates
/// alongside the runtime that powers them.
#[derive(Debug)]
pub struct NoopTool {
    manifest: ToolManifest,
}

impl Default for NoopTool {
    fn default() -> Self {
        Self::new()
    }
}

impl NoopTool {
    /// Construct a `NoopTool` with the standard manifest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: ToolManifest {
                name: "noop".to_string(),
                description: "Returns input bytes unchanged. For tests and empty deployments."
                    .to_string(),
                action_kind: "tool.noop".to_string(),
                declared_capabilities: Vec::new(),
                default_approval: ApprovalPolicy::Never,
            },
        }
    }
}

impl Tool for NoopTool {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    fn call(&self, call: &ToolCall) -> Result<ToolOutput, ToolError> {
        let bytes = call.input.clone();
        let output_hash = Digest(*blake3::hash(&bytes).as_bytes());
        Ok(ToolOutput { bytes, output_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniclaw_receipt::Digest;

    fn call_with(input: &[u8]) -> ToolCall {
        ToolCall {
            tool_name: "noop".to_string(),
            target: "test".to_string(),
            input: input.to_vec(),
            input_hash: Digest(*blake3::hash(input).as_bytes()),
        }
    }

    #[test]
    fn noop_manifest_is_well_formed() {
        let t = NoopTool::new();
        assert_eq!(t.name(), "noop");
        assert_eq!(t.manifest().action_kind, "tool.noop");
        assert!(t.manifest().declared_capabilities.is_empty());
        assert_eq!(t.manifest().default_approval, ApprovalPolicy::Never);
    }

    #[test]
    fn noop_returns_input_verbatim() {
        let t = NoopTool::new();
        let out = t.call(&call_with(b"hello world")).unwrap();
        assert_eq!(out.bytes, b"hello world".to_vec());
    }

    #[test]
    fn noop_output_hash_matches_blake3_of_bytes() {
        let t = NoopTool::new();
        let input = b"some bytes";
        let out = t.call(&call_with(input)).unwrap();
        let expected = Digest(*blake3::hash(input).as_bytes());
        assert_eq!(out.output_hash, expected);
    }

    #[test]
    fn noop_handles_empty_input() {
        let t = NoopTool::new();
        let out = t.call(&call_with(b"")).unwrap();
        assert!(out.bytes.is_empty());
        let expected = Digest(*blake3::hash(b"").as_bytes());
        assert_eq!(out.output_hash, expected);
    }

    #[test]
    fn noop_approval_policy_is_never() {
        let t = NoopTool::new();
        assert_eq!(
            t.approval_policy(&call_with(b"anything")),
            ApprovalPolicy::Never
        );
    }
}
