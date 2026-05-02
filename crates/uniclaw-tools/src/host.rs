//! [`ToolHost`] — the registry that maps tool names to their
//! implementations.

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::tool::{BoxedTool, Tool, ToolCall, ToolError, ToolOutput};

/// A registry of registered [`Tool`]s, looked up by name.
///
/// This is the simplest possible host: a `BTreeMap<String, Box<dyn Tool>>`
/// with a name-routed `call` method. Real deployments may wrap their
/// own scheduling around this (rate limits, async dispatch, sandbox
/// pools); the kernel only needs to see something that takes a
/// `ToolCall` and returns a `Result<ToolOutput, ToolError>`.
///
/// `ToolHost` is `Send + Sync` (every registered tool is bounded by
/// `Send + Sync` via the [`BoxedTool`] type alias), so it can be
/// shared across threads behind an `Arc<RwLock<…>>` or similar
/// without further bounds.
#[derive(Default)]
pub struct ToolHost {
    by_name: BTreeMap<String, BoxedTool>,
}

impl core::fmt::Debug for ToolHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ToolHost")
            .field("registered_tool_count", &self.by_name.len())
            .finish()
    }
}

impl ToolHost {
    /// Construct an empty host.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `tool` under `tool.name()`. If a tool with the same
    /// name is already registered, returns the previous `BoxedTool`
    /// (the caller can decide whether to drop or re-register it).
    pub fn register(&mut self, tool: BoxedTool) -> Option<BoxedTool> {
        let name = String::from(tool.name());
        self.by_name.insert(name, tool)
    }

    /// Number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// True when no tools are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Look up a registered tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.by_name.get(name).map(|b| &**b as &dyn Tool)
    }

    /// Iterate over registered tool names in stable (lexicographic) order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    /// Dispatch `call` to the named tool. Returns
    /// [`ToolError::NotFound`] if no tool with that name is registered.
    ///
    /// # Errors
    ///
    /// Either [`ToolError::NotFound`] or whatever the named tool's
    /// `call` returned.
    pub fn call(&self, call: &ToolCall) -> Result<ToolOutput, ToolError> {
        match self.by_name.get(&call.tool_name) {
            Some(tool) => tool.call(call),
            None => Err(ToolError::NotFound {
                tool_name: call.tool_name.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noop::NoopTool;
    use crate::tool::{ApprovalPolicy, ToolManifest};
    use alloc::boxed::Box;
    use alloc::string::ToString;
    use alloc::vec;
    use uniclaw_receipt::Digest;

    fn input(bytes: &[u8]) -> ToolCall {
        ToolCall {
            tool_name: "noop".to_string(),
            target: "test".to_string(),
            input: bytes.to_vec(),
            // We don't care about the actual hash for these unit tests
            // — we're testing the registry, not the hashing path.
            input_hash: Digest([0u8; 32]),
        }
    }

    #[test]
    fn empty_host_reports_zero_tools() {
        let h = ToolHost::new();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.get("anything").is_none());
        assert_eq!(h.names().count(), 0);
    }

    #[test]
    fn register_and_lookup_works() {
        let mut h = ToolHost::new();
        h.register(Box::new(NoopTool::new()));
        assert_eq!(h.len(), 1);
        assert!(!h.is_empty());
        assert!(h.get("noop").is_some());
        assert!(h.get("missing").is_none());
        let names: alloc::vec::Vec<&str> = h.names().collect();
        assert_eq!(names, vec!["noop"]);
    }

    #[test]
    fn re_registering_returns_previous() {
        let mut h = ToolHost::new();
        let first_returned = h.register(Box::new(NoopTool::new()));
        assert!(first_returned.is_none());
        let second_returned = h.register(Box::new(NoopTool::new()));
        assert!(second_returned.is_some(), "old tool replaced");
        assert_eq!(h.len(), 1, "register replaces, doesn't accumulate");
    }

    #[test]
    fn call_routes_to_registered_tool() {
        let mut h = ToolHost::new();
        h.register(Box::new(NoopTool::new()));
        let out = h.call(&input(b"hello")).expect("noop call ok");
        assert_eq!(out.bytes, b"hello".to_vec());
    }

    #[test]
    fn call_unknown_tool_returns_not_found() {
        let h = ToolHost::new();
        let err = h.call(&input(b"x")).unwrap_err();
        match err {
            ToolError::NotFound { tool_name } => assert_eq!(tool_name, "noop"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn host_is_thread_safe_marker_check() {
        // Compile-time check: ToolHost is Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ToolHost>();
    }

    /// Used to silence the unused-import lint when the [`ApprovalPolicy`] /
    /// [`ToolManifest`] aren't otherwise touched in this file's tests.
    #[allow(dead_code)]
    fn _types_referenced_for_lint(_: ApprovalPolicy, _: ToolManifest) {}
}
