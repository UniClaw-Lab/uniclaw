//! Host-side implementation of the `host` interface in
//! `wit/tool.wit`.
//!
//! Backs the WASM guest's host imports for the `tool-with-host`
//! world (16c). Each guest's `http-fetch` call routes through the
//! same `HttpFetchTool` instance the host operator built — same
//! capability allowlist, same SSRF gate, same response bound,
//! same broker-backed Authorization injection. The guest never
//! sees secret values; it only references them by broker name.
//!
//! Per-call usage (which secrets the guest touched, how many
//! http-fetch calls it made, what it logged) accumulates in
//! [`HostState`] and gets surfaced to the kernel via
//! `ToolOutput::metadata` when `WasmTool::call` returns.
//!
//! ## Trait wiring
//!
//! The bindgen-generated `host::Host` trait lives on
//! [`crate::limits::StoreData`] (NOT on `HostState` directly).
//! That's because wasmtime's component-linker needs a single
//! type as the store data — not a state-plus-options pair.
//! `StoreData` holds an `Option<HostState>`; the trait methods
//! delegate to the inner state if configured, return graceful
//! errors otherwise.
//!
//! For 16a/16b paths (no host imports) the Host trait impl
//! exists but is never invoked, because we don't add the host
//! import to those linkers. The Option stays `None`.
//!
//! Adopt-don't-copy: shape mirrors `IronClaw`'s
//! `crates/ironclaw_wasm/src/host.rs` (logging accumulator,
//! rate-limit constants, http-request routed through a host-side
//! Tool). BoardProof's v0 surface is leaner — no workspace-read,
//! no tool-invoke, no detailed resource counters yet.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use boardproof_receipt::Digest;
use boardproof_secrets::SecretBroker;
use boardproof_tools::{Tool, ToolCall, ToolError};
use boardproof_tools_http::{AuthSpec, HttpFetchInput, HttpFetchOutput, HttpFetchTool};

use crate::bindings::with_host::boardproof::tool::host;
use crate::limits::StoreData;

/// Soft caps for the guest's `log-message` import. `IronClaw`'s
/// values; reasonable for v0. A cap-busting log call is a no-op
/// (silently dropped) rather than an error — logging shouldn't
/// be a path to break the guest.
pub const MAX_LOG_ENTRIES: usize = 1000;
pub const MAX_LOG_MESSAGE_BYTES: usize = 4096;

/// One log entry collected from the guest. The host accumulates
/// these per-call; they don't reach stdio inside the sandbox.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub level: host::LogLevel,
    pub message: String,
}

/// Per-call host state: the references needed to satisfy the
/// guest's host imports, plus accumulators for per-call usage.
///
/// Constructed fresh per `WasmTool::call` so accumulators don't
/// leak across calls. `Arc<...>` references are cheap to clone.
pub struct HostState {
    http: Arc<HttpFetchTool>,
    broker: Arc<dyn SecretBroker>,
    secrets_used: Vec<String>,
    logs: Vec<LogRecord>,
    http_fetch_calls: u32,
}

impl core::fmt::Debug for HostState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostState")
            .field("secrets_used", &self.secrets_used)
            .field("logs_count", &self.logs.len())
            .field("http_fetch_calls", &self.http_fetch_calls)
            .finish_non_exhaustive()
    }
}

impl HostState {
    pub fn new(http: Arc<HttpFetchTool>, broker: Arc<dyn SecretBroker>) -> Self {
        Self {
            http,
            broker,
            secrets_used: Vec::new(),
            logs: Vec::new(),
            http_fetch_calls: 0,
        }
    }

    /// Deduplicated list of secret reference names the guest
    /// touched during this call, in first-touch order. Surfaced
    /// to the kernel via `ToolOutput::metadata.secrets_used`.
    pub fn secrets_used(&self) -> Vec<String> {
        let mut seen = Vec::with_capacity(self.secrets_used.len());
        for s in &self.secrets_used {
            if !seen.iter().any(|t: &String| t == s) {
                seen.push(s.clone());
            }
        }
        seen
    }

    /// Read-only view of accumulated log entries.
    pub fn logs(&self) -> &[LogRecord] {
        &self.logs
    }

    /// How many `http-fetch` calls the guest made during this call.
    pub fn http_fetch_calls(&self) -> u32 {
        self.http_fetch_calls
    }

    fn record_log(&mut self, level: host::LogLevel, message: String) {
        if self.logs.len() >= MAX_LOG_ENTRIES {
            return;
        }
        let truncated = if message.len() > MAX_LOG_MESSAGE_BYTES {
            // Truncate at a UTF-8 boundary. `floor_char_boundary`
            // is unstable; doing it manually here keeps stable.
            let mut idx = MAX_LOG_MESSAGE_BYTES;
            while idx > 0 && !message.is_char_boundary(idx) {
                idx -= 1;
            }
            message[..idx].to_string()
        } else {
            message
        };
        self.logs.push(LogRecord {
            level,
            message: truncated,
        });
    }

    fn check_secret_exists(&mut self, name: &str) -> bool {
        // v0 brokers: existence check is `fetch.is_ok()`. The
        // returned `SecretValue` is dropped (zeroed) immediately.
        // Future ACL-aware brokers may distinguish "exists" from
        // "callable by this caller"; for v0 the answer is the same.
        self.broker.fetch(name).is_ok()
    }

    fn run_http_fetch(
        &mut self,
        url: String,
        auth: Option<host::AuthSpec>,
        timeout_ms: Option<u32>,
    ) -> Result<host::HttpResponse, String> {
        // Brought to top of function so clippy::items_after_statements
        // doesn't fire on a `use` deeper down.
        use base64::Engine as _;

        self.http_fetch_calls = self.http_fetch_calls.saturating_add(1);

        // WIT auth-spec → boardproof-tools-http AuthSpec. Record the
        // secret reference name BEFORE the call — even on failure
        // the guest *attempted* to touch it, and the audit trail
        // should reflect that.
        let host_auth = auth.map(|a| match a {
            host::AuthSpec::BearerHeader(secret_ref) => {
                self.secrets_used.push(secret_ref.clone());
                AuthSpec::BearerHeader { secret_ref }
            }
        });

        // The guest can suggest a timeout. v0 accepts the
        // suggestion as-is; the engine's epoch deadline still
        // fires from the outside if the guest blows the budget.
        // Future step: cap `timeout_ms` at remaining wall-clock
        // budget to prevent a guest from extending its own
        // execution by burning host time.
        let _ = timeout_ms;

        let input = HttpFetchInput {
            url: url.clone(),
            auth: host_auth,
        };
        let input_bytes =
            serde_json::to_vec(&input).map_err(|e| format!("encode HttpFetchInput: {e}"))?;
        let input_hash = Digest(*blake3::hash(&input_bytes).as_bytes());
        let call = ToolCall {
            tool_name: "http_fetch".to_string(),
            target: url,
            input: input_bytes,
            input_hash,
        };

        let out = self.http.call(&call).map_err(host_error_message)?;

        // Aggregate the inner tool's secrets_used into the host
        // accumulator (defensive — the WIT auth-spec is currently
        // a 1:1 source of secret names, but if HttpFetchTool ever
        // records additional ones, we want them too).
        for s in &out.metadata.secrets_used {
            self.secrets_used.push(s.clone());
        }

        // Decode the inner tool's JSON envelope so the guest gets
        // a structured response rather than re-parsing JSON.
        let envelope: HttpFetchOutput = serde_json::from_slice(&out.bytes)
            .map_err(|e| format!("decode HttpFetchOutput: {e}"))?;
        let body = base64::engine::general_purpose::STANDARD
            .decode(&envelope.body_b64)
            .map_err(|e| format!("decode base64 body: {e}"))?;

        Ok(host::HttpResponse {
            status: envelope.status,
            headers: envelope.headers,
            body,
        })
    }
}

/// Implementation of the bindgen-generated `Host` trait on the
/// shared store data type. Methods delegate to the inner
/// `HostState` if configured; return graceful errors otherwise.
impl host::Host for StoreData {
    fn log_message(&mut self, level: host::LogLevel, message: String) {
        if let Some(host_state) = self.host_mut() {
            host_state.record_log(level, message);
        }
        // No host configured → silently drop. (Can only happen
        // if the wiring is buggy; the host trait isn't added to
        // the linker for non-host paths.)
    }

    fn now_millis(&mut self) -> u64 {
        // Doesn't need a host. Returns 0 if the system clock is
        // before the Unix epoch (won't happen on real hardware
        // but the API requires us to handle the error).
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            Err(_) => 0,
        }
    }

    fn secret_exists(&mut self, name: String) -> bool {
        match self.host_mut() {
            Some(h) => h.check_secret_exists(&name),
            None => false,
        }
    }

    fn http_fetch(
        &mut self,
        url: String,
        auth: Option<host::AuthSpec>,
        timeout_ms: Option<u32>,
    ) -> Result<host::HttpResponse, String> {
        match self.host_mut() {
            Some(h) => h.run_http_fetch(url, auth, timeout_ms),
            None => Err("host imports not configured".to_string()),
        }
    }
}

/// Translate a `ToolError` from `HttpFetchTool::call` into a
/// short string the guest sees as `Err(string)`. We never include
/// secret values; `ToolError` doesn't carry any (the `secret_ref`
/// names appear in `Failed` messages, which is fine — those are
/// the names the guest already supplied).
fn host_error_message(err: ToolError) -> String {
    match err {
        ToolError::CapabilityDenied { attempted } => {
            format!("capability denied: {attempted:?}")
        }
        ToolError::InvalidInput(msg) => format!("invalid input: {msg}"),
        ToolError::Failed(msg) => format!("failed: {msg}"),
        ToolError::Timeout => "timeout".to_string(),
        ToolError::NotFound { tool_name } => format!("tool not found: {tool_name}"),
    }
}
