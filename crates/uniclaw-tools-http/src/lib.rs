//! HTTP fetch tool for Uniclaw — capability-checked GET with SSRF
//! defense, response-size bounds, and configurable timeout.
//!
//! This is the **first real `Tool` implementation** in the workspace
//! (Phase 3 step 14). It validates the [`uniclaw_tools::Capability`]
//! enum against actual network code: every request goes through a
//! [`Capability::is_granted_by`] gate before the HTTP client is touched,
//! and a separate [`ssrf::is_disallowed_ip`] gate refuses literal
//! private/loopback/link-local addresses by default.
//!
//! ## Scope (v0)
//!
//! - **GET only.** POST/PUT/etc are deferred. JSON envelope shape is
//!   forwards-compatible (extra fields land behind `#[serde(default)]`
//!   when they arrive).
//! - **No auto-redirects.** A 3xx response is surfaced as the actual
//!   status — the caller decides whether to follow. Auto-following
//!   would let a redirect bypass the capability allowlist by
//!   targeting a different host.
//! - **No cookies.** No session state across calls.
//! - **No custom request headers** (User-Agent only). v0 uses a fixed
//!   `User-Agent: uniclaw-tools-http/<version>`.
//!
//! ## Defenses
//!
//! - **Capability allowlist.** Each [`HttpFetchTool`] is constructed
//!   with a list of [`uniclaw_tools::GlobPattern`]s; requests whose
//!   host doesn't match any pattern fail with
//!   [`uniclaw_tools::ToolError::CapabilityDenied`] without opening a
//!   socket.
//! - **SSRF refusal.** Literal-IP requests to private/loopback/
//!   link-local/multicast/reserved ranges are refused before the
//!   request fires. See [`ssrf`] for the full table.
//! - **Bounded response.** Bodies larger than
//!   [`HttpFetchConfig::max_response_bytes`] (default 10 MiB) fail
//!   with [`uniclaw_tools::ToolError::Failed`] — the body is **not**
//!   returned partially.
//! - **Timeout.** Default 30 s; configurable.
//! - **TLS.** Pure-Rust `rustls` via `ureq`'s default TLS feature.
//!
//! ## Known limitations
//!
//! - **DNS rebinding.** A hostname that resolves to a public IP at
//!   parse time but a private IP at connect time slips past the SSRF
//!   gate. A future step pins the resolved IP at lookup and uses it
//!   verbatim for the connection. v0 documents this as a known gap.
//! - **Duplicate header names.** ureq's high-level API surfaces
//!   duplicates only via per-name lookup. v0 returns unique header
//!   names; multi-instance headers (e.g. `Set-Cookie`) collapse to
//!   the first value. A follow-up step uses the lower-level header
//!   iterator to preserve duplicates.
//! - **No streaming.** The full response body is read into memory
//!   before being returned. Tools needing larger payloads should
//!   use a different mechanism.
//!
//! ## Adopt-don't-copy
//!
//! - **`IronClaw`'s SSRF defense** — adopted in [`ssrf`]. Their
//!   implementation uses similar IP-range checks at the HTTP-client
//!   layer; the table here matches the same RFCs and adds the IPv6
//!   side. No source borrowed.
//! - **`OpenFang`'s capability-glob enforcement** — adopted at the
//!   tool layer. Each request goes through [`Capability::is_granted_by`]
//!   from `uniclaw-tools` before any network activity.
//!
//! No source borrowed from any reference claw.

#![forbid(unsafe_code)]

mod config;
mod envelope;
mod ssrf;

pub use config::HttpFetchConfig;
pub use envelope::{AuthSpec, HttpFetchInput, HttpFetchOutput};

use std::io::Read;
use std::sync::Arc;

use base64::Engine;

use uniclaw_receipt::Digest;
use uniclaw_secrets::SecretBroker;
use uniclaw_tools::{
    ApprovalPolicy, Capability, GlobPattern, Tool, ToolCall, ToolError, ToolManifest, ToolMetadata,
    ToolOutput,
};

/// HTTP fetch tool. Implements [`Tool`] over `ureq`.
///
/// Four constructors, increasing in capability:
///
/// - [`HttpFetchTool::with_allowlist`] — minimal: pass an allowed-host
///   glob list, get default config + no `SecretBroker`.
///   Authenticated inputs (`HttpFetchInput::auth`) fail-closed.
/// - [`HttpFetchTool::with_config`] — minimal + custom config.
/// - [`HttpFetchTool::with_broker`] — minimal + a [`SecretBroker`] for
///   authenticated requests.
/// - [`HttpFetchTool::with_broker_and_config`] — both.
pub struct HttpFetchTool {
    manifest: ToolManifest,
    config: HttpFetchConfig,
    agent: ureq::Agent,
    /// Optional broker. When `None`, requests with
    /// `HttpFetchInput::auth` set fail-closed with
    /// `ToolError::Failed("input requested authentication but tool
    /// has no SecretBroker configured")`.
    broker: Option<Arc<dyn SecretBroker>>,
}

impl core::fmt::Debug for HttpFetchTool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // ureq::Agent doesn't impl Debug — print the relevant fields.
        // The broker field shows only "Some(...)" / "None"; we never
        // try to print into it (it's `dyn SecretBroker`, no Debug).
        f.debug_struct("HttpFetchTool")
            .field("manifest", &self.manifest)
            .field("config", &self.config)
            .field("agent", &"<ureq::Agent>")
            .field(
                "broker",
                &if self.broker.is_some() {
                    "<configured>"
                } else {
                    "<none>"
                },
            )
            .finish()
    }
}

impl HttpFetchTool {
    /// Build a tool whose only declared capability is
    /// `NetConnect(host_pattern)` for each pattern in `allowed_hosts`.
    /// Uses [`HttpFetchConfig::default`] for everything else; no
    /// `SecretBroker` configured.
    #[must_use]
    pub fn with_allowlist(allowed_hosts: Vec<GlobPattern>) -> Self {
        Self::with_config(allowed_hosts, HttpFetchConfig::default())
    }

    /// Build a tool with explicit config + allowed-hosts list, no
    /// `SecretBroker` configured.
    #[must_use]
    pub fn with_config(allowed_hosts: Vec<GlobPattern>, config: HttpFetchConfig) -> Self {
        Self::build(allowed_hosts, config, None)
    }

    /// Build a tool with a `SecretBroker` for authenticated
    /// requests; default config otherwise.
    #[must_use]
    pub fn with_broker(allowed_hosts: Vec<GlobPattern>, broker: Arc<dyn SecretBroker>) -> Self {
        Self::build(allowed_hosts, HttpFetchConfig::default(), Some(broker))
    }

    /// Build a tool with both a `SecretBroker` and explicit config.
    #[must_use]
    pub fn with_broker_and_config(
        allowed_hosts: Vec<GlobPattern>,
        broker: Arc<dyn SecretBroker>,
        config: HttpFetchConfig,
    ) -> Self {
        Self::build(allowed_hosts, config, Some(broker))
    }

    /// Internal constructor used by all four public ones.
    fn build(
        allowed_hosts: Vec<GlobPattern>,
        config: HttpFetchConfig,
        broker: Option<Arc<dyn SecretBroker>>,
    ) -> Self {
        let manifest = ToolManifest {
            name: "http_fetch".to_string(),
            description: "GET an HTTP/HTTPS URL with capability and SSRF guards.".to_string(),
            action_kind: "tool.http_fetch".to_string(),
            declared_capabilities: allowed_hosts
                .into_iter()
                .map(Capability::NetConnect)
                .collect(),
            default_approval: ApprovalPolicy::Never,
        };
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .build();
        Self {
            manifest,
            config,
            agent,
            broker,
        }
    }

    /// Read-only view of the runtime config.
    #[must_use]
    pub fn config(&self) -> &HttpFetchConfig {
        &self.config
    }

    /// True when a `SecretBroker` is configured. Read-only check.
    #[must_use]
    pub fn has_broker(&self) -> bool {
        self.broker.is_some()
    }
}

impl Tool for HttpFetchTool {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    fn call(&self, call: &ToolCall) -> Result<ToolOutput, ToolError> {
        // 1. Parse input.
        let input: HttpFetchInput = serde_json::from_slice(&call.input)
            .map_err(|e| ToolError::InvalidInput(format!("input not valid JSON: {e}")))?;

        // 2. Parse URL + extract host.
        let url = url::Url::parse(&input.url)
            .map_err(|e| ToolError::InvalidInput(format!("malformed URL: {e}")))?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ToolError::InvalidInput(format!(
                "unsupported scheme: {scheme}"
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| ToolError::InvalidInput("URL has no host".to_string()))?;

        // 3. Capability gate. We treat the host as a literal (no
        //    glob in the request side); any declared NetConnect
        //    capability whose glob matches it grants access.
        let requested = Capability::NetConnect(GlobPattern::new(host));
        if !Capability::is_granted_by(&self.manifest.declared_capabilities, &requested) {
            return Err(ToolError::CapabilityDenied {
                attempted: requested,
            });
        }

        // 4. SSRF gate. A hostname that's a literal IP gets checked
        //    against the disallowed-ranges table; a hostname stays
        //    unchecked (DNS-rebinding limitation, documented).
        if !self.config.allow_private_ips && ssrf::is_disallowed_ip(host) {
            return Err(ToolError::Failed(format!(
                "refusing private/loopback/link-local IP: {host}"
            )));
        }

        // 5. Resolve authentication. If `input.auth` is set we MUST
        //    have a `SecretBroker` configured — fail-closed otherwise
        //    (silently dropping auth is the IronClaw failure mode we
        //    explicitly avoid). Each resolved secret records its
        //    *reference name* (never its value) into `secrets_used`,
        //    which the kernel later reads off `ToolMetadata` to mint
        //    `secret_used` provenance edges.
        let mut req = self.agent.get(url.as_str());
        let mut secrets_used: Vec<String> = Vec::new();
        if let Some(auth) = &input.auth {
            let broker = self.broker.as_ref().ok_or_else(|| {
                ToolError::Failed(
                    "input requested authentication but tool has no SecretBroker configured"
                        .to_string(),
                )
            })?;
            match auth {
                AuthSpec::BearerHeader { secret_ref } => {
                    let secret = broker.fetch(secret_ref).map_err(|e| {
                        // The error preserves the secret *name* (which
                        // the receipt audit trail will already see) but
                        // not the value — `BrokerError`'s Display impl
                        // is value-free by construction.
                        ToolError::Failed(format!("failed to fetch secret '{secret_ref}': {e}"))
                    })?;
                    let header_value = format!("Bearer {}", secret.expose());
                    req = req.set("Authorization", &header_value);
                    secrets_used.push(secret_ref.clone());
                    // `secret` (and its inner buffer) is dropped at
                    // end of this block; SecretValue::Drop zeroes
                    // the bytes.
                }
            }
        }

        // 6. Execute the GET. ureq surfaces 4xx/5xx as
        //    `Error::Status(code, response)`; we want the response
        //    either way, so accept both via Ok-or-Status.
        let response = match req.call() {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                // All transport-layer failures (DNS, connect refused,
                // TCP read/write error, TLS handshake failure, **timeouts**)
                // map to `ToolError::Failed` for v0.
                //
                // Why not surface timeouts as `ToolError::Timeout` here?
                // Portable timeout detection in `ureq` 2.x requires
                // inspecting an OS-dependent inner `io::Error` or
                // string-matching the display message — and the wording
                // varies wildly across platforms (Linux: "timed out";
                // Windows: "did not properly respond after a period of
                // time"; macOS: "Operation timed out"). The earlier
                // string-match approach failed on Windows CI. The
                // structurally clean fix needs a richer ureq API
                // (a stable `is_timeout()` predicate or downcast path)
                // that doesn't yet exist in 2.x.
                //
                // `ToolError::Timeout` stays in the trait surface — file-IO
                // and subprocess tools that can detect timeouts cleanly
                // will use it. `HttpFetchTool` is conservative and uses
                // `Failed` with the message preserved so callers can
                // still grep platform-specific timeout patterns
                // out-of-band if they need to.
                let kind = format!("{:?}", t.kind());
                let msg = t.to_string();
                return Err(ToolError::Failed(format!("transport [{kind}]: {msg}")));
            }
        };

        let status: u16 = response.status();

        // 7. Collect headers. v0 limitation: unique names only.
        //    See "Known limitations" in crate docs.
        let header_names: Vec<String> = response.headers_names().into_iter().collect();
        let mut headers: Vec<(String, String)> = Vec::with_capacity(header_names.len());
        for name in &header_names {
            if let Some(v) = response.header(name) {
                headers.push((name.to_ascii_lowercase(), v.to_string()));
            }
        }

        // 8. Read body bounded by max_response_bytes. The +1 trick:
        //    if we read exactly max+1 bytes, the body is too long
        //    and we refuse — without ever returning a truncated body.
        let max = self.config.max_response_bytes;
        let mut reader = response.into_reader().take(max.saturating_add(1));
        // Cap the initial allocation at 64 KiB; the bound is
        // mathematically ≤ 65_536 so it always fits in `usize` on
        // every supported target.
        let initial_cap = usize::try_from(max.min(64 * 1024)).unwrap_or(64 * 1024);
        let mut body = Vec::with_capacity(initial_cap);
        reader
            .read_to_end(&mut body)
            .map_err(|e| ToolError::Failed(format!("read body: {e}")))?;
        if body.len() as u64 > max {
            return Err(ToolError::Failed(format!(
                "response exceeded max_response_bytes ({max})"
            )));
        }

        // 9. Encode body + build envelope.
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body);
        let envelope = HttpFetchOutput {
            status,
            headers,
            body_b64,
        };

        // 10. Serialize envelope to JSON. The output_hash is over the
        //     envelope bytes, not the raw body — so a verifier that
        //     re-runs the tool with the same input gets a deterministic
        //     match on the whole envelope (status + headers + body).
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ToolError::Failed(format!("encode envelope: {e}")))?;
        let output_hash = Digest(*blake3::hash(&bytes).as_bytes());

        Ok(ToolOutput {
            bytes,
            output_hash,
            metadata: ToolMetadata { secrets_used },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_well_formed_with_one_allowed_host() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("api.example.com")]);
        assert_eq!(t.name(), "http_fetch");
        assert_eq!(t.manifest().action_kind, "tool.http_fetch");
        assert_eq!(t.manifest().declared_capabilities.len(), 1);
        match &t.manifest().declared_capabilities[0] {
            Capability::NetConnect(g) => assert_eq!(g.as_str(), "api.example.com"),
            other => panic!("unexpected capability variant: {other:?}"),
        }
    }

    #[test]
    fn capability_denied_when_host_not_in_allowlist() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("api.example.com")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "https://evil.test/".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        match err {
            ToolError::CapabilityDenied {
                attempted: Capability::NetConnect(g),
            } => {
                assert_eq!(g.as_str(), "evil.test");
            }
            other => panic!("expected CapabilityDenied, got {other:?}"),
        }
    }

    #[test]
    fn ssrf_refuses_loopback_ip_with_default_config() {
        // Even if loopback is in the allowlist, default config refuses.
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "http://127.0.0.1:9999/".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        match err {
            ToolError::Failed(msg) => assert!(msg.contains("127.0.0.1")),
            other => panic!("expected Failed for SSRF, got {other:?}"),
        }
    }

    #[test]
    fn ssrf_refuses_private_ip_explicit_allowlist_and_default_config() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("10.0.0.1")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "http://10.0.0.1/".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        assert!(matches!(err, ToolError::Failed(_)));
    }

    #[test]
    fn invalid_url_rejected_before_any_other_gate() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("*")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "not-a-url".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    #[test]
    fn unsupported_scheme_rejected() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("*")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "ftp://example.com/".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        match err {
            ToolError::InvalidInput(msg) => assert!(msg.contains("scheme")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn input_must_be_valid_json() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("*")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: b"not json".to_vec(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    #[test]
    fn approval_policy_defaults_to_never() {
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("*")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "https://api.example.com/".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        assert_eq!(t.approval_policy(&call), ApprovalPolicy::Never);
    }

    // =====================================================================
    // Auth gate (broker integration)
    // =====================================================================
    //
    // The "happy path" auth tests live in tests/integration.rs because
    // they need a localhost mock server to verify the Authorization
    // header actually reached the wire. Here we only cover the
    // input-validation paths that don't open a socket.

    #[test]
    fn auth_set_with_no_broker_fails_closed_before_network() {
        // Allow * so the capability gate is permissive; no broker is
        // installed. Fetching a localhost URL would trip SSRF if we
        // got that far, but `Failed("...has no SecretBroker
        // configured")` should fire first because the auth check is
        // step 5 (after capability + SSRF, before the GET).
        //
        // We use a non-loopback public-ish URL so SSRF doesn't fire;
        // the auth gate fires before the network does.
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("api.example.com")]);
        assert!(!t.has_broker(), "test precondition: no broker");
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "https://api.example.com/me".into(),
                auth: Some(AuthSpec::BearerHeader {
                    secret_ref: "github.token".into(),
                }),
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        match err {
            ToolError::Failed(msg) => {
                assert!(
                    msg.contains("SecretBroker"),
                    "expected fail-closed message mentioning SecretBroker, got: {msg}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn auth_set_with_unknown_secret_fails_closed_before_network() {
        // A broker is configured, but it doesn't know the secret. The
        // tool must surface the BrokerError as Failed (not silently
        // proceed unauthenticated).
        let broker = Arc::new(uniclaw_secrets::InMemorySecretBroker::new());
        let t = HttpFetchTool::with_broker(vec![GlobPattern::new("api.example.com")], broker);
        assert!(t.has_broker());
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "https://api.example.com/".into(),
                auth: Some(AuthSpec::BearerHeader {
                    secret_ref: "github.token".into(),
                }),
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        match err {
            ToolError::Failed(msg) => {
                assert!(
                    msg.contains("github.token"),
                    "expected secret name in error, got: {msg}"
                );
                assert!(
                    msg.contains("not found") || msg.contains("fetch"),
                    "expected lookup-failure wording, got: {msg}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn capability_gate_runs_before_auth_gate() {
        // If the host is denied, we must error with CapabilityDenied —
        // not with a SecretBroker complaint. The capability gate is
        // step 3, the auth gate is step 5.
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("api.example.com")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "https://evil.test/".into(),
                auth: Some(AuthSpec::BearerHeader {
                    secret_ref: "github.token".into(),
                }),
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        let err = t.call(&call).unwrap_err();
        assert!(
            matches!(err, ToolError::CapabilityDenied { .. }),
            "expected capability gate to fire before auth gate, got: {err:?}"
        );
    }

    #[test]
    fn no_auth_means_no_broker_required() {
        // A tool without a broker can still serve unauthenticated
        // requests. We test up to the capability gate (further would
        // need a network mock); the point is that the auth check
        // doesn't complain when input.auth is None.
        let t = HttpFetchTool::with_allowlist(vec![GlobPattern::new("api.example.com")]);
        let call = ToolCall {
            tool_name: "http_fetch".into(),
            target: "...".into(),
            input: serde_json::to_vec(&HttpFetchInput {
                url: "https://denied.test/".into(),
                auth: None,
            })
            .unwrap(),
            input_hash: Digest([0u8; 32]),
        };
        // Fails on the capability gate, NOT on a missing-broker
        // complaint — proving the auth path was a no-op.
        let err = t.call(&call).unwrap_err();
        assert!(matches!(err, ToolError::CapabilityDenied { .. }));
    }

    #[test]
    fn has_broker_reflects_constructor() {
        let no_broker = HttpFetchTool::with_allowlist(vec![GlobPattern::new("*")]);
        assert!(!no_broker.has_broker());

        let broker = Arc::new(uniclaw_secrets::InMemorySecretBroker::new());
        let with_broker = HttpFetchTool::with_broker(vec![GlobPattern::new("*")], broker.clone());
        assert!(with_broker.has_broker());
    }
}
