//! Integration tests for [`uniclaw_tools_wasm::WasmTool::from_component_bytes_with_host`]
//! — the 16c host-imports path.
//!
//! Loads the committed `http-tool-component.wasm` fixture (built
//! from `tests/fixtures/http-tool-component/`) and drives it
//! against a local mock HTTP server. The fixture's `call(input)`
//! takes a small ASCII command (`"fetch <url>"`,
//! `"fetch_auth <url> <secret-ref>"`, `"check <name>"`, `"now"`,
//! `"log"`) and uses the corresponding host import.
//!
//! The point of these tests is to verify that calls FROM the
//! guest go through the SAME machinery that direct host-side
//! `HttpFetchTool::call` does:
//! - capability allowlist enforcement,
//! - SSRF gate (with `for_test_localhost()` config),
//! - broker-backed Authorization header injection,
//! - oversize / timeout / trap → Err(string) returned to guest,
//! - `secrets_used` accumulated in the host's `HostState` and
//!   surfaced into `ToolOutput::metadata.secrets_used`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use uniclaw_receipt::Digest;
use uniclaw_secrets::{InMemorySecretBroker, SecretBroker};
use uniclaw_tools::{
    ApprovalPolicy, Capability, GlobPattern, Tool, ToolCall, ToolError, ToolManifest,
};
use uniclaw_tools_http::{HttpFetchConfig, HttpFetchTool};
use uniclaw_tools_wasm::{WasmConfig, WasmTool};

const HTTP_TOOL_COMPONENT: &[u8] = include_bytes!("fixtures/http-tool-component.wasm");

// =====================================================================
// Mock HTTP server — same shape as uniclaw-tools-http's integration
// tests. Records request headers so we can verify the host's auth
// injection actually reached the wire.
// =====================================================================

#[derive(Debug, Clone)]
struct Captured {
    headers: Vec<(String, String)>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct MockServer {
    addr: String,
    stop: Arc<Mutex<bool>>,
    captures: Arc<Mutex<Vec<Captured>>>,
}

impl MockServer {
    fn start(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(Mutex::new(false));
        let stop_for_thread = stop.clone();
        let captures: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
        let captures_for_thread = captures.clone();
        let body = Arc::new(body);
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            let _ = ready_tx.send(());
            loop {
                if *stop_for_thread.lock().unwrap() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let body = body.clone();
                        let captures = captures_for_thread.clone();
                        thread::spawn(move || {
                            let _ = handle(stream, &body, &captures);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        let _ = ready_rx.recv_timeout(Duration::from_secs(1));
        Self {
            addr,
            stop,
            captures,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn captured(&self) -> Vec<Captured> {
        self.captures.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(&self.addr);
    }
}

fn handle(
    mut stream: TcpStream,
    body: &[u8],
    captures: &Mutex<Vec<Captured>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 1024];
    let mut acc = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&acc).to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in req.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    captures.lock().unwrap().push(Captured { headers });

    write!(stream, "HTTP/1.1 200 OK\r\n")?;
    write!(stream, "content-length: {}\r\n", body.len())?;
    write!(stream, "content-type: application/octet-stream\r\n")?;
    write!(stream, "connection: close\r\n\r\n")?;
    stream.write_all(body)?;
    Ok(())
}

// =====================================================================
// Test plumbing
// =====================================================================

fn manifest(name: &str) -> ToolManifest {
    ToolManifest {
        name: name.into(),
        description: "host-imports test fixture".into(),
        action_kind: format!("tool.{name}"),
        declared_capabilities: vec![Capability::NetConnect(GlobPattern::new("noop"))],
        default_approval: ApprovalPolicy::Never,
    }
}

fn make_call(input: &[u8]) -> ToolCall {
    ToolCall {
        tool_name: "wasm".into(),
        target: "test".into(),
        input: input.to_vec(),
        input_hash: Digest(*blake3::hash(input).as_bytes()),
    }
}

/// Build a `HttpFetchTool` with localhost-friendly config (SSRF
/// gate disabled for 127.0.0.1) plus the configured allowlist.
fn http_with_allowlist(allowed_hosts: Vec<GlobPattern>) -> Arc<HttpFetchTool> {
    Arc::new(HttpFetchTool::with_config(
        allowed_hosts,
        HttpFetchConfig::for_test_localhost(),
    ))
}

/// Build a `HttpFetchTool` that uses a broker (so `bearer-header`
/// auth works end to end).
fn http_with_broker(
    allowed_hosts: Vec<GlobPattern>,
    broker: Arc<dyn SecretBroker>,
) -> Arc<HttpFetchTool> {
    Arc::new(HttpFetchTool::with_broker_and_config(
        allowed_hosts,
        broker,
        HttpFetchConfig::for_test_localhost(),
    ))
}

fn empty_broker() -> Arc<dyn SecretBroker> {
    Arc::new(InMemorySecretBroker::new())
}

// =====================================================================
// Host imports actually reach the host (and the host actually
// satisfies them).
// =====================================================================

#[test]
fn guest_http_fetch_returns_response_body_to_guest() {
    let server = MockServer::start(b"hello via wasm".to_vec());
    let http = http_with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
    let broker = empty_broker();

    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        broker,
    )
    .expect("compiles");

    let cmd = format!("fetch {}", server.url());
    let out = tool.call(&make_call(cmd.as_bytes())).expect("ok");
    assert_eq!(out.bytes, b"hello via wasm");

    // 200-status was hit; the server saw a real request.
    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    // Unauthenticated request — no Authorization header on the wire.
    assert!(captured[0].header("authorization").is_none());

    // Guest used no secrets.
    assert!(out.metadata.secrets_used.is_empty());
}

#[test]
fn guest_http_fetch_with_bearer_auth_injects_secret_via_broker() {
    let server = MockServer::start(b"authed body".to_vec());

    let mut broker_state = InMemorySecretBroker::new();
    broker_state.insert_string("github.token", "ghp_test_token_xyz".to_string());
    let broker: Arc<dyn SecretBroker> = Arc::new(broker_state);

    let http = http_with_broker(vec![GlobPattern::new("127.0.0.1")], Arc::clone(&broker));

    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        Arc::clone(&broker),
    )
    .unwrap();

    let cmd = format!("fetch_auth {} github.token", server.url());
    let out = tool.call(&make_call(cmd.as_bytes())).expect("ok");
    assert_eq!(out.bytes, b"authed body");

    // The Authorization header reached the wire — the broker
    // injection went through HttpFetchTool's existing logic.
    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].header("authorization"),
        Some("Bearer ghp_test_token_xyz"),
    );

    // The secret reference name (NEVER the value) is in
    // ToolOutput.metadata.secrets_used. The kernel will mint
    // `secret_used` provenance edges from this list.
    assert_eq!(out.metadata.secrets_used, vec!["github.token".to_string()]);
}

#[test]
fn guest_http_fetch_capability_denied_surfaces_as_guest_err_string() {
    // HttpFetchTool's allowlist is api.example.com; the guest
    // tries 127.0.0.1. The host-side capability check refuses,
    // and the guest sees `Err(string)` — NOT a wasm trap.
    let server = MockServer::start(b"never reached".to_vec());
    let http = http_with_allowlist(vec![GlobPattern::new("api.example.com")]);
    let broker = empty_broker();

    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        broker,
    )
    .unwrap();

    // Sanity — the URL is real but the allowlist refuses it.
    let cmd = format!("fetch {}", server.url());
    let err = tool
        .call(&make_call(cmd.as_bytes()))
        .expect_err("must fail");
    match err {
        ToolError::Failed(msg) => {
            assert!(
                msg.contains("guest:") && msg.contains("capability denied"),
                "expected guest-relayed capability denial, got: {msg}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    // No request reached the server — fail-closed.
    assert!(server.captured().is_empty());
}

#[test]
fn guest_http_fetch_with_unknown_secret_fail_closes_without_request() {
    // Broker is empty; the guest asks for `bearer-header(github.token)`.
    // HttpFetchTool's broker fetch fails; the guest sees Err.
    let server = MockServer::start(b"unreachable".to_vec());
    let broker = empty_broker();
    let http = http_with_broker(vec![GlobPattern::new("127.0.0.1")], Arc::clone(&broker));

    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        Arc::clone(&broker),
    )
    .unwrap();

    let cmd = format!("fetch_auth {} github.token", server.url());
    let err = tool
        .call(&make_call(cmd.as_bytes()))
        .expect_err("must fail");
    match err {
        ToolError::Failed(msg) => {
            assert!(
                msg.contains("guest:") && msg.contains("github.token"),
                "expected guest-relayed broker failure, got: {msg}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    // No network IO — fail-closed before the host touches the
    // socket. The metadata-aggregation behaviour (the secret_ref
    // still landing in secrets_used even though the fetch failed)
    // is exercised by `guest_http_fetch_with_bearer_auth_injects_secret_via_broker`
    // on the success path; on the failure path here, the
    // important property is *no socket open*.
    assert!(server.captured().is_empty());
}

#[test]
fn guest_secret_exists_returns_yes_for_registered_no_for_unknown() {
    let mut broker_state = InMemorySecretBroker::new();
    broker_state.insert_string("known.key", "value".to_string());
    let broker: Arc<dyn SecretBroker> = Arc::new(broker_state);

    let http = http_with_allowlist(vec![GlobPattern::new("127.0.0.1")]);

    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        Arc::clone(&broker),
    )
    .unwrap();

    let yes = tool
        .call(&make_call(b"check known.key"))
        .expect("known check works");
    assert_eq!(yes.bytes, b"yes");
    // Crucially: the guest only got back "yes" — not the value.
    // ToolOutput.metadata is empty because secret-exists doesn't
    // touch via auth-spec (no broker.fetch in the auth-injection
    // path).
    assert!(yes.metadata.secrets_used.is_empty());

    let no = tool
        .call(&make_call(b"check unregistered.key"))
        .expect("unknown check works");
    assert_eq!(no.bytes, b"no");
}

#[test]
fn guest_now_millis_returns_a_recent_unix_epoch_value() {
    let http = http_with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
    let broker = empty_broker();
    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        broker,
    )
    .unwrap();

    let out = tool.call(&make_call(b"now")).expect("ok");
    let body = std::str::from_utf8(&out.bytes).unwrap();
    let t: u64 = body.parse().expect("decimal millis");
    // Sanity: should be well past 1970-01-01 (any millisecond
    // count from a real clock satisfies this).
    assert!(t > 1_700_000_000_000, "now-millis returned {t}");
    // Should not be in the absurd-future range.
    assert!(t < u64::from(u32::MAX) * 1000 * 100, "{t} too large");
}

#[test]
fn guest_log_message_does_not_crash_and_is_dropped_in_v0() {
    // Logs accumulate in HostState but aren't surfaced via
    // ToolOutput in v0 (a future step exposes them in
    // ToolMetadata). The point of this test: the host-side
    // log-message path runs without panicking.
    let http = http_with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
    let broker = empty_broker();
    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        WasmConfig::default(),
        http,
        broker,
    )
    .unwrap();

    let out = tool.call(&make_call(b"log")).expect("log call works");
    assert_eq!(out.bytes, b"ok");
}

#[test]
fn host_imports_path_inherits_fuel_bound_from_16a() {
    // Tight fuel; the very first instruction the canonical ABI
    // executes blows the budget. We reach into the Tool::call
    // dispatch path for ComponentWithHost — same map_wasm_error
    // mapping, so the result is `Failed("fuel exhausted")`.
    let http = http_with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
    let broker = empty_broker();
    let cfg = WasmConfig {
        fuel: 0,
        ..WasmConfig::default()
    };
    let tool = WasmTool::from_component_bytes_with_host(
        HTTP_TOOL_COMPONENT,
        manifest("http-tool"),
        cfg,
        http,
        broker,
    )
    .unwrap();

    let err = tool.call(&make_call(b"now")).expect_err("must trap");
    match err {
        ToolError::Failed(msg) => assert!(msg.contains("fuel"), "got: {msg}"),
        other => panic!("expected Failed(fuel...), got {other:?}"),
    }
}

#[test]
fn host_imports_invalid_bytes_fail_at_construction() {
    let http = http_with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
    let broker = empty_broker();
    let err = WasmTool::from_component_bytes_with_host(
        b"not a wasm component",
        manifest("bad"),
        WasmConfig::default(),
        http,
        broker,
    )
    .expect_err("must reject");
    assert!(matches!(
        err,
        uniclaw_tools_wasm::BuildError::InvalidWasm(_)
    ));
}
