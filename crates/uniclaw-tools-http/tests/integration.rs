//! Integration tests for `HttpFetchTool` against a hand-rolled
//! localhost HTTP/1.1 server. Hand-rolled (not axum/hyper/wiremock) to
//! keep this crate's dev-dep tree empty — we already pull in ureq +
//! url + `serde_json` transitively, that's enough.
//!
//! Tests use `HttpFetchConfig::for_test_localhost()` so the SSRF
//! gate doesn't block us on `127.0.0.1` (production config refuses
//! it). One test stays on the default config to confirm SSRF still
//! triggers there.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use base64::Engine;

use uniclaw_receipt::Digest;
use uniclaw_tools::{Capability, GlobPattern, Tool, ToolCall, ToolError};
use uniclaw_tools_http::{HttpFetchConfig, HttpFetchInput, HttpFetchOutput, HttpFetchTool};

/// What a route should return when matched.
#[derive(Clone)]
struct Response {
    status: u16,
    reason: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    delay: Option<Duration>,
}

impl Response {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: vec![("content-type", "text/plain".to_string())],
            body: body.into(),
            delay: None,
        }
    }
    fn not_found() -> Self {
        Self {
            status: 404,
            reason: "Not Found",
            headers: vec![("content-type", "text/plain".to_string())],
            body: b"missing".to_vec(),
            delay: None,
        }
    }
    fn slow(d: Duration) -> Self {
        let mut r = Self::ok(b"slow".to_vec());
        r.delay = Some(d);
        r
    }
}

/// Blocking single-threaded mock server bound to 127.0.0.1:0. The
/// `MockServer` Drop signals the loop to stop.
struct MockServer {
    addr: String,
    stop: Arc<Mutex<bool>>,
}

impl MockServer {
    fn start(routes: impl Fn(&str) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap().to_string();
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");

        let stop = Arc::new(Mutex::new(false));
        let stop_for_thread = stop.clone();
        let routes = Arc::new(routes);

        let (ready_tx, ready_rx) = mpsc::channel::<()>();

        thread::spawn(move || {
            let _ = ready_tx.send(());
            loop {
                if *stop_for_thread.lock().unwrap() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let routes = routes.clone();
                        thread::spawn(move || {
                            let _ = handle_one(stream, routes.as_ref());
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        // Wait for the listener loop to be live before returning.
        let _ = ready_rx.recv_timeout(Duration::from_secs(1));

        Self { addr, stop }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
        // Best-effort wake: open a dummy connection so accept() returns.
        let _ = std::net::TcpStream::connect(&self.addr);
    }
}

fn handle_one(
    mut stream: TcpStream,
    routes: &(dyn Fn(&str) -> Response + Send + Sync),
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    // Read request headers (until \r\n\r\n).
    let mut buf = [0u8; 4096];
    let mut acc = Vec::with_capacity(1024);
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if acc.len() > 32 * 1024 {
            return Ok(());
        }
    }
    let req = String::from_utf8_lossy(&acc).to_string();
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();

    let resp = routes(&path);
    if let Some(d) = resp.delay {
        thread::sleep(d);
    }

    write!(stream, "HTTP/1.1 {} {}\r\n", resp.status, resp.reason)?;
    write!(stream, "content-length: {}\r\n", resp.body.len())?;
    write!(stream, "connection: close\r\n")?;
    for (k, v) in &resp.headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&resp.body)?;
    Ok(())
}

/// Helper: build a tool with the localhost-allowing config + a
/// permissive allowlist for `127.0.0.1`.
fn tool_for_localhost() -> HttpFetchTool {
    HttpFetchTool::with_config(
        vec![GlobPattern::new("127.0.0.1")],
        HttpFetchConfig::for_test_localhost(),
    )
}

fn make_call(url: &str) -> ToolCall {
    ToolCall {
        tool_name: "http_fetch".into(),
        target: url.into(),
        input: serde_json::to_vec(&HttpFetchInput {
            url: url.to_string(),
        })
        .unwrap(),
        input_hash: Digest([0u8; 32]),
    }
}

fn parse_envelope(out: &uniclaw_tools::ToolOutput) -> HttpFetchOutput {
    serde_json::from_slice(&out.bytes).expect("envelope is valid JSON")
}

// =====================================================================
// Happy path
// =====================================================================

#[test]
fn fetches_a_simple_200_and_returns_envelope_with_body() {
    let server = MockServer::start(|_| Response::ok(b"hello world".to_vec()));
    let tool = tool_for_localhost();

    let out = tool.call(&make_call(&server.url("/"))).expect("ok");
    let env = parse_envelope(&out);

    assert_eq!(env.status, 200);
    let body = base64::engine::general_purpose::STANDARD
        .decode(&env.body_b64)
        .unwrap();
    assert_eq!(body, b"hello world");

    // Header names are lowercased; content-type should be present.
    let ct = env
        .headers
        .iter()
        .find(|(n, _)| n == "content-type")
        .map(|(_, v)| v.as_str());
    assert_eq!(ct, Some("text/plain"));

    // output_hash is BLAKE3 of the envelope JSON.
    let expected = Digest(*blake3::hash(&out.bytes).as_bytes());
    assert_eq!(out.output_hash, expected);
}

// =====================================================================
// 4xx is NOT an error — the response is returned with its status
// =====================================================================

#[test]
fn fetches_a_404_and_returns_404_status_not_an_error() {
    let server = MockServer::start(|_| Response::not_found());
    let tool = tool_for_localhost();

    let out = tool.call(&make_call(&server.url("/missing"))).expect("ok");
    let env = parse_envelope(&out);

    assert_eq!(env.status, 404);
    let body = base64::engine::general_purpose::STANDARD
        .decode(&env.body_b64)
        .unwrap();
    assert_eq!(body, b"missing");
}

// =====================================================================
// Capability allowlist actually denies before any network IO
// =====================================================================

#[test]
fn capability_denied_when_host_not_in_allowlist() {
    // Tool only allows api.example.com — the request goes to localhost.
    // The capability gate fires before the SSRF gate, so we get
    // CapabilityDenied (not Failed).
    let tool = HttpFetchTool::with_config(
        vec![GlobPattern::new("api.example.com")],
        HttpFetchConfig::for_test_localhost(),
    );
    let err = tool
        .call(&make_call("http://127.0.0.1:1/"))
        .expect_err("should refuse");
    match err {
        ToolError::CapabilityDenied {
            attempted: Capability::NetConnect(g),
        } => assert_eq!(g.as_str(), "127.0.0.1"),
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

// =====================================================================
// SSRF refuses loopback under default config
// =====================================================================

#[test]
fn default_config_refuses_loopback_even_with_matching_capability() {
    // Allowlist matches 127.0.0.1, but allow_private_ips=false.
    let tool = HttpFetchTool::with_allowlist(vec![GlobPattern::new("127.0.0.1")]);
    let err = tool
        .call(&make_call("http://127.0.0.1:1/"))
        .expect_err("should refuse");
    match err {
        ToolError::Failed(msg) => assert!(msg.contains("127.0.0.1")),
        other => panic!("expected Failed for SSRF refusal, got {other:?}"),
    }
}

// =====================================================================
// Oversize response is refused
// =====================================================================

#[test]
fn oversize_response_is_refused_without_returning_partial_body() {
    let server = MockServer::start(|_| {
        // 12 KiB of 'a'.
        Response::ok(vec![b'a'; 12 * 1024])
    });
    let tool = HttpFetchTool::with_config(
        vec![GlobPattern::new("127.0.0.1")],
        HttpFetchConfig {
            max_response_bytes: 8 * 1024, // smaller than the body
            ..HttpFetchConfig::for_test_localhost()
        },
    );

    let err = tool
        .call(&make_call(&server.url("/big")))
        .expect_err("oversize must be refused");
    match err {
        ToolError::Failed(msg) => assert!(
            msg.contains("max_response_bytes"),
            "expected size-limit message, got: {msg}"
        ),
        other => panic!("expected Failed, got {other:?}"),
    }
}

// =====================================================================
// Timeout
// =====================================================================

#[test]
fn slow_response_times_out() {
    // Server delays 2s; tool timeout is 250 ms.
    let server = MockServer::start(|_| Response::slow(Duration::from_secs(2)));
    let tool = HttpFetchTool::with_config(
        vec![GlobPattern::new("127.0.0.1")],
        HttpFetchConfig {
            timeout: Duration::from_millis(250),
            ..HttpFetchConfig::for_test_localhost()
        },
    );

    let err = tool
        .call(&make_call(&server.url("/slow")))
        .expect_err("should time out");
    // ureq's transport error covers both connect and read timeouts;
    // we accept either Timeout or Failed-with-timeout-like-message.
    match err {
        ToolError::Timeout => {}
        ToolError::Failed(msg) => {
            assert!(
                msg.contains("timed out") || msg.contains("deadline") || msg.contains("timeout"),
                "expected timeout-flavored Failed, got: {msg}"
            );
        }
        other => panic!("expected Timeout/Failed-timeout, got {other:?}"),
    }
}

// =====================================================================
// Non-UTF8 bytes survive base64 round-trip
// =====================================================================

#[test]
fn non_utf8_response_body_survives_base64_round_trip() {
    let bytes: Vec<u8> = (0..=255).collect(); // every byte value 0..=255
    let server = MockServer::start({
        let bytes = bytes.clone();
        move |_| Response::ok(bytes.clone())
    });
    let tool = tool_for_localhost();

    let out = tool.call(&make_call(&server.url("/"))).expect("ok");
    let env = parse_envelope(&out);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&env.body_b64)
        .expect("valid base64");
    assert_eq!(decoded, bytes);
}

// =====================================================================
// 3xx is NOT auto-followed
// =====================================================================

#[test]
fn redirects_are_not_auto_followed() {
    // Server returns 302 with a Location header to evil.test. Our tool
    // must NOT follow — that would be a capability bypass.
    let server = MockServer::start(|_| {
        let mut r = Response::ok(b"".to_vec());
        r.status = 302;
        r.reason = "Found";
        r.headers = vec![
            ("location", "http://evil.test/".to_string()),
            ("content-type", "text/plain".to_string()),
        ];
        r
    });
    let tool = tool_for_localhost();

    let out = tool.call(&make_call(&server.url("/redir"))).expect("ok");
    let env = parse_envelope(&out);
    assert_eq!(env.status, 302);
    let location = env
        .headers
        .iter()
        .find(|(n, _)| n == "location")
        .map(|(_, v)| v.as_str());
    assert_eq!(location, Some("http://evil.test/"));
    // The caller decides what to do with the redirect; we don't follow.
}
