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

use boardproof_receipt::Digest;
use boardproof_secrets::InMemorySecretBroker;
use boardproof_tools::{Capability, GlobPattern, Tool, ToolCall, ToolError};
use boardproof_tools_http::{HttpFetchConfig, HttpFetchInput, HttpFetchOutput, HttpFetchTool};

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

/// One captured request as the server saw it: parsed headers from
/// the request line block. Tests use this to verify e.g. an
/// `Authorization` header was actually injected on the wire.
///
/// Note: we don't capture path/method here because the existing
/// `routes` callback already gets the path. Add fields if a future
/// test needs to assert on more than headers.
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

/// Blocking single-threaded mock server bound to 127.0.0.1:0. The
/// `MockServer` Drop signals the loop to stop.
///
/// Every served request is recorded into `captures` so tests can
/// assert on what reached the wire (header values, path, etc.) — used
/// for the auth-injection tests.
struct MockServer {
    addr: String,
    stop: Arc<Mutex<bool>>,
    captures: Arc<Mutex<Vec<Captured>>>,
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
        let captures: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
        let captures_for_thread = captures.clone();

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
                        let captures = captures_for_thread.clone();
                        thread::spawn(move || {
                            let _ = handle_one(stream, routes.as_ref(), &captures);
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

        Self {
            addr,
            stop,
            captures,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Snapshot of every request the server has handled so far.
    fn captured(&self) -> Vec<Captured> {
        self.captures.lock().unwrap().clone()
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
    captures: &Mutex<Vec<Captured>>,
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

    // Parse headers — second line onward, up to the empty separator.
    // Values keep their original case (HTTP headers are case-insensitive
    // by name, case-preserving by value).
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
            auth: None,
        })
        .unwrap(),
        input_hash: Digest([0u8; 32]),
    }
}

/// Variant of `make_call` that attaches a [`boardproof_tools_http::AuthSpec`]
/// directing the tool to inject `Authorization: Bearer <broker[ref]>`.
fn make_auth_call(url: &str, secret_ref: &str) -> ToolCall {
    ToolCall {
        tool_name: "http_fetch".into(),
        target: url.into(),
        input: serde_json::to_vec(&HttpFetchInput {
            url: url.to_string(),
            auth: Some(boardproof_tools_http::AuthSpec::BearerHeader {
                secret_ref: secret_ref.to_string(),
            }),
        })
        .unwrap(),
        input_hash: Digest([0u8; 32]),
    }
}

fn parse_envelope(out: &boardproof_tools::ToolOutput) -> HttpFetchOutput {
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
// Timeout — measured by elapsed time, not by error wording
// =====================================================================

#[test]
fn slow_response_returns_error_well_before_the_server_delay() {
    // The server takes 4 s to respond; tool timeout is 250 ms. We
    // check two things, both platform-agnostic:
    //
    //   (a) the call returns Err — any variant. We do *not* match on
    //       error wording, because socket-timeout messages differ
    //       across operating systems (Linux: "timed out"; Windows:
    //       "did not properly respond after a period of time"; macOS:
    //       "Operation timed out"). Earlier versions of this test
    //       grep'd for "timed out" / "deadline" / "timeout" and broke
    //       on Windows CI. Don't repeat that mistake.
    //
    //   (b) it returned in roughly the timeout window, well short of
    //       the 4 s server delay, proving the timeout actually fired
    //       (not that we got an unrelated transport failure that
    //       just happened to surface).
    //
    // 1.5 s is generous slop on a loaded CI runner; the timeout is
    // 250 ms.
    let server = MockServer::start(|_| Response::slow(Duration::from_secs(4)));
    let tool = HttpFetchTool::with_config(
        vec![GlobPattern::new("127.0.0.1")],
        HttpFetchConfig {
            timeout: Duration::from_millis(250),
            ..HttpFetchConfig::for_test_localhost()
        },
    );

    let started = std::time::Instant::now();
    let result = tool.call(&make_call(&server.url("/slow")));
    let elapsed = started.elapsed();

    assert!(result.is_err(), "expected timeout-induced error, got Ok");
    assert!(
        elapsed < Duration::from_millis(1500),
        "tool waited {elapsed:?} — timeout (250 ms) did not fire well \
         before the 4 s server delay",
    );
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

// =====================================================================
// Auth: SecretBroker injects Authorization header on the wire
// =====================================================================

#[test]
fn authenticated_request_injects_authorization_bearer_header() {
    let server = MockServer::start(|_| Response::ok(b"hello".to_vec()));

    let mut broker = InMemorySecretBroker::new();
    broker.insert_string("github.token", "ghp_secret_xyz".to_string());
    let tool = HttpFetchTool::with_broker_and_config(
        vec![GlobPattern::new("127.0.0.1")],
        Arc::new(broker),
        HttpFetchConfig::for_test_localhost(),
    );

    let out = tool
        .call(&make_auth_call(&server.url("/"), "github.token"))
        .expect("authenticated request should succeed");

    // Metadata records the *reference name*, not the value. The
    // kernel reads this off `output.metadata.secrets_used` to mint
    // `secret_used` provenance edges in the receipt.
    assert_eq!(out.metadata.secrets_used, vec!["github.token".to_string()]);

    let captured = server.captured();
    assert!(
        !captured.is_empty(),
        "server should have received a request"
    );
    let auth = captured[0].header("authorization");
    assert_eq!(
        auth,
        Some("Bearer ghp_secret_xyz"),
        "tool must inject Authorization: Bearer <value> on the wire"
    );
}

#[test]
fn unauthenticated_request_carries_no_authorization_header() {
    let server = MockServer::start(|_| Response::ok(b"hello".to_vec()));
    let tool = tool_for_localhost();

    let out = tool.call(&make_call(&server.url("/"))).expect("ok");
    assert!(
        out.metadata.secrets_used.is_empty(),
        "no secret was used; metadata should be empty"
    );

    let captured = server.captured();
    assert!(
        !captured.is_empty(),
        "server should have received a request"
    );
    assert!(
        captured[0].header("authorization").is_none(),
        "no Authorization header on an unauthenticated request"
    );
}

#[test]
fn unknown_secret_fails_closed_without_opening_a_socket() {
    // Empty broker — the tool can't satisfy `auth`. The fail-closed
    // semantic is: surface the error AND don't make any network IO.
    // We assert both: an Err result, and zero captured requests.
    let server = MockServer::start(|_| Response::ok(b"unreachable".to_vec()));
    let broker = InMemorySecretBroker::new(); // empty
    let tool = HttpFetchTool::with_broker_and_config(
        vec![GlobPattern::new("127.0.0.1")],
        Arc::new(broker),
        HttpFetchConfig::for_test_localhost(),
    );

    let err = tool
        .call(&make_auth_call(&server.url("/"), "github.token"))
        .expect_err("unknown secret must fail");
    match err {
        ToolError::Failed(msg) => {
            assert!(
                msg.contains("github.token"),
                "expected secret name in error message, got: {msg}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    assert!(
        server.captured().is_empty(),
        "no network IO should fire when the broker can't satisfy auth"
    );
}

#[test]
fn auth_input_with_no_broker_fails_closed_without_opening_a_socket() {
    // Same fail-closed property, different cause: the tool was built
    // without a broker but the input asks for auth. The point of
    // having two tests is that one exercises the "broker missing"
    // branch and the other exercises the "broker fetch failed"
    // branch — both must short-circuit before any socket opens.
    let server = MockServer::start(|_| Response::ok(b"unreachable".to_vec()));
    let tool = HttpFetchTool::with_config(
        vec![GlobPattern::new("127.0.0.1")],
        HttpFetchConfig::for_test_localhost(),
    );
    assert!(!tool.has_broker());

    let err = tool
        .call(&make_auth_call(&server.url("/"), "github.token"))
        .expect_err("missing broker must fail");
    match err {
        ToolError::Failed(msg) => assert!(msg.contains("SecretBroker"), "got: {msg}"),
        other => panic!("expected Failed, got {other:?}"),
    }

    assert!(
        server.captured().is_empty(),
        "no network IO should fire when no broker is configured"
    );
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
