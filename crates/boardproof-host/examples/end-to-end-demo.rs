//! Phase 3.5 step 20 — BoardProof end-to-end demo.
//!
//! A single runnable artifact that exercises the whole Phase 3 wedge:
//! kernel + constitution + budget + approval + HTTP tool + secret broker
//! + redactor + signed receipts + browser verifier. Run it, get URLs,
//!   paste them into the verifier, see the wedge work in 30 seconds.
//!
//! ## What this demo proves
//!
//! 1. **Allowed.** Plain http.fetch passes the constitution and gets
//!    a signed Allowed receipt.
//! 2. **Pending → Approved.** A risky path triggers
//!    `RuleVerdict::RequireApproval`. The kernel mints a Pending
//!    receipt; the demo auto-resolves it as a synthetic operator;
//!    the kernel mints an Approved receipt linked back to Pending
//!    via the chain (`prev_hash` matches the pending receipt's
//!    `leaf_hash`).
//! 3. **Denied.** A blocked action (`shell.exec`) trips a `Deny` rule.
//!    The receipt records the denial; no tool runs.
//! 4. **Tool execution + `secret_used`.** `HttpFetchTool` injects an
//!    Authorization header from a broker reference. The receipt's
//!    provenance edges include `secret_used → secret:github.token`
//!    (the NAME, never the value).
//! 5. **Tool execution + redaction.** The mock server returns a
//!    body containing `ghp_...`. The redactor matches the GitHub PAT
//!    pattern, replaces it with `[REDACTED:default::github_pat]`, and
//!    the receipt commits to the post-redaction `output_hash` plus a
//!    `redaction_applied` provenance edge.
//!
//! ## Why this matters
//!
//! Until step 20, every piece of the wedge was provable in isolation
//! (each step has its own tests). The demo is the first artifact that
//! makes the wedge VISIBLE: a third party who has never read the code
//! can run it, paste a URL, and see the trust property work end to end.
//!
//! ## Run
//!
//! ```bash
//! cargo run --release --example end-to-end-demo -p boardproof-host
//! ```
//!
//! Then open the printed URLs in any browser. Visit `/verify`, paste
//! a receipt URL or its raw JSON, and the page reconstructs the
//! canonical bytes (RFC 8785 JCS, step 19), recomputes the BLAKE3
//! `content_id`, and verifies the Ed25519 signature client-side. The
//! verifier never trusts the host; that's the point.
//!
//! Press Ctrl+C to stop the server.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use tokio::sync::RwLock;

use boardproof_approval::ApprovalDecision;
use boardproof_constitution::{InMemoryConstitution, MatchClause, Rule, RuleVerdict};
use boardproof_host::router;
use boardproof_kernel::{Approval, Clock, Kernel, KernelEvent, Proposal, Signer, ToolExecution};
use boardproof_receipt::{Action, Decision, Digest, PublicKey, Receipt, ReceiptBody, crypto};
use boardproof_redact::{PatternRedactor, Redactor};
use boardproof_secrets::{InMemorySecretBroker, SecretBroker};
use boardproof_store::{InMemoryReceiptLog, ReceiptLog};
use boardproof_tools::{GlobPattern, Tool, ToolCall};
use boardproof_tools_http::{
    AuthSpec, HttpFetchConfig, HttpFetchInput, HttpFetchOutput, HttpFetchTool,
};

// ---------------------------------------------------------------------
// Signer + Clock for the kernel (test-grade — deterministic key, real
// system clock).
// ---------------------------------------------------------------------

struct Ed25519Signer(SigningKey);

impl Signer for Ed25519Signer {
    fn sign(&self, body: ReceiptBody) -> Receipt {
        crypto::sign(body, &self.0)
    }
    fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_iso8601(&self) -> String {
        // Cheap-and-cheerful: fixed prefix + a counter wouldn't be
        // realistic. For the demo we just stamp epoch-millis.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        format!(
            "1970-01-01T00:00:00.{:03}Z+epoch{}",
            now.subsec_millis(),
            now.as_secs()
        )
    }
}

// ---------------------------------------------------------------------
// Tiny mock HTTP server. Routes:
//   /data            → 200 "public data"
//   /admin/keys      → 200 "secret keys list"
//   /api/me          → 200 echoes the Authorization header so the demo
//                       can show what the host actually sent
//   /api/dump        → 200 body containing a fake GitHub PAT to redact
// ---------------------------------------------------------------------

fn start_mock_server() -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("mock addr");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    thread::spawn(move || {
        while !stop_for_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(move || {
                        let _ = handle_mock(stream);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (addr, stop)
}

fn handle_mock(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
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
    }
    let req = String::from_utf8_lossy(&acc).to_string();
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();

    // Echo Authorization back so the secret_used demo step can SHOW
    // the bearer header reached the wire (without revealing the value
    // in the receipt — only the name landed in metadata.secrets_used).
    let auth_echoed = req
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_default();

    let body = match path.as_str() {
        "/data" => "public data — no auth needed".to_string(),
        "/admin/keys" => "[demo] admin keys would be here".to_string(),
        "/api/me" => format!("server saw header: {auth_echoed}"),
        "/api/dump" => {
            // Embed a fake GitHub PAT shape so the redactor has
            // something to match. The trailing run is 36 chars of
            // [A-Za-z0-9] (no underscores — those'd break the
            // \b boundary in the default github_pat rule, which
            // matches `\bghp_[A-Za-z0-9]{30,}`).
            "user_id=42 token=ghp_demoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA done".to_string()
        }
        _ => "not found".to_string(),
    };

    write!(stream, "HTTP/1.1 200 OK\r\n")?;
    write!(stream, "content-length: {}\r\n", body.len())?;
    write!(stream, "content-type: text/plain\r\n")?;
    write!(stream, "connection: close\r\n\r\n")?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------
// Constitution
// ---------------------------------------------------------------------

fn build_constitution() -> InMemoryConstitution {
    InMemoryConstitution::from_rules(vec![
        Rule {
            id: "demo/no-shell".to_string(),
            description: "Block any shell.exec — agent should never run a shell.".to_string(),
            verdict: RuleVerdict::Deny,
            match_clause: MatchClause {
                kind: Some("shell.exec".to_string()),
                target_contains: None,
            },
        },
        Rule {
            id: "demo/admin-requires-approval".to_string(),
            description: "Anything touching /admin/ needs human approval first.".to_string(),
            verdict: RuleVerdict::RequireApproval,
            match_clause: MatchClause {
                kind: None,
                target_contains: Some("/admin/".to_string()),
            },
        },
    ])
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn proposal_for_action(kind: &str, target: String, input_hash: Digest) -> Proposal {
    Proposal::unbounded(
        Action {
            kind: kind.to_string(),
            target,
            input_hash,
        },
        // Default decision pre-evaluation. The kernel + constitution
        // override based on rules.
        Decision::Allowed,
        vec![],
        vec![],
    )
}

fn hash_bytes(b: &[u8]) -> Digest {
    Digest(*blake3::hash(b).as_bytes())
}

fn short(d: &Digest) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(8);
    for b in &d.0[..4] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn full_hex(d: &Digest) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in &d.0 {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// Build a raw HttpFetchTool ToolCall (input = serialized HttpFetchInput).
fn http_call(url: &str, auth: Option<AuthSpec>) -> ToolCall {
    let input = serde_json::to_vec(&HttpFetchInput {
        url: url.to_string(),
        auth,
    })
    .expect("encode HttpFetchInput");
    let input_hash = hash_bytes(&input);
    ToolCall {
        tool_name: "http_fetch".into(),
        target: url.into(),
        input,
        input_hash,
    }
}

// Decode HttpFetchOutput's base64-encoded body so the demo can
// show what the tool actually returned (useful for the redaction
// step where the body contains the leaked credential before the
// redactor runs over it).
fn decoded_body(out_bytes: &[u8]) -> Vec<u8> {
    let env: HttpFetchOutput = serde_json::from_slice(out_bytes).expect("envelope");
    base64::engine::general_purpose::STANDARD
        .decode(env.body_b64)
        .expect("base64 body")
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------

// The demo's main walks 5 actions in sequence so a reader can
// follow the narrative top-to-bottom. Splitting into helper fns
// would obscure the storyline; the demo's value is in readability,
// not modularity.
#[allow(clippy::too_many_lines)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    println!();
    println!("BoardProof end-to-end demo");
    println!("=======================");
    println!();
    println!("Phase 3.5 step 20. Wires every shipped component into one runnable artifact.");
    println!();

    // ------------------------------------------------------------
    // Build the runtime
    // ------------------------------------------------------------

    let (mock_addr, _mock_stop) = start_mock_server();
    println!("Mock HTTP server bound at http://{mock_addr}/");

    // Deterministic signer key for reproducibility. Production
    // deployments use HSM-backed signers; we use a fixed test key
    // so the demo's receipt content_ids are stable across runs.
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let signer = Ed25519Signer(signing_key.clone());
    let issuer_hex = full_hex(&Digest(signer.public_key().0));

    let constitution = build_constitution();
    let mut kernel = Kernel::new(signer, SystemClock, constitution);

    // HttpFetchTool — allowlist for 127.0.0.1, with broker for
    // bearer-auth. for_test_localhost() disables the SSRF gate
    // (production refuses literal-IP private/loopback by default).
    let mut broker_state = InMemorySecretBroker::new();
    broker_state.insert_string(
        "github.token",
        "ghp_demo_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    );
    let broker: Arc<dyn SecretBroker> = Arc::new(broker_state);
    let http_tool: Arc<HttpFetchTool> = Arc::new(HttpFetchTool::with_broker_and_config(
        vec![GlobPattern::new("127.0.0.1")],
        Arc::clone(&broker),
        HttpFetchConfig::for_test_localhost(),
    ));

    let redactor = PatternRedactor::with_defaults("demo");

    let log = Arc::new(RwLock::new(InMemoryReceiptLog::new(PublicKey(
        signing_key.verifying_key().to_bytes(),
    ))));

    println!("Built:");
    println!("  - Kernel issuer (Ed25519 public key): {issuer_hex}");
    println!("  - Constitution: 2 rules (deny shell.exec, require-approval on /admin/)");
    println!("  - HttpFetchTool: allowlist 127.0.0.1, broker-backed Bearer auth");
    println!("  - SecretBroker: 1 secret (github.token)");
    println!("  - Redactor: PatternRedactor with default credential rules");
    println!();

    // Helper: append a receipt to the log and return a borrow.
    let append = |receipt: Receipt| async {
        let mut g = log.write().await;
        g.append(receipt.clone()).expect("append");
        receipt
    };

    let mut receipts: Vec<(String, Receipt)> = Vec::new();

    // ------------------------------------------------------------
    // [1/5] Allowed
    // ------------------------------------------------------------

    println!("[1/5] Allowed");
    println!("    Action: http.fetch /data — public endpoint, no rules trip.");

    let p1 = proposal_for_action(
        "http.fetch",
        format!("http://{mock_addr}/data"),
        Digest([1u8; 32]),
    );
    let r1 = kernel
        .handle(KernelEvent::evaluate(p1))
        .expect("evaluate")
        .receipt;
    println!("    Decision: {:?}", r1.body.decision);
    println!(
        "    leaf_hash: {} ...",
        short(&r1.body.merkle_leaf.leaf_hash)
    );
    let r1 = append(r1).await;
    receipts.push(("Allowed".into(), r1));

    // ------------------------------------------------------------
    // [2/5] Pending → Approved
    // ------------------------------------------------------------

    println!();
    println!("[2/5] Pending → Approved");
    println!("    Action: http.fetch /admin/keys — admin-requires-approval rule fires.");

    let p2 = proposal_for_action(
        "http.fetch",
        format!("http://{mock_addr}/admin/keys"),
        Digest([2u8; 32]),
    );
    let r2_pending = kernel
        .handle(KernelEvent::evaluate(p2.clone()))
        .expect("evaluate")
        .receipt;
    println!("    First receipt decision: {:?}", r2_pending.body.decision);
    println!("    Auto-resolving with synthetic principal 'demo-operator'...");

    let approval = Approval {
        pending_receipt: r2_pending.clone(),
        original_proposal: p2,
        response: ApprovalDecision::Approved,
    };
    let r2_approved = kernel
        .handle(KernelEvent::resolve(approval))
        .expect("resolve")
        .receipt;
    println!(
        "    Second receipt decision: {:?}, prev_hash chains back to pending: {}",
        r2_approved.body.decision,
        r2_approved.body.merkle_leaf.prev_hash == r2_pending.body.merkle_leaf.leaf_hash,
    );
    let r2_pending = append(r2_pending).await;
    let r2_approved = append(r2_approved).await;
    receipts.push(("Pending".into(), r2_pending));
    receipts.push(("Approved".into(), r2_approved));

    // ------------------------------------------------------------
    // [3/5] Denied
    // ------------------------------------------------------------

    println!();
    println!("[3/5] Denied");
    println!("    Action: shell.exec rm -rf / — no-shell rule fires.");

    let p3 = proposal_for_action("shell.exec", "rm -rf /".into(), Digest([3u8; 32]));
    let r3 = kernel
        .handle(KernelEvent::evaluate(p3))
        .expect("evaluate")
        .receipt;
    println!("    Decision: {:?}. Tool never runs.", r3.body.decision);
    let r3 = append(r3).await;
    receipts.push(("Denied".into(), r3));

    // ------------------------------------------------------------
    // [4/5] Tool execution + secret_used
    // ------------------------------------------------------------

    println!();
    println!("[4/5] Tool execution + secret_used");
    println!("    Action: http.fetch /api/me with auth=BearerHeader{{secret_ref=github.token}}.");

    // Step A: evaluate the proposal.
    let url = format!("http://{mock_addr}/api/me");
    let call = http_call(
        &url,
        Some(AuthSpec::BearerHeader {
            secret_ref: "github.token".into(),
        }),
    );
    let p4 = proposal_for_action("tool.http_fetch", url.clone(), call.input_hash);
    let r4_allowed = kernel
        .handle(KernelEvent::evaluate(p4.clone()))
        .expect("evaluate")
        .receipt;
    let r4_allowed = append(r4_allowed).await;

    // Step B: execute the tool. HttpFetchTool fetches the secret
    // through the broker, injects the Authorization header, makes
    // the request, and returns the JSON envelope.
    let tool_out = http_tool.call(&call).expect("HttpFetchTool::call ok");
    let body = decoded_body(&tool_out.bytes);
    println!(
        "    Mock server saw: {}",
        String::from_utf8_lossy(&body).trim()
    );

    // Step C: anchor the result in the chain. metadata.secrets_used
    // carries 'github.token' (the NAME) — never the value.
    let exec = ToolExecution {
        allowed_receipt: r4_allowed,
        original_proposal: p4,
        result: Ok(tool_out),
        redaction: None,
    };
    let r4_executed = kernel
        .handle(KernelEvent::record_tool_execution(exec))
        .expect("record")
        .receipt;
    let secret_edges: Vec<_> = r4_executed
        .body
        .provenance
        .iter()
        .filter(|e| e.kind == "secret_used")
        .collect();
    println!(
        "    Receipt mints {} secret_used provenance edge(s):",
        secret_edges.len()
    );
    for e in &secret_edges {
        println!("        {} → {}", e.from, e.to);
    }
    let r4_executed = append(r4_executed).await;
    receipts.push(("Tool+Secret".into(), r4_executed));

    // ------------------------------------------------------------
    // [5/5] Tool execution + redaction
    // ------------------------------------------------------------

    println!();
    println!("[5/5] Tool execution + redaction");
    println!("    Action: http.fetch /api/dump — mock server returns a body with a fake PAT.");

    let url = format!("http://{mock_addr}/api/dump");
    let call = http_call(&url, None);
    let p5 = proposal_for_action("tool.http_fetch", url.clone(), call.input_hash);
    let r5_allowed = kernel
        .handle(KernelEvent::evaluate(p5.clone()))
        .expect("evaluate")
        .receipt;
    let r5_allowed = append(r5_allowed).await;

    let tool_out = http_tool.call(&call).expect("HttpFetchTool::call ok");
    let raw_body = decoded_body(&tool_out.bytes);
    println!(
        "    Pre-redaction body: {}",
        String::from_utf8_lossy(&raw_body).trim()
    );

    // The HttpFetchTool's output is a JSON envelope with the body
    // base64-encoded inside `body_b64`. A redactor that scanned
    // those bytes wouldn't find `ghp_…` because base64 garbles
    // ASCII patterns. Real production redactors run over the
    // *meaningful* bytes — for HTTP, that's the decoded body.
    //
    // Pattern: decode → redact → re-encode the envelope → hash.
    // The kernel takes the resulting RedactionReport (with the
    // *new* hash committed to the post-redaction envelope) and
    // mints `redaction_applied` provenance edges.
    let body_redaction = redactor.redact(&raw_body);
    println!(
        "    Redactor matched {} rule(s):",
        body_redaction.report.matches.len()
    );
    for m in &body_redaction.report.matches {
        println!("        rule={} count={}", m.rule_id, m.count);
    }

    // Re-encode the envelope with the redacted body so the
    // receipt commits to the post-redaction form.
    let envelope: HttpFetchOutput = serde_json::from_slice(&tool_out.bytes).unwrap();
    let new_envelope = HttpFetchOutput {
        status: envelope.status,
        headers: envelope.headers,
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_redaction.redacted_bytes),
    };
    let new_envelope_bytes = serde_json::to_vec(&new_envelope).unwrap();
    let final_redaction_report = boardproof_receipt::RedactionReport {
        redacted_output_hash: hash_bytes(&new_envelope_bytes),
        matches: body_redaction.report.matches.clone(),
        stack_hash: body_redaction.report.stack_hash,
    };

    let exec = ToolExecution {
        allowed_receipt: r5_allowed,
        original_proposal: p5,
        result: Ok(tool_out),
        redaction: Some(final_redaction_report),
    };
    let r5_executed = kernel
        .handle(KernelEvent::record_tool_execution(exec))
        .expect("record")
        .receipt;

    let redaction_edges: Vec<_> = r5_executed
        .body
        .provenance
        .iter()
        .filter(|e| e.kind == "redaction_applied")
        .collect();
    println!(
        "    Receipt commits to post-redaction output_hash; emits {} redaction_applied edge(s):",
        redaction_edges.len()
    );
    for e in &redaction_edges {
        println!("        {} → {}", e.from, e.to);
    }
    println!(
        "    body.redactor_stack_hash present: {}",
        r5_executed.body.redactor_stack_hash.is_some()
    );
    let r5_executed = append(r5_executed).await;
    receipts.push(("Tool+Redact".into(), r5_executed));

    // ------------------------------------------------------------
    // Spin up the host
    // ------------------------------------------------------------

    let app = router(Arc::clone(&log));
    let bind: SocketAddr = "127.0.0.1:0".parse()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let host_addr = listener.local_addr()?;

    println!();
    println!("---------------------------------------------------------------");
    println!("Receipts published. Open these in any browser:");
    println!();
    for (label, r) in &receipts {
        let id = r.content_id();
        println!(
            "    [{label:<13}] http://{host_addr}/receipts/{}",
            full_hex(&id)
        );
    }
    println!();
    println!("To verify any of these:");
    println!("    1. Open http://{host_addr}/verify");
    println!("    2. Paste a receipt URL or its full JSON.");
    println!("    3. The page reconstructs canonical bytes (RFC 8785 JCS),");
    println!("       recomputes BLAKE3, and verifies the Ed25519 signature");
    println!("       client-side. The verifier never trusts this server.");
    println!();
    println!("Issuer public key (paste this into the verifier if asked):");
    println!("    {issuer_hex}");
    println!();
    println!("Press Ctrl+C to stop.");
    println!("---------------------------------------------------------------");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            println!();
            println!("Stopping demo.");
        })
        .await?;

    Ok(())
}
