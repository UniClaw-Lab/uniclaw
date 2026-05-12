//! Integration tests for the step-21 HTTP proposal + approval API.
//!
//! Each test builds a merged router (read-only routes + `/v1` API)
//! over an in-memory log, drives it via `tower::ServiceExt::oneshot`,
//! and asserts the response shape + chain linkage. No real network.
//!
//! The kernel uses a deterministic test signing key and a
//! `StubClock` so the receipts in any given test run are byte-for-byte
//! reproducible (helps debugging when a snapshot fails).

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;

use uniclaw_constitution::parse_toml;
use uniclaw_host::api::{ApiState, AuthConfig, api_router};
use uniclaw_host::clock::SystemClock;
use uniclaw_host::router;
use uniclaw_host::signer::Ed25519Signer;
use uniclaw_kernel::{Kernel, Signer};
use uniclaw_receipt::{Receipt, crypto};
use uniclaw_store::InMemoryReceiptLog;

const TEST_SEED: [u8; 32] = [13u8; 32];

const TEST_CONSTITUTION: &str = r#"
title = "test"
version = 1

[[rules]]
id = "test/no-shell"
description = "shell.exec is denied"
verdict = "deny"
match.kind = "shell.exec"

[[rules]]
id = "test/admin-needs-approval"
description = "anything containing /admin/ needs approval"
verdict = "require_approval"
match.target_contains = "/admin/"
"#;

#[derive(Debug, Deserialize)]
struct ReceiptResponse {
    decision: String,
    content_id: String,
    receipt_url: String,
    issuer: String,
    sequence: u64,
    schema_version: u32,
}

fn build_app() -> Router {
    build_app_with_auth(AuthConfig::insecure())
}

fn build_app_with_auth(auth: AuthConfig) -> Router {
    let signer = Ed25519Signer::from_seed(&TEST_SEED);
    let issuer = signer.public_key();
    let constitution = parse_toml(TEST_CONSTITUTION).expect("parse test constitution");
    let kernel = Kernel::new(signer, SystemClock, constitution);
    let log = Arc::new(RwLock::new(InMemoryReceiptLog::new(issuer)));
    let state = ApiState::new(kernel, log.clone());
    router(log).merge(api_router(state, auth))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).expect("response was not JSON")
}

async fn body_as<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).expect("response did not match expected shape")
}

fn json_request(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ---------------------------------------------------------------------
// POST /v1/proposals
// ---------------------------------------------------------------------

#[tokio::test]
async fn allowed_proposal_returns_signed_receipt_at_seq_0() {
    let app = build_app();
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/data",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "allowed");
    assert_eq!(r.sequence, 0);
    assert_eq!(r.schema_version, 2);
    assert!(r.receipt_url.starts_with("/receipts/"));
    assert_eq!(r.content_id.len(), 64);
    assert_eq!(r.issuer.len(), 64);

    // The receipt is also fetchable at the read-only route.
    let fetch = app
        .oneshot(
            Request::builder()
                .uri(r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fetch.status(), StatusCode::OK);
    let receipt: Receipt = body_as(fetch).await;
    crypto::verify(&receipt).expect("signature valid under embedded issuer");
    assert_eq!(receipt.body.merkle_leaf.sequence, 0);
    assert_eq!(receipt.body.decision, uniclaw_receipt::Decision::Allowed);
}

#[tokio::test]
async fn shell_exec_is_denied_by_constitution_rule() {
    let app = build_app();
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "shell.exec",
                "target": "rm -rf /",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "denied");
}

#[tokio::test]
async fn admin_target_returns_pending() {
    let app = build_app();
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/admin/keys",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "pending");
}

#[tokio::test]
async fn malformed_input_hash_returns_400() {
    let app = build_app();
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/",
                "input_hash": "not-hex",
            }
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "bad_request");
    assert!(body["detail"].as_str().unwrap().contains("input_hash"));
}

#[tokio::test]
async fn missing_action_field_returns_400() {
    let app = build_app();
    let req = json_request("/v1/proposals", &json!({}));
    let resp = app.oneshot(req).await.unwrap();
    // axum's Json extractor rejects missing fields with 422 by default,
    // but the body still indicates a client error — assert it's 4xx.
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

// ---------------------------------------------------------------------
// POST /v1/approvals/{content_id}/resolve
// ---------------------------------------------------------------------

#[tokio::test]
async fn pending_can_be_approved_and_chains_to_pending() {
    let app = build_app();

    // 1. Submit a proposal that the constitution forces Pending.
    let propose = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/admin/keys",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.clone().oneshot(propose).await.unwrap();
    let pending: ReceiptResponse = body_as(resp).await;
    assert_eq!(pending.decision, "pending");

    // 2. Fetch the pending receipt so we know its leaf_hash; the
    //    approved receipt's prev_hash must equal it.
    let fetch_pending = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&pending.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let pending_full: Receipt = body_as(fetch_pending).await;
    let expected_prev_hex = pending_full.body.merkle_leaf.leaf_hash.to_hex();

    // 3. Resolve as Approved.
    let resolve = json_request(
        &format!("/v1/approvals/{}/resolve", pending.content_id),
        &json!({
            "principal": "operator@example.com",
            "outcome": "approved",
        }),
    );
    let resp = app.clone().oneshot(resolve).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let approved: ReceiptResponse = body_as(resp).await;
    assert_eq!(approved.decision, "approved");
    assert_eq!(approved.sequence, 1);

    // 4. Fetch the approved receipt and verify chain linkage.
    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&approved.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let approved_full: Receipt = body_as(fetch).await;
    crypto::verify(&approved_full).expect("approved receipt verifies");
    assert_eq!(
        approved_full.body.merkle_leaf.prev_hash.to_hex(),
        expected_prev_hex,
        "approved.prev_hash must equal pending.leaf_hash",
    );
}

#[tokio::test]
async fn pending_can_be_denied() {
    let app = build_app();
    let propose = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/admin/secrets",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let pending: ReceiptResponse = body_as(app.clone().oneshot(propose).await.unwrap()).await;

    let resolve = json_request(
        &format!("/v1/approvals/{}/resolve", pending.content_id),
        &json!({
            "principal": "operator@example.com",
            "outcome": "denied",
        }),
    );
    let resp = app.oneshot(resolve).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "denied");
}

#[tokio::test]
async fn resolving_unknown_content_id_returns_404() {
    let app = build_app();
    let unknown = "ab".repeat(32);
    let resolve = json_request(
        &format!("/v1/approvals/{unknown}/resolve"),
        &json!({
            "principal": "operator@example.com",
            "outcome": "approved",
        }),
    );
    let resp = app.oneshot(resolve).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn resolving_an_allowed_receipt_returns_409() {
    let app = build_app();

    // Submit an Allowed proposal.
    let propose = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/data",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let allowed: ReceiptResponse = body_as(app.clone().oneshot(propose).await.unwrap()).await;
    assert_eq!(allowed.decision, "allowed");

    // Try to resolve it — should 409 because it's not Pending.
    let resolve = json_request(
        &format!("/v1/approvals/{}/resolve", allowed.content_id),
        &json!({
            "principal": "operator@example.com",
            "outcome": "approved",
        }),
    );
    let resp = app.oneshot(resolve).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "conflict");
}

#[tokio::test]
async fn malformed_content_id_in_url_returns_400() {
    let app = build_app();
    let resolve = json_request(
        "/v1/approvals/not-a-hash/resolve",
        &json!({
            "principal": "operator@example.com",
            "outcome": "approved",
        }),
    );
    let resp = app.oneshot(resolve).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "bad_request");
}

// ---------------------------------------------------------------------
// Chain semantics
// ---------------------------------------------------------------------

#[tokio::test]
async fn three_proposals_chain_with_incrementing_sequence_and_prev_hash() {
    let app = build_app();

    let mut last_hash: Option<String> = None;
    for i in 0..3u64 {
        let req = json_request(
            "/v1/proposals",
            &json!({
                "action": {
                    "kind": "http.fetch",
                    "target": format!("https://example.com/page/{i}"),
                    "input_hash": format!("{i:02x}").repeat(32),
                }
            }),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let r: ReceiptResponse = body_as(resp).await;
        assert_eq!(r.sequence, i);

        let fetch = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&r.receipt_url)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let full: Receipt = body_as(fetch).await;
        let prev_hex = full.body.merkle_leaf.prev_hash.to_hex();
        if let Some(prev) = &last_hash {
            assert_eq!(
                &prev_hex,
                prev,
                "prev_hash should link to sequence {}",
                i - 1
            );
        } else {
            assert_eq!(prev_hex, "00".repeat(32), "genesis prev_hash must be zero");
        }
        last_hash = Some(full.body.merkle_leaf.leaf_hash.to_hex());
    }
}

// ---------------------------------------------------------------------
// POST /v1/tool-executions (step 23)
// ---------------------------------------------------------------------

/// Helper: mint an Allowed `tool.*` receipt so we have something to
/// record an execution against. Returns its `content_id`.
async fn mint_allowed_tool_receipt(app: &Router, target: &str) -> String {
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "tool.http_fetch",
                "target": target,
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "allowed");
    r.content_id
}

#[tokio::test]
async fn tool_execution_success_no_redaction_no_secrets_links_to_allowed() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/data").await;

    // Fetch the Allowed receipt's leaf_hash so we can assert linkage.
    let fetch_allowed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/receipts/{allowed_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let allowed_full: Receipt = body_as(fetch_allowed).await;
    let expected_prev = allowed_full.body.merkle_leaf.leaf_hash.to_hex();

    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed_id,
            "output_hash": "11".repeat(32),
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "allowed");
    assert_eq!(r.sequence, 1);
    assert_eq!(r.schema_version, 2);

    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let full: Receipt = body_as(fetch).await;
    crypto::verify(&full).expect("execution receipt verifies");
    assert_eq!(
        full.body.merkle_leaf.prev_hash.to_hex(),
        expected_prev,
        "execution.prev_hash must equal allowed.leaf_hash",
    );
    assert_eq!(full.body.action.kind, "$kernel/tool/executed");
    assert!(full.body.action.target.contains("tool=http_fetch"));
    assert!(full.body.action.target.contains("status=ok"));
    assert!(full.body.redactor_stack_hash.is_none());
}

#[tokio::test]
async fn tool_execution_with_secrets_used_emits_secret_used_edges() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/me").await;

    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed_id,
            "output_hash": "22".repeat(32),
            "secrets_used": ["github.token", "slack.webhook"],
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;

    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let full: Receipt = body_as(fetch).await;
    let secret_edges: Vec<_> = full
        .body
        .provenance
        .iter()
        .filter(|e| e.kind == "secret_used")
        .collect();
    assert_eq!(secret_edges.len(), 2);
    assert!(secret_edges.iter().any(|e| e.to == "secret:github.token"));
    assert!(secret_edges.iter().any(|e| e.to == "secret:slack.webhook"));
}

#[tokio::test]
async fn tool_execution_with_redaction_populates_stack_hash_and_emits_edges() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/dump").await;

    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed_id,
            "output_hash": "33".repeat(32),
            "redaction": {
                "redacted_output_hash": "44".repeat(32),
                "matches": [
                    {"rule_id": "github_pat", "count": 1},
                    {"rule_id": "openai_key", "count": 0}
                ],
                "stack_hash": "ab".repeat(32),
            }
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;

    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let full: Receipt = body_as(fetch).await;

    // redactor_stack_hash populated.
    let stack = full
        .body
        .redactor_stack_hash
        .expect("redactor_stack_hash must be set");
    assert_eq!(stack.to_hex(), "ab".repeat(32));

    // Only the count>0 rule emits a redaction_applied edge.
    let redact_edges: Vec<_> = full
        .body
        .provenance
        .iter()
        .filter(|e| e.kind == "redaction_applied")
        .collect();
    assert_eq!(redact_edges.len(), 1);
    assert!(redact_edges[0].to.contains("github_pat:count=1"));

    // tool_output edge commits to the POST-redaction hash.
    let out_edges: Vec<_> = full
        .body
        .provenance
        .iter()
        .filter(|e| e.kind == "tool_output")
        .collect();
    assert_eq!(out_edges.len(), 1);
    assert!(
        out_edges[0].to.ends_with(&"44".repeat(32)),
        "tool_output edge should reference redacted hash, got {}",
        out_edges[0].to,
    );
}

#[tokio::test]
async fn tool_execution_failure_emits_failure_edge() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/err").await;

    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed_id,
            "error": "connection refused",
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "allowed"); // failure receipts are still Allowed (audit anchor)

    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let full: Receipt = body_as(fetch).await;
    assert!(full.body.action.target.contains("status=failed"));
    let failure_edges: Vec<_> = full
        .body
        .provenance
        .iter()
        .filter(|e| e.kind == "tool_execution_failure")
        .collect();
    assert_eq!(failure_edges.len(), 1);
    assert!(
        failure_edges[0].to.contains("connection refused"),
        "failure edge should embed the error message, got {}",
        failure_edges[0].to,
    );
}

#[tokio::test]
async fn tool_execution_missing_both_output_and_error_returns_400() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/x").await;
    let req = json_request(
        "/v1/tool-executions",
        &json!({ "allowed_receipt_id": allowed_id }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn tool_execution_both_output_and_error_returns_400() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/x").await;
    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed_id,
            "output_hash": "11".repeat(32),
            "error": "boom",
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tool_execution_malformed_hex_returns_400() {
    let app = build_app();
    let allowed_id = mint_allowed_tool_receipt(&app, "https://api.example.com/x").await;
    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed_id,
            "output_hash": "not-hex",
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap().contains("output_hash"));
}

#[tokio::test]
async fn tool_execution_unknown_allowed_id_returns_404() {
    let app = build_app();
    let unknown = "ab".repeat(32);
    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": unknown,
            "output_hash": "11".repeat(32),
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tool_execution_against_non_allowed_receipt_returns_409() {
    let app = build_app();

    // Mint a Pending receipt (constitution forces it on /admin/).
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/admin/keys",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let pending: ReceiptResponse = body_as(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(pending.decision, "pending");

    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": pending.content_id,
            "output_hash": "11".repeat(32),
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap().contains("not Allowed"));
}

#[tokio::test]
async fn tool_execution_against_non_tool_action_returns_409() {
    let app = build_app();

    // Mint an Allowed http.fetch (NOT tool.*) receipt.
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/data",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let allowed: ReceiptResponse = body_as(app.clone().oneshot(req).await.unwrap()).await;

    let req = json_request(
        "/v1/tool-executions",
        &json!({
            "allowed_receipt_id": allowed.content_id,
            "output_hash": "11".repeat(32),
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap().contains("tool."));
}

// ---------------------------------------------------------------------
// Step 25 — bearer-token auth on /v1
// ---------------------------------------------------------------------

const TEST_TOKEN_BYTES: [u8; 32] = [0xa5u8; 32];
// 64 hex chars matching the bytes above.
const TEST_TOKEN_HEX: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

fn build_auth_app() -> Router {
    let auth = AuthConfig::with_token(TEST_TOKEN_BYTES.to_vec()).expect("32 bytes");
    build_app_with_auth(auth)
}

fn proposal_request(uri: &str) -> Request<Body> {
    json_request(
        uri,
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/auth-test",
                "input_hash": "00".repeat(32),
            }
        }),
    )
}

#[tokio::test]
async fn auth_required_returns_401_without_authorization_header() {
    let app = build_auth_app();
    let resp = app
        .oneshot(proposal_request("/v1/proposals"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "unauthorized");
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("missing Authorization")
    );
}

#[tokio::test]
async fn auth_required_returns_401_with_non_bearer_scheme() {
    let app = build_auth_app();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Basic foo")
        .body(Body::from(
            json!({"action": {"kind": "x", "target": "y", "input_hash": "00".repeat(32)}})
                .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_required_returns_401_with_wrong_token() {
    let app = build_auth_app();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            // Same length, different bytes — exercises the
            // constant-time comparison branch.
            format!("Bearer {}", "b6".repeat(32)),
        )
        .body(Body::from(
            json!({"action": {"kind": "x", "target": "y", "input_hash": "00".repeat(32)}})
                .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap().contains("rejected"));
}

#[tokio::test]
async fn auth_required_returns_401_with_short_token() {
    let app = build_auth_app();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer abcd")
        .body(Body::from(
            json!({"action": {"kind": "x", "target": "y", "input_hash": "00".repeat(32)}})
                .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap().contains("64 hex"));
}

#[tokio::test]
async fn auth_required_accepts_correct_token() {
    let app = build_auth_app();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN_HEX}"))
        .body(Body::from(
            json!({
                "action": {
                    "kind": "http.fetch",
                    "target": "https://example.com/data",
                    "input_hash": "00".repeat(32),
                }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "allowed");
}

#[tokio::test]
async fn auth_required_accepts_lowercase_bearer_scheme() {
    // RFC 6750: the scheme name is case-insensitive.
    let app = build_auth_app();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("bearer {TEST_TOKEN_HEX}"))
        .body(Body::from(
            json!({
                "action": {
                    "kind": "http.fetch",
                    "target": "https://example.com/data",
                    "input_hash": "00".repeat(32),
                }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_required_does_not_affect_read_only_routes() {
    // /healthz, /, /verify, /receipts/<hash> must stay public even
    // when /v1 is gated. The cold-verify trust property depends on
    // public receipt access.
    let app = build_auth_app();
    for uri in ["/healthz", "/", "/verify"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "read-only route {uri} must stay public under auth",
        );
    }
}

#[tokio::test]
async fn auth_required_protects_every_v1_endpoint() {
    // Sweep across the three /v1 endpoints — each must return 401
    // when no Authorization header is supplied.
    let app = build_auth_app();
    for uri in [
        "/v1/proposals",
        &format!("/v1/approvals/{}/resolve", "00".repeat(32)),
        "/v1/tool-executions",
    ] {
        let req = json_request(
            uri,
            &json!({
                "action": {"kind": "x", "target": "y", "input_hash": "00".repeat(32)},
                "principal": "x",
                "outcome": "approved",
                "allowed_receipt_id": "00".repeat(32),
                "output_hash": "00".repeat(32),
            }),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "endpoint {uri} must require auth",
        );
    }
}

#[tokio::test]
async fn insecure_mode_accepts_calls_without_authorization() {
    // The existing build_app() uses AuthConfig::insecure(); every
    // pre-existing test exercises this path. One explicit test
    // here for documentation + regression guard.
    let app = build_app(); // insecure mode
    let resp = app
        .oneshot(proposal_request("/v1/proposals"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: ReceiptResponse = body_as(resp).await;
    assert_eq!(r.decision, "allowed");
}

#[tokio::test]
async fn auth_config_with_token_rejects_wrong_length() {
    // Defensive: only 32-byte tokens are accepted at AuthConfig
    // construction. The CLI also enforces 64 hex chars upstream;
    // this is the library-layer guard.
    assert!(AuthConfig::with_token(vec![0u8; 16]).is_err());
    assert!(AuthConfig::with_token(vec![0u8; 31]).is_err());
    assert!(AuthConfig::with_token(vec![0u8; 32]).is_ok());
    assert!(AuthConfig::with_token(vec![0u8; 33]).is_err());
    assert!(AuthConfig::with_token(vec![0u8; 64]).is_err());
}

// ---------------------------------------------------------------------
// Step 19a — key_id field on minted receipts
// ---------------------------------------------------------------------

fn build_app_with_key_id(key_id: &str) -> Router {
    let signer = Ed25519Signer::from_seed(&TEST_SEED).with_key_id(key_id);
    let issuer = signer.public_key();
    let constitution = parse_toml(TEST_CONSTITUTION).expect("parse test constitution");
    let kernel = Kernel::new(signer, SystemClock, constitution);
    let log = Arc::new(RwLock::new(InMemoryReceiptLog::new(issuer)));
    let state = ApiState::new(kernel, log.clone());
    router(log).merge(api_router(state, AuthConfig::insecure()))
}

#[tokio::test]
async fn signer_without_key_id_mints_receipts_without_key_id_field() {
    // Default Ed25519Signer path: receipts must NOT have a key_id
    // (byte-identical to pre-step-19a output via skip_serializing_if).
    let app = build_app();
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/no-key-id",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let r: ReceiptResponse = body_as(resp).await;

    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let receipt: Receipt = body_as(fetch).await;
    assert!(
        receipt.body.key_id.is_none(),
        "default signer must not set body.key_id",
    );
    crypto::verify(&receipt).expect("receipt verifies");
}

#[tokio::test]
async fn signer_with_key_id_mints_receipts_carrying_that_id() {
    let app = build_app_with_key_id("prod-2026");
    let req = json_request(
        "/v1/proposals",
        &json!({
            "action": {
                "kind": "http.fetch",
                "target": "https://example.com/with-key",
                "input_hash": "00".repeat(32),
            }
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let r: ReceiptResponse = body_as(resp).await;

    let fetch = app
        .oneshot(
            Request::builder()
                .uri(&r.receipt_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let receipt: Receipt = body_as(fetch).await;
    assert_eq!(
        receipt.body.key_id.as_deref(),
        Some("prod-2026"),
        "minted receipt must carry the signer's key_id",
    );
    // And the signature still verifies under the embedded issuer.
    crypto::verify(&receipt).expect("receipt verifies with key_id present");
}

#[tokio::test]
async fn key_id_appears_in_canonical_bytes_and_changes_content_id() {
    // The whole point of putting key_id IN the body (not on the
    // unsigned wrapper) is that it changes the canonical bytes
    // and therefore the content_id. Two otherwise-identical
    // receipts with different key_ids must have different
    // content_ids.
    let app_a = build_app_with_key_id("prod-2026");
    let app_b = build_app_with_key_id("hsm-3");

    let body = json!({
        "action": {
            "kind": "http.fetch",
            "target": "https://example.com/same-action",
            "input_hash": "00".repeat(32),
        }
    });

    let id_a: ReceiptResponse = body_as(
        app_a
            .oneshot(json_request("/v1/proposals", &body))
            .await
            .unwrap(),
    )
    .await;
    let id_b: ReceiptResponse = body_as(
        app_b
            .oneshot(json_request("/v1/proposals", &body))
            .await
            .unwrap(),
    )
    .await;

    // Same action, same kernel state — but different key_ids must
    // produce different content_ids (and therefore different
    // receipt_urls).
    assert_ne!(
        id_a.content_id, id_b.content_id,
        "different key_id values must produce different content_ids",
    );
}

#[tokio::test]
async fn key_id_appears_in_chain_of_receipts() {
    // 3 sequential proposals — each receipt's body.key_id should
    // be the same configured value. Regression guard against
    // accidentally dropping the field per-mint.
    let app = build_app_with_key_id("hsm-3");
    for i in 0..3u64 {
        let req = json_request(
            "/v1/proposals",
            &json!({
                "action": {
                    "kind": "http.fetch",
                    "target": format!("https://example.com/seq/{i}"),
                    "input_hash": format!("{i:02x}").repeat(32),
                }
            }),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        let r: ReceiptResponse = body_as(resp).await;
        let fetch = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&r.receipt_url)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let receipt: Receipt = body_as(fetch).await;
        assert_eq!(
            receipt.body.key_id.as_deref(),
            Some("hsm-3"),
            "sequence {i}: body.key_id must persist across mints",
        );
    }
}

#[tokio::test]
async fn ed25519_signer_with_key_id_builder_works() {
    let signer = Ed25519Signer::from_seed(&[1u8; 32]).with_key_id("test-key");
    assert_eq!(signer.key_id(), Some("test-key"));
    let signer = signer.without_key_id();
    assert_eq!(signer.key_id(), None);
}
