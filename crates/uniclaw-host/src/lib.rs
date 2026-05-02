//! Public-URL receipt hosting for Uniclaw.
//!
//! Master plan §21 #1 + §28 Phase 2. Turns `uniclaw://receipt/<hash>`
//! into something an external auditor can `curl`. The whole point is
//! **cold client-side verification** — the server returns the receipt
//! as it was stored, signature and all, and never claims that what it
//! served is correct. Verification stays the client's job (use
//! `uniclaw-verify` or any Ed25519-aware tool).
//!
//! ## Endpoints (v0)
//!
//! | Method | Path                 | Returns                                                   |
//! |--------|----------------------|-----------------------------------------------------------|
//! | GET    | `/receipts/<hex>`    | Canonical receipt JSON, or 404 with a small JSON error.   |
//! | GET    | `/healthz`           | `{"ok": true, "count": <log_len>}`                         |
//! | GET    | `/`                  | Minimal HTML index pointing at the docs and `/verify`.    |
//! | GET    | `/verify`            | Static HTML page that verifies a pasted receipt cold,     |
//! |        |                      | client-side, using `crypto.subtle` Ed25519. No server     |
//! |        |                      | round-trip — the page itself is the verifier.             |
//!
//! Receipts are content-addressed and immutable, so successful fetches
//! ship `Cache-Control: public, max-age=31536000, immutable` and a
//! strong `ETag` derived from the hash. CORS is permissive on every
//! response — the receipts are *meant* to be verifiable from any origin
//! without an account.
//!
//! ## Library shape
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use uniclaw_host::router;
//! use uniclaw_store::InMemoryReceiptLog;
//!
//! let log = Arc::new(RwLock::new(InMemoryReceiptLog::new(my_pubkey)));
//! let app = router(log);                        // axum::Router
//! // axum::serve(listener, app).await?;         // bind a port and go
//! ```
//!
//! Generic over any `ReceiptLog + Send + Sync + 'static`, so a future
//! SQLite-backed log slots in without touching this crate.
//!
//! ## Adopt-don't-copy
//!
//! Public, content-addressed, signed-receipt hosting in this shape is
//! net-new; no source borrowed from any of the nine reference claw
//! runtimes (none of them ship signed receipts, let alone host them).
//! The HTTP shape itself follows ordinary REST + cache conventions
//! (RFC 7234 / 9110 — `Cache-Control: immutable`, strong `ETag`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use uniclaw_receipt::{Digest, HexDecodeError};
use uniclaw_store::ReceiptLog;

/// Shared application state passed into every handler.
///
/// Generic over `L: ReceiptLog` so the same router serves an
/// `InMemoryReceiptLog` today and a SQLite-backed log in a follow-up
/// step. The receipt log is wrapped in a `tokio::sync::RwLock` because
/// axum handlers run on a multi-threaded runtime; readers do not block
/// each other while a writer (a future ingest path) holds the lock.
#[derive(Debug)]
pub struct AppState<L: ReceiptLog + Send + Sync + 'static> {
    /// The receipt log this host serves from.
    pub log: Arc<RwLock<L>>,
}

impl<L: ReceiptLog + Send + Sync + 'static> AppState<L> {
    /// Construct a new shared state from an `Arc<RwLock<L>>`.
    #[must_use]
    pub fn new(log: Arc<RwLock<L>>) -> Self {
        Self { log }
    }
}

/// Build the axum `Router` for the public receipt-hosting service.
///
/// The router serves three endpoints (see crate docs). CORS is
/// permissive on every route because receipts are designed to be
/// verifiable from any origin without authentication.
pub fn router<L>(log: Arc<RwLock<L>>) -> Router
where
    L: ReceiptLog + Send + Sync + 'static,
{
    let state = Arc::new(AppState::new(log));
    Router::new()
        .route("/", get(get_index))
        .route("/verify", get(get_verify_page))
        .route("/healthz", get(get_healthz::<L>))
        .route("/receipts/:hash_hex", get(get_receipt::<L>))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

/// Static HTML verifier page. Compiled into the binary via `include_str!`
/// — no filesystem read at runtime, no separate static-files directory
/// to deploy. The page itself does Ed25519 verification client-side
/// using `crypto.subtle`; the server never touches the receipt being
/// verified.
const VERIFY_PAGE: &str = include_str!("verify.html");

async fn get_verify_page() -> impl IntoResponse {
    // No-store on the verifier page so updates propagate without
    // CDN caching surprises. The receipts themselves stay
    // immutable-cached at `/receipts/<hex>`.
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        VERIFY_PAGE,
    )
}

/// Body for the small JSON 404 we return when a hash is unknown.
#[derive(Serialize)]
struct NotFoundBody<'a> {
    error: &'a str,
    hash: &'a str,
}

/// Body for the small JSON 400 we return when the URL hash is malformed.
#[derive(Serialize)]
struct BadRequestBody<'a> {
    error: &'a str,
    detail: &'a str,
}

/// Body for `/healthz`.
#[derive(Serialize)]
struct HealthBody {
    ok: bool,
    count: usize,
}

async fn get_index() -> impl IntoResponse {
    const BODY: &str = concat!(
        "<!doctype html>\n",
        "<html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<title>Uniclaw — verifiable receipt host</title></head>",
        "<body style=\"font-family: system-ui, sans-serif; max-width: 40em; margin: 4em auto; line-height: 1.5;\">",
        "<h1>Uniclaw</h1>",
        "<p>This service hosts <strong>signed, content-addressed receipts</strong> ",
        "produced by a Uniclaw kernel. Each receipt is verifiable cold ",
        "(no API call, no account) using the issuer's Ed25519 public key.</p>",
        "<p>Want to check one right now? ",
        "<a href=\"/verify\"><strong>Open the in-browser verifier →</strong></a></p>",
        "<h2>Endpoints</h2>",
        "<ul>",
        "<li><code>GET /receipts/&lt;hex&gt;</code> — fetch a receipt by content hash.</li>",
        "<li><code>GET /verify</code> — paste a receipt, verify it client-side.</li>",
        "<li><code>GET /healthz</code> — JSON liveness probe.</li>",
        "</ul>",
        "<p>See <a href=\"https://github.com/UniClaw-Lab/uniclaw\">the project on GitHub</a> ",
        "for the receipt format spec and the offline command-line verifier.</p>",
        "</body></html>",
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        BODY,
    )
}

async fn get_healthz<L>(State(state): State<Arc<AppState<L>>>) -> impl IntoResponse
where
    L: ReceiptLog + Send + Sync + 'static,
{
    let count = state.log.read().await.len();
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(HealthBody { ok: true, count }),
    )
        .into_response()
}

async fn get_receipt<L>(
    State(state): State<Arc<AppState<L>>>,
    Path(hash_hex): Path<String>,
    headers: HeaderMap,
) -> Response
where
    L: ReceiptLog + Send + Sync + 'static,
{
    // Parse the hex into a Digest. Bad hex → 400 with a small JSON body.
    let digest = match Digest::from_hex(&hash_hex) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(BadRequestBody {
                    error: "invalid_hash",
                    detail: hex_error_detail(e),
                }),
            )
                .into_response();
        }
    };

    // Build the strong ETag once — it's just the hex form back, in quotes.
    // (The hash IS the canonical id; no other ETag is meaningful.)
    let etag_value = format!("\"{}\"", digest.to_hex());

    // If the client already has this exact hash, save them the body.
    if client_has_etag(&headers, &etag_value) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag_value.as_str()),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
        )
            .into_response();
    }

    // Look up under a read lock; the trait returns an owned receipt so we
    // can release the lock immediately. Read locks don't block other readers.
    let receipt = {
        let log = state.log.read().await;
        log.get_by_id(&digest)
    };

    let Some(receipt) = receipt else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            axum::Json(NotFoundBody {
                error: "receipt_not_found",
                hash: &hash_hex,
            }),
        )
            .into_response();
    };

    // 200 with immutable cache + strong ETag. Receipts are content-addressed,
    // so the body for a given hash never changes — cache forever is correct.
    (
        StatusCode::OK,
        [
            (header::ETAG, etag_value.as_str()),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        axum::Json(receipt),
    )
        .into_response()
}

fn hex_error_detail(e: HexDecodeError) -> &'static str {
    match e {
        HexDecodeError::InvalidLength { .. } => "hash must be 64 hex characters",
        HexDecodeError::InvalidCharacter => "hash contained a non-hex character",
    }
}

fn client_has_etag(headers: &HeaderMap, etag: &str) -> bool {
    let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) else {
        return false;
    };
    let Ok(value) = if_none_match.to_str() else {
        return false;
    };
    // Tolerate weak ETag prefixes ("W/...") even though we only mint strong
    // ones; spec says the comparison is weak for If-None-Match.
    let trimmed = value.trim().trim_start_matches("W/");
    trimmed == etag
}

/// Construct a `HeaderValue` from a static string. Helper for the rare
/// case a caller wants to sniff the immutable cache header value.
#[must_use]
pub fn immutable_cache_header() -> HeaderValue {
    HeaderValue::from_static("public, max-age=31536000, immutable")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use tokio::sync::RwLock;

    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use tower::ServiceExt;
    use uniclaw_receipt::{
        Action, Decision, Digest, MerkleLeaf, PublicKey, RECEIPT_FORMAT_VERSION, Receipt,
        ReceiptBody, crypto,
    };
    use uniclaw_store::InMemoryReceiptLog;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pubkey(k: &SigningKey) -> PublicKey {
        PublicKey(k.verifying_key().to_bytes())
    }

    fn receipt_at(k: &SigningKey, seq: u64, prev: Digest, target: &str) -> Receipt {
        let mut body = ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at: format!("2026-04-28T00:00:{seq:02}Z"),
            action: Action {
                kind: "http.fetch".into(),
                target: target.into(),
                input_hash: Digest([0u8; 32]),
            },
            decision: Decision::Allowed,
            constitution_rules: vec![],
            provenance: vec![],
            redactor_stack_hash: None,
            merkle_leaf: MerkleLeaf {
                sequence: seq,
                leaf_hash: Digest([0u8; 32]),
                prev_hash: prev,
            },
        };
        let canonical = serde_json::to_vec(&body).expect("encode body");
        body.merkle_leaf.leaf_hash = Digest(*blake3::hash(&canonical).as_bytes());
        crypto::sign(body, k)
    }

    /// Build a router with a log holding `n` valid, chained receipts and
    /// return both the router and the receipts (for assertions).
    fn fixture(n: u64) -> (Router, Vec<Receipt>) {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let mut receipts = Vec::new();
        let mut prev = Digest([0u8; 32]);
        for i in 0..n {
            let r = receipt_at(&k, i, prev, &format!("https://example.com/{i}"));
            prev = r.body.merkle_leaf.leaf_hash;
            log.append(r.clone()).expect("append");
            receipts.push(r);
        }
        let app = router(Arc::new(RwLock::new(log)));
        (app, receipts)
    }

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn healthz_reports_log_count() {
        let (app, _) = fixture(3);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"ok\":true"));
        assert!(body.contains("\"count\":3"));
    }

    #[tokio::test]
    async fn index_returns_html() {
        let (app, _) = fixture(0);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().starts_with("text/html"));
    }

    #[tokio::test]
    async fn known_hash_returns_canonical_receipt_json() {
        let (app, receipts) = fixture(2);
        let target = receipts[0].clone();
        let id = target.content_id();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{}", id.to_hex()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Cache headers say immutable + strong ETag matching the hash.
        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache.contains("immutable"));
        assert!(cache.contains("max-age=31536000"));

        let etag = resp.headers().get(header::ETAG).unwrap().to_str().unwrap();
        assert_eq!(etag, format!("\"{}\"", id.to_hex()));

        // Body round-trips back into the same Receipt and verifies cold.
        let body = body_string(resp).await;
        let parsed: Receipt = serde_json::from_str(&body).expect("parse");
        assert_eq!(parsed, target);
        crypto::verify(&parsed).expect("served receipt verifies");
    }

    #[tokio::test]
    async fn unknown_hash_returns_404_json() {
        let (app, _) = fixture(1);
        let other = Digest([0xCD; 32]).to_hex();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{other}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // 404 must NOT be cached — the receipt could appear later.
        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "no-store");
        let body = body_string(resp).await;
        assert!(body.contains("\"error\":\"receipt_not_found\""));
    }

    #[tokio::test]
    async fn malformed_hash_returns_400() {
        let (app, _) = fixture(1);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/receipts/not-a-hash")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("\"error\":\"invalid_hash\""));
    }

    #[tokio::test]
    async fn matching_if_none_match_returns_304() {
        let (app, receipts) = fixture(1);
        let id = receipts[0].content_id();
        let etag = format!("\"{}\"", id.to_hex());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{}", id.to_hex()))
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn cors_header_is_permissive() {
        let (app, _) = fixture(1);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header(header::ORIGIN, "https://auditor.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let allow = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("ACAO header set")
            .to_str()
            .unwrap();
        // Permissive layer echoes the origin or returns "*" depending on
        // tower-http defaults; either is acceptable for our use case.
        assert!(allow == "*" || allow == "https://auditor.example.com");
    }

    // --- Phase 2 step 4: HTML verifier page ---

    #[tokio::test]
    async fn verify_page_is_served_with_html_content_type() {
        let (app, _) = fixture(0);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type set")
            .to_str()
            .unwrap();
        assert!(
            ct.starts_with("text/html"),
            "Content-Type was {ct:?}, expected text/html",
        );

        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("Cache-Control set")
            .to_str()
            .unwrap();
        assert_eq!(
            cache, "no-store",
            "verifier page must not be cached so updates propagate",
        );
    }

    #[tokio::test]
    async fn verify_page_contains_essential_ui_and_crypto_subtle_call() {
        let (app, _) = fixture(0);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_string(resp).await;

        // Title + form elements an auditor-end-user would look for.
        assert!(body.contains("Uniclaw Receipt Verifier"));
        assert!(body.contains("<textarea"));
        assert!(body.contains("Verify"));

        // The whole point: it does Ed25519 in the browser. If a refactor
        // ever drops the SubtleCrypto call, this test catches it.
        assert!(body.contains(r#"crypto.subtle.verify("Ed25519""#));
        assert!(body.contains("crypto.subtle.importKey"));
        assert!(body.contains(r#"name: "Ed25519""#));

        // Browser-support warning is present (and starts hidden).
        assert!(body.contains("warn-noed25519"));
        assert!(body.contains("hidden"));

        // No external resources — the verifier must be entirely
        // self-contained, otherwise the trust model leaks. Rough check:
        // no <script src=...>, no <link rel="stylesheet" href=...>.
        assert!(
            !body.contains("<script src="),
            "verifier page must not load external scripts",
        );
        assert!(
            !body.contains("<link rel=\"stylesheet\""),
            "verifier page must not load external stylesheets",
        );
    }

    #[tokio::test]
    async fn index_page_links_to_verifier() {
        let (app, _) = fixture(0);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_string(resp).await;
        // The index must surface the verifier — otherwise users won't
        // discover it.
        assert!(
            body.contains("/verify"),
            "index page must link to /verify so users find the in-browser verifier",
        );
    }

    #[tokio::test]
    async fn verify_page_has_no_cors_origin_block_for_static_assets() {
        // Sanity: even though the page is static, the CORS layer should
        // still apply (an embedding site might want to fetch it).
        let (app, _) = fixture(0);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/verify")
                    .header(header::ORIGIN, "https://auditor.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let allow = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("ACAO header set on /verify too")
            .to_str()
            .unwrap();
        assert!(allow == "*" || allow == "https://auditor.example.com");
    }
}
