//! HTTP proposal + approval API (step 21).
//!
//! Mounted at `/v1` by [`crate::api_router`] when the host is started
//! with a constitution. The endpoints expose the kernel's
//! `EvaluateProposal` and `ResolveApproval` paths over HTTP, so any
//! claw (`OpenClaw`, `NemoClaw`, `NanoClaw`, etc.) can integrate via
//! the "local sidecar" pattern from the war analysis without
//! embedding the Rust kernel.
//!
//! ## Endpoints
//!
//! | Method | Path                                  | Mints                              |
//! |--------|---------------------------------------|-------------------------------------|
//! | POST   | `/v1/proposals`                       | `evaluate_proposal` receipt         |
//! | POST   | `/v1/approvals/{content_id}/resolve`  | `resolve_approval` receipt          |
//! | POST   | `/v1/tool-executions`                 | `$kernel/tool/executed` receipt     |
//!
//! Receipts produced here flow into the same in-memory log the
//! read-only routes (`/receipts/<hash>`, step 9) serve from, so a
//! client can immediately fetch any minted receipt by `content_id`.
//!
//! ## Trust model
//!
//! Step 25 adds first-class **bearer-token authentication** on the
//! `/v1` surface. The auth config is supplied to [`api_router`] at
//! startup:
//!
//! - [`AuthConfig::with_token`] — every `/v1` request must carry
//!   `Authorization: Bearer <hex>` matching the configured token
//!   (constant-time comparison). Missing or wrong → 401.
//! - [`AuthConfig::insecure`] — accept every `/v1` call. Operators
//!   must opt in via `--insecure-no-auth` on the binary (a startup
//!   `WARN` line is printed in this mode).
//!
//! Read-only routes (`/receipts/<hash>`, `/verify`, `/`, `/healthz`)
//! stay public regardless — the cold-verify trust property requires
//! public access to receipts.
//!
//! The binary's safe default is *require auth*: if `--constitution`
//! is provided without `--bearer-token-hex` AND without
//! `--insecure-no-auth`, startup fails with a helpful error.
//!
//! ## Out of scope (queued)
//!
//! - `POST /v1/checkpoints` — `$kernel/chain/checkpointed` receipts
//!   (step 19c).
//! - Standalone `POST /v1/secret-uses` / `POST /v1/redactions`
//!   endpoints. Today both kinds of audit fact ride on the
//!   `POST /v1/tool-executions` payload (as `secrets_used: []` and
//!   `redaction: {...}` fields). If a future BoardProof release adds
//!   detached secret-use or redaction events (i.e. events not tied
//!   to a tool call), the standalone endpoints would land here.
//! - Auth.

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use boardproof_approval::ApprovalDecision;
use boardproof_constitution::InMemoryConstitution;
use boardproof_kernel::{
    Approval, Kernel, KernelError, KernelEvent, KernelState, Proposal, ToolError,
    ToolExecution as KernelToolExecution, ToolMetadata, ToolOutput,
};
use boardproof_receipt::{
    Action, Decision, Digest, HexDecodeError, Receipt, RedactionReport, RuleMatch,
};
use boardproof_store::ReceiptLog;

use crate::clock::SystemClock;
use crate::signer::Ed25519Signer;

/// Concrete kernel type used by the HTTP API.
///
/// The kernel itself is generic; binding it to one tuple here keeps
/// the kernel side of `ApiState` simple. The log side IS generic
/// (since step 26) — see [`ApiState`].
pub type ApiKernel = Kernel<Ed25519Signer, SystemClock, InMemoryConstitution>;

/// State shared by the proposal + approval handlers, *and* the
/// read-only route handlers (step 9) when both are mounted on the
/// same server.
///
/// Generic over `L: ReceiptLog + Send + Sync + 'static` (since step
/// 26): the binary picks `ApiState<InMemoryReceiptLog>` for the
/// existing transient mode and `ApiState<SqliteReceiptLog>` for the
/// new persistent mode (`--constitution` + `--db <path>`). The
/// read-only `router<L>(log)` is already generic over the same
/// trait, so the patterns line up.
///
/// - `kernel` is wrapped in a `std::sync::Mutex` because the
///   critical section is short and synchronous — the handler calls
///   `Kernel::handle` and never `.await`s while holding the lock.
///   Std-mutex is the correct primitive for that shape.
/// - `log` reuses the same `tokio::sync::RwLock<L>` the read-only
///   `router(log)` consumes. The API takes a write lock around
///   `append`; the read-only routes take a read lock around
///   `get_by_id`. Sharing the lock makes minted receipts
///   immediately fetchable at `/receipts/<hash>`.
#[derive(Debug)]
pub struct ApiState<L: ReceiptLog + Send + Sync + 'static> {
    pub kernel: Mutex<ApiKernel>,
    pub log: Arc<RwLock<L>>,
}

impl<L: ReceiptLog + Send + Sync + 'static> ApiState<L> {
    /// Wire a kernel + shared log into an Arc-wrapped state.
    #[must_use]
    pub fn new(kernel: ApiKernel, log: Arc<RwLock<L>>) -> Arc<Self> {
        Arc::new(Self {
            kernel: Mutex::new(kernel),
            log,
        })
    }
}

/// Build an [`ApiKernel`] whose state continues from the log's
/// current head (step 26).
///
/// - **Empty log**: returns `Kernel::new(signer, SystemClock,
///   constitution)` — the genesis state (`sequence = 0`, zero
///   `prev_hash`). Behavior is identical to pre-step-26 hosts.
/// - **Non-empty log**: peeks `log.last()` and builds a
///   `KernelState` whose `sequence` is `last.sequence + 1` and
///   `prev_hash` is `last.leaf_hash`, then calls
///   `Kernel::resume(state, ...)`. The next minted receipt links
///   continuously to the persisted chain.
///
/// Without this helper, a fresh `Kernel::new` against a populated
/// log mints at `sequence = 0` again, which the log rejects with
/// `AppendError::OutOfOrder`. The binary + tests use this helper
/// after re-opening a `SqliteReceiptLog`.
#[must_use]
pub fn build_kernel_from_log<L>(
    log: &L,
    signer: Ed25519Signer,
    constitution: InMemoryConstitution,
) -> ApiKernel
where
    L: ReceiptLog,
{
    match log.last() {
        Some(last) => {
            let state = KernelState {
                sequence: last.body.merkle_leaf.sequence.saturating_add(1),
                prev_hash: last.body.merkle_leaf.leaf_hash,
            };
            Kernel::resume(state, signer, SystemClock, constitution)
        }
        None => Kernel::new(signer, SystemClock, constitution),
    }
}

/// Authentication configuration for the `/v1` proposal API.
///
/// The two constructors codify the operator's decision:
///
/// - [`AuthConfig::with_token`] — require `Authorization: Bearer
///   <hex>` matching the supplied 32-byte token on every `/v1`
///   call. Constant-time comparison.
/// - [`AuthConfig::insecure`] — accept every `/v1` call without
///   any header. Operators must explicitly opt in (the binary
///   requires `--insecure-no-auth`); a startup WARN line is
///   printed.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// `None` = insecure mode (no auth required). `Some(bytes)` =
    /// the token to compare against. Length is enforced to 32 bytes
    /// by [`AuthConfig::with_token`].
    bearer_token: Option<Vec<u8>>,
}

/// Why an [`AuthConfig::with_token`] call rejected the supplied
/// token bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthConfigError {
    /// Token wasn't 32 bytes long.
    WrongLength { got: usize },
}

impl core::fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { got } => write!(
                f,
                "bearer token must be exactly 32 bytes (64 hex chars), got {got}",
            ),
        }
    }
}

impl std::error::Error for AuthConfigError {}

impl AuthConfig {
    /// Construct an [`AuthConfig`] that requires `Authorization:
    /// Bearer <hex>` matching `token` on every `/v1` call. The
    /// token must be exactly 32 bytes (256 bits).
    ///
    /// # Errors
    ///
    /// Returns [`AuthConfigError::WrongLength`] if `token` is not
    /// exactly 32 bytes.
    pub fn with_token(token: Vec<u8>) -> Result<Self, AuthConfigError> {
        if token.len() != 32 {
            return Err(AuthConfigError::WrongLength { got: token.len() });
        }
        Ok(Self {
            bearer_token: Some(token),
        })
    }

    /// Construct an [`AuthConfig`] that accepts every `/v1` call
    /// without any header. The binary's CLI requires
    /// `--insecure-no-auth` to land here.
    #[must_use]
    pub fn insecure() -> Self {
        Self { bearer_token: None }
    }

    /// Whether this config requires auth on `/v1` calls.
    #[must_use]
    pub fn requires_auth(&self) -> bool {
        self.bearer_token.is_some()
    }
}

/// Build the `/v1` axum router. The caller composes this with the
/// read-only router via `Router::merge` to expose both surfaces on
/// the same listener.
///
/// `auth` controls whether the `/v1` routes require a bearer token.
/// Read-only routes (mounted by [`crate::router`]) are always
/// public and are not affected by this config.
pub fn api_router<L>(state: Arc<ApiState<L>>, auth: AuthConfig) -> Router
where
    L: ReceiptLog + Send + Sync + 'static,
{
    let auth = Arc::new(auth);
    let mut routes = Router::new()
        .route("/v1/proposals", post(post_proposal::<L>))
        .route(
            "/v1/approvals/:content_id/resolve",
            post(post_resolve_approval::<L>),
        )
        .route("/v1/tool-executions", post(post_tool_execution::<L>))
        .with_state(state);
    if auth.requires_auth() {
        // Only install the middleware when auth is actually required.
        // Insecure mode skips the layer entirely — keeps the routing
        // fast path identical to pre-step-25 for operators who opted
        // out.
        let auth_for_layer = auth.clone();
        routes = routes.layer(middleware::from_fn(move |req: Request, next: Next| {
            let auth = auth_for_layer.clone();
            async move { auth_middleware(auth, req, next).await }
        }));
    }
    routes
}

/// Constant-time byte-slice equality. Returns `false` immediately
/// on length mismatch — the length itself isn't a secret (32 bytes,
/// well-known). For equal-length inputs, OR'd XORs avoid leaking
/// the position of the first differing byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Bearer-token middleware. Runs on every `/v1` request when
/// [`AuthConfig::requires_auth`] is true.
async fn auth_middleware(auth: Arc<AuthConfig>, req: Request, next: Next) -> Response {
    let Some(expected) = auth.bearer_token.as_ref() else {
        // Insecure mode — shouldn't be installed, but if it is we
        // fail open. Defensive: the layer is only added in
        // api_router when requires_auth is true.
        return next.run(req).await;
    };

    let Some(header_value) = req.headers().get(header::AUTHORIZATION) else {
        return unauthorized("missing Authorization header");
    };
    let Ok(value) = header_value.to_str() else {
        return unauthorized("Authorization header must be ASCII");
    };
    // Accept both "Bearer foo" and "bearer foo" — RFC 6750 says the
    // scheme is case-insensitive. The token itself is hex so case
    // matters only for hex parsing.
    let Some(token_str) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return unauthorized("Authorization must be 'Bearer <hex-token>'");
    };
    let token_str = token_str.trim();
    let Ok(provided_digest) = boardproof_receipt::Digest::from_hex(token_str) else {
        return unauthorized("bearer token must be 64 hex characters");
    };
    if !ct_eq(&provided_digest.0, expected) {
        return unauthorized("bearer token rejected");
    }
    next.run(req).await
}

fn unauthorized(detail: &str) -> Response {
    // Same `{error, detail}` shape the other ApiError variants use.
    let body = serde_json::json!({
        "error": "unauthorized",
        "detail": detail,
    });
    let body_bytes = serde_json::to_vec(&body).expect("static JSON serializes");
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_bytes))
        .expect("unauthorized response builds")
}

// ---------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------

/// `POST /v1/proposals` request body.
///
/// Just the action — the kernel applies the constitution + budget
/// pipeline. Pre-existing constitution rules / provenance edges
/// from upstream callers are not yet accepted; that's a future
/// expansion.
#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    pub action: ActionWire,
}

/// Action wire shape. Mirrors `boardproof_receipt::Action` but uses
/// a hex-string `input_hash` so plain JSON clients (TS, Python, Go,
/// curl) can populate it without thinking about byte arrays.
#[derive(Debug, Deserialize)]
pub struct ActionWire {
    pub kind: String,
    pub target: String,
    pub input_hash: String,
}

/// Response body for both `/v1/proposals` and `/v1/approvals/.../resolve`.
///
/// The receipt itself is content-addressed and immediately fetchable
/// at `receipt_url`, but for callers that don't want to round-trip
/// the URL we also embed the recomputable fields (`decision`,
/// `content_id`, `issuer`, `sequence`, `schema_version`).
#[derive(Debug, Serialize)]
pub struct ReceiptResponse {
    pub decision: String,
    pub content_id: String,
    pub receipt_url: String,
    pub issuer: String,
    pub sequence: u64,
    pub schema_version: u32,
    /// Step 19a: operator-chosen identifier for the signing key,
    /// when present in the minted receipt's `body.key_id`.
    /// Omitted from the wire response when the signer didn't set
    /// one (backward-compatible: pre-19a clients receive the same
    /// shape they did before).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// `POST /v1/approvals/{content_id}/resolve` request body.
///
/// `principal` is the named operator/identity authorizing the
/// decision. It is accepted in the wire format now so adapters
/// don't have to change shape later, but is **not** recorded in the
/// receipt today — the current `ResolveApproval` flow uses the
/// kernel's signer as the implicit principal. Identity-bound
/// approvals are a future step (Phase 6 governance).
#[derive(Debug, Deserialize)]
pub struct ResolveApprovalRequest {
    pub principal: String,
    pub outcome: ResolveOutcome,
}

/// Caller's decision on a pending receipt.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveOutcome {
    Approved,
    Denied,
}

impl From<ResolveOutcome> for ApprovalDecision {
    fn from(o: ResolveOutcome) -> Self {
        match o {
            ResolveOutcome::Approved => Self::Approved,
            ResolveOutcome::Denied => Self::Denied,
        }
    }
}

/// `POST /v1/tool-executions` request body.
///
/// Anchors a completed external tool call into the chain. Exactly
/// one of `output_hash` / `error` must be set:
///
/// - `output_hash` (success): BLAKE3 of the tool's raw output
///   bytes. The actual bytes never cross the kernel boundary —
///   the kernel only records the hash + optional audit metadata.
/// - `error` (failure): free-form message describing why the call
///   failed. Surfaced as a `tool_execution_failure` provenance
///   edge on the resulting receipt.
///
/// `secrets_used` lists the **reference names** of secrets the
/// tool consumed (e.g. `"github.token"`). The kernel mints one
/// `secret_used` provenance edge per name. Secret VALUES never
/// cross any wire — neither to the kernel nor to the receipt.
///
/// `redaction`, when present, commits the receipt to a
/// post-redaction `output_hash` and populates
/// `body.redactor_stack_hash`. The kernel mints one
/// `redaction_applied` provenance edge per rule with `count > 0`.
/// The pre-redaction bytes never enter the kernel either.
#[derive(Debug, Deserialize)]
pub struct ToolExecutionRequest {
    pub allowed_receipt_id: String,
    /// Set on success. 64 hex chars (BLAKE3 of tool's output bytes).
    pub output_hash: Option<String>,
    /// Set on failure. Human-readable error message.
    pub error: Option<String>,
    /// Reference names of secrets the tool consumed. Optional;
    /// defaults to empty when omitted.
    #[serde(default)]
    pub secrets_used: Vec<String>,
    /// Optional redaction audit data. When present the kernel
    /// uses `redaction.redacted_output_hash` as the receipt's
    /// `output_hash` and populates `body.redactor_stack_hash`.
    pub redaction: Option<RedactionWire>,
}

/// Wire shape for [`RedactionReport`]. Mirrors the Rust struct but
/// uses hex-string digests so JSON clients can populate them
/// without byte-array fiddling.
#[derive(Debug, Deserialize)]
pub struct RedactionWire {
    pub redacted_output_hash: String,
    #[serde(default)]
    pub matches: Vec<RuleMatchWire>,
    pub stack_hash: String,
}

/// One redactor rule's match count.
#[derive(Debug, Deserialize)]
pub struct RuleMatchWire {
    pub rule_id: String,
    pub count: u32,
}

// ---------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------

/// API error type. Implements `IntoResponse` to control status codes
/// and the JSON body shape returned to callers.
#[derive(Debug)]
pub enum ApiError {
    /// Bad request shape (invalid JSON, malformed hex, etc.).
    BadRequest(String),
    /// Referenced `content_id` is not in the log.
    NotFound(String),
    /// Approval target exists but is not in `Pending` state, or the
    /// kernel rejected the resolve event for some other authenticity
    /// reason.
    Conflict(String),
    /// Internal failure — should not happen under valid input.
    Internal(String),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, detail) = match self {
            Self::BadRequest(d) => (StatusCode::BAD_REQUEST, "bad_request", d),
            Self::NotFound(d) => (StatusCode::NOT_FOUND, "not_found", d),
            Self::Conflict(d) => (StatusCode::CONFLICT, "conflict", d),
            Self::Internal(d) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", d),
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                detail,
            }),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

/// `POST /v1/proposals`
///
/// Submit an action; receive a signed receipt. The kernel runs the
/// constitution + budget pipeline (budget enforcement is currently
/// not configurable through the API; all proposals are "unbounded"
/// — the kernel never charges a lease). The minted receipt is
/// immediately appended to the log and fetchable at `receipt_url`.
pub async fn post_proposal<L: ReceiptLog + Send + Sync + 'static>(
    State(state): State<Arc<ApiState<L>>>,
    Json(req): Json<ProposeRequest>,
) -> Result<Json<ReceiptResponse>, ApiError> {
    let action = parse_action(req.action)?;
    let proposal = Proposal::unbounded(action, Decision::Allowed, Vec::new(), Vec::new());
    let event = KernelEvent::evaluate(proposal);

    let receipt = handle_event(&state, event).await?;
    Ok(Json(receipt_response(&receipt)))
}

/// `POST /v1/approvals/{content_id}/resolve`
///
/// Resolve a pending receipt. The kernel re-verifies the pending
/// receipt's signature and decision before honoring the resolve;
/// see `Kernel::handle_resolve_approval` for the gate.
pub async fn post_resolve_approval<L: ReceiptLog + Send + Sync + 'static>(
    State(state): State<Arc<ApiState<L>>>,
    Path(content_id): Path<String>,
    Json(req): Json<ResolveApprovalRequest>,
) -> Result<Json<ReceiptResponse>, ApiError> {
    let digest = parse_digest(&content_id, "content_id")?;

    // Look up the pending receipt in the log. A 404 here means the
    // caller asked us to resolve something this kernel never minted.
    let pending = {
        let log = state.log.read().await;
        log.get_by_id(&digest)
            .ok_or_else(|| ApiError::NotFound(format!("no receipt with content_id {content_id}")))?
    };

    // Reject up-front if it isn't actually a Pending receipt — the
    // kernel would also reject, but we can return a clearer error.
    if pending.body.decision != Decision::Pending {
        return Err(ApiError::Conflict(format!(
            "receipt {content_id} is in state {:?}, not Pending",
            pending.body.decision
        )));
    }

    // Reconstruct the original proposal from the pending receipt's
    // body. The action survives intact; constitution_rules and
    // provenance are carried forward. The kernel re-runs the
    // resolve-time authenticity checks regardless.
    let original_proposal = Proposal::unbounded(
        pending.body.action.clone(),
        Decision::Pending,
        pending.body.constitution_rules.clone(),
        pending.body.provenance.clone(),
    );
    // `principal` is captured in the request but not yet propagated
    // into the receipt — identity-bound approvals are a future step.
    let _ = req.principal;

    let approval = Approval {
        pending_receipt: pending,
        original_proposal,
        response: req.outcome.into(),
    };
    let event = KernelEvent::resolve(approval);

    let receipt = handle_event(&state, event).await?;
    Ok(Json(receipt_response(&receipt)))
}

/// `POST /v1/tool-executions`
///
/// Record a completed external tool call against a previously-
/// minted Allowed receipt. The kernel re-verifies the prior
/// receipt's authenticity (signature, issuer, decision-is-Allowed,
/// action-kind-starts-with-`"tool."`) before honoring the record;
/// see `Kernel::handle_record_tool_execution` for the gate.
pub async fn post_tool_execution<L: ReceiptLog + Send + Sync + 'static>(
    State(state): State<Arc<ApiState<L>>>,
    Json(req): Json<ToolExecutionRequest>,
) -> Result<Json<ReceiptResponse>, ApiError> {
    // --- Input validation -------------------------------------------------

    let allowed_id = parse_digest(&req.allowed_receipt_id, "allowed_receipt_id")?;
    if req.output_hash.is_some() && req.error.is_some() {
        return Err(ApiError::BadRequest(
            "exactly one of output_hash or error must be set, not both".into(),
        ));
    }
    if req.output_hash.is_none() && req.error.is_none() {
        return Err(ApiError::BadRequest(
            "exactly one of output_hash or error must be set".into(),
        ));
    }

    // --- Look up the prior Allowed receipt -------------------------------

    let allowed_receipt = {
        let log = state.log.read().await;
        log.get_by_id(&allowed_id).ok_or_else(|| {
            ApiError::NotFound(format!(
                "no receipt with content_id {}",
                req.allowed_receipt_id
            ))
        })?
    };

    // Cheap up-front rejection: the kernel would also reject these,
    // but we can return a clearer error before submitting the event.
    if allowed_receipt.body.decision != Decision::Allowed {
        return Err(ApiError::Conflict(format!(
            "receipt {} is in state {:?}, not Allowed",
            req.allowed_receipt_id, allowed_receipt.body.decision
        )));
    }
    if !allowed_receipt.body.action.kind.starts_with("tool.") {
        return Err(ApiError::Conflict(format!(
            "receipt {} action.kind {:?} does not start with \"tool.\"",
            req.allowed_receipt_id, allowed_receipt.body.action.kind,
        )));
    }

    // --- Build the kernel event ------------------------------------------

    let original_proposal = Proposal::unbounded(
        allowed_receipt.body.action.clone(),
        Decision::Allowed,
        allowed_receipt.body.constitution_rules.clone(),
        allowed_receipt.body.provenance.clone(),
    );

    let result: Result<ToolOutput, ToolError> = if let Some(hash_hex) = req.output_hash.as_ref() {
        let output_hash = parse_digest(hash_hex, "output_hash")?;
        Ok(ToolOutput {
            // The kernel only reads `output_hash` and `metadata`;
            // bytes are not used (and the agent runtime owns them
            // anyway). Empty `bytes` keeps the HTTP wire compact.
            bytes: Vec::new(),
            output_hash,
            metadata: ToolMetadata {
                secrets_used: req.secrets_used.clone(),
            },
        })
    } else {
        // `error` is set (we validated up-front that exactly one of
        // output_hash/error is present). v1 maps every error to
        // `ToolError::Failed(message)`; richer variants (Timeout,
        // CapabilityDenied, NotFound, InvalidInput) can be added
        // to the wire later by introducing an optional `error_kind`
        // field.
        let msg = req.error.clone().unwrap_or_default();
        Err(ToolError::Failed(msg))
    };

    let redaction = if let Some(r) = req.redaction.as_ref() {
        let redacted_output_hash =
            parse_digest(&r.redacted_output_hash, "redaction.redacted_output_hash")?;
        let stack_hash = parse_digest(&r.stack_hash, "redaction.stack_hash")?;
        let matches = r
            .matches
            .iter()
            .map(|m| RuleMatch {
                rule_id: m.rule_id.clone(),
                count: m.count,
            })
            .collect();
        Some(RedactionReport {
            redacted_output_hash,
            matches,
            stack_hash,
        })
    } else {
        None
    };

    let execution = KernelToolExecution {
        allowed_receipt,
        original_proposal,
        result,
        redaction,
    };
    let event = KernelEvent::record_tool_execution(execution);

    let receipt = handle_event(&state, event).await?;
    Ok(Json(receipt_response(&receipt)))
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

/// Drive a `KernelEvent` through the kernel + append the resulting
/// receipt to the log. Returns the receipt itself so the handler can
/// build the response.
///
/// Lock order: `kernel` (sync) → `log` (async). The kernel lock is
/// released before we await the log write lock; nothing else holds
/// the log lock for long enough to matter.
async fn handle_event<L: ReceiptLog + Send + Sync + 'static>(
    state: &ApiState<L>,
    event: KernelEvent,
) -> Result<Receipt, ApiError> {
    // Step 1: drive the kernel under its sync mutex. Critical
    // section is bounded by `Kernel::handle`, which doesn't await
    // or block on external I/O.
    let outcome = {
        let mut kernel = state
            .kernel
            .lock()
            .map_err(|e| ApiError::Internal(format!("kernel lock poisoned: {e}")))?;
        kernel.handle(event).map_err(map_kernel_error)?
    };

    // Step 2: append the minted receipt under the async write lock
    // shared with the read-only `/receipts/<hash>` handler.
    let mut log = state.log.write().await;
    log.append(outcome.receipt.clone())
        .map_err(|e| ApiError::Internal(format!("log append: {e:?}")))?;
    Ok(outcome.receipt)
}

fn map_kernel_error(e: KernelError) -> ApiError {
    // Authenticity-rejection cases produce a 409 because they describe
    // a state mismatch between caller and kernel (e.g. the caller
    // tried to resolve a non-Pending receipt). Other internal kernel
    // errors get 500.
    match e {
        KernelError::ResolveApprovalRejected(r) => {
            ApiError::Conflict(format!("approval rejected: {r:?}"))
        }
        KernelError::RecordToolExecutionRejected(r) => {
            ApiError::Conflict(format!("tool execution rejected: {r:?}"))
        }
    }
}

fn parse_action(wire: ActionWire) -> Result<Action, ApiError> {
    let input_hash = parse_digest(&wire.input_hash, "action.input_hash")?;
    Ok(Action {
        kind: wire.kind,
        target: wire.target,
        input_hash,
    })
}

fn parse_digest(s: &str, field: &str) -> Result<Digest, ApiError> {
    Digest::from_hex(s).map_err(|e| {
        let detail = match e {
            HexDecodeError::InvalidLength { expected, got } => {
                format!("{field}: expected {expected} hex chars, got {got}")
            }
            HexDecodeError::InvalidCharacter => format!("{field}: non-hex character"),
        };
        ApiError::BadRequest(detail)
    })
}

fn receipt_response(r: &Receipt) -> ReceiptResponse {
    let id = r.content_id();
    let id_hex = id.to_hex();
    ReceiptResponse {
        decision: decision_str(r.body.decision).to_string(),
        receipt_url: format!("/receipts/{id_hex}"),
        content_id: id_hex,
        issuer: hex32(&r.issuer.0),
        sequence: r.body.merkle_leaf.sequence,
        schema_version: r.body.schema_version,
        key_id: r.body.key_id.clone(),
    }
}

fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allowed => "allowed",
        Decision::Denied => "denied",
        Decision::Approved => "approved",
        Decision::Pending => "pending",
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}
