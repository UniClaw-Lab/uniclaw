//! `boardproof-host` — small server that serves BoardProof receipts.
//!
//! ## Read-only mode (default, since step 9)
//!
//! Two backends:
//!
//! - **`--db <path>`** (recommended): persistent `SqliteReceiptLog`. Survives
//!   restarts. Required for any real deployment. On first run, the issuer
//!   is read from the `UNICLAW_HOST_ISSUER` env var (64-char hex) and
//!   pinned into the database.
//! - **`--receipts-dir <dir>`** (default, in-memory): loads every `*.json`
//!   file at startup, sorts by sequence, replays into an
//!   `InMemoryReceiptLog`. Good for demos and tests; loses everything on
//!   restart.
//!
//! ## Proposal-API mode (step 21)
//!
//! When `--constitution <path>` is passed, the server additionally
//! mounts the `/v1/proposals` + `/v1/approvals/{id}/resolve` endpoints
//! backed by an in-memory kernel + log. Proposals submitted over HTTP
//! are evaluated and minted on the spot; the resulting receipts are
//! immediately fetchable via the standard `/receipts/<hash>` route.
//! The signing key is loaded from `--signer-seed-hex` (32-byte hex
//! seed; dev-only) — production deployments must add an HSM-backed
//! signer in a future step. There is **no authentication** in front
//! of `/v1` today; expose only on loopback / a trusted segment.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Router;
use clap::{ArgGroup, Parser};
use tokio::sync::RwLock;

use boardproof_constitution::parse_toml;
use boardproof_host::api::{ApiState, AuthConfig, api_router, build_kernel_from_log};
use boardproof_host::router;
use boardproof_host::signer::Ed25519Signer;
use boardproof_kernel::Signer;
use boardproof_receipt::{PublicKey, Receipt};
use boardproof_store::{InMemoryReceiptLog, ReceiptLog};
use boardproof_store_sqlite::SqliteReceiptLog;

#[derive(Parser, Debug)]
#[command(
    name = "boardproof-host",
    about = "Serve BoardProof receipts at boardproof://receipt/<hash> over HTTP."
)]
#[command(group(
    ArgGroup::new("backend")
        .args(["db", "receipts_dir"])
        .multiple(false)
        .required(false)
))]
struct Args {
    /// Persistent SQLite-backed receipt log. Survives restarts.
    ///
    /// In **read-only mode** (no `--constitution`): on first run
    /// set `UNICLAW_HOST_ISSUER=<64-hex>` to pin the log.
    ///
    /// In **proposal mode** (`--constitution`, step 26 onward):
    /// the issuer is pinned to the kernel's signing key. Fresh
    /// DB = pin to the kernel pubkey. Existing DB = the kernel
    /// pubkey MUST match the DB's pinned issuer; the binary
    /// refuses to start otherwise (chain integrity).
    #[arg(long)]
    db: Option<PathBuf>,

    /// Directory of `*.json` receipts (in-memory backend, default mode).
    #[arg(long, default_value = "./receipts")]
    receipts_dir: PathBuf,

    /// Address to bind the HTTP listener on.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,

    /// Enable proposal-API mode by loading a constitution from a
    /// TOML file. When present, the `/v1/proposals` /
    /// `/v1/approvals/{id}/resolve` / `/v1/tool-executions`
    /// endpoints are mounted; the kernel that backs them uses this
    /// constitution to decide each proposal.
    ///
    /// **Authentication.** In proposal mode, supply either
    /// `--bearer-token-hex <64-hex>` to require an
    /// `Authorization: Bearer <hex>` header on every `/v1` call,
    /// OR `--insecure-no-auth` to explicitly opt out. The binary
    /// refuses to start in proposal mode without one of the two
    /// flags so insecure exposure can't happen by accident.
    #[arg(long)]
    constitution: Option<PathBuf>,

    /// 32-byte seed hex (64 chars) for the dev signing key.
    /// Required when `--constitution` is provided. Production must
    /// replace this with an HSM-backed signer (future step).
    #[arg(long)]
    signer_seed_hex: Option<String>,

    /// Optional opaque identifier for the signing key (step 19a /
    /// RFC-0001 rev 2.1). When set, the kernel embeds this value
    /// in every minted receipt's `body.key_id` so auditors can
    /// correlate receipts with an external key directory entry
    /// — useful for rotation, revocation, and expiry tracking.
    /// Receipts minted without `--key-id` omit the field entirely
    /// and remain byte-identical to pre-19a output.
    #[arg(long)]
    key_id: Option<String>,

    /// 32-byte bearer token (64 hex chars) required on every `/v1`
    /// request as `Authorization: Bearer <hex>`. Constant-time
    /// comparison. Read-only routes stay public.
    ///
    /// Generate one with `head -c 32 /dev/urandom | xxd -p -c 64`.
    #[arg(long)]
    bearer_token_hex: Option<String>,

    /// Disable bearer-token auth on `/v1`. Mutually exclusive with
    /// `--bearer-token-hex`. The binary prints a loud WARN on
    /// startup; only use on loopback / a fully-trusted network
    /// segment. Required for proposal mode when
    /// `--bearer-token-hex` isn't supplied.
    #[arg(long, default_value_t = false)]
    insecure_no_auth: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(c_path) = args.constitution.as_deref() {
        run_proposal_mode(c_path, &args).await
    } else if let Some(db_path) = args.db.as_deref() {
        let issuer = read_or_require_issuer(db_path)?;
        let log = SqliteReceiptLog::open(db_path, issuer)
            .with_context(|| format!("opening SQLite log at {}", db_path.display()))?;
        serve_readonly("sqlite", db_path.display().to_string(), args.bind, log).await
    } else {
        let log = load_receipts_dir(&args.receipts_dir)
            .with_context(|| format!("loading receipts from {}", args.receipts_dir.display()))?;
        serve_readonly(
            "in-memory",
            args.receipts_dir.display().to_string(),
            args.bind,
            log,
        )
        .await
    }
}

async fn run_proposal_mode(c_path: &Path, args: &Args) -> Result<()> {
    // --- Build the signer ---
    let seed_hex = args
        .signer_seed_hex
        .as_deref()
        .context("--constitution requires --signer-seed-hex (dev key, 64 hex chars)")?;
    let seed_digest = boardproof_receipt::Digest::from_hex(seed_hex)
        .context("--signer-seed-hex must be 64 hex characters")?;
    let mut signer = Ed25519Signer::from_seed(&seed_digest.0);
    if let Some(key_id) = args.key_id.as_deref() {
        signer = signer.with_key_id(key_id);
    }
    let issuer = signer.public_key();

    // --- Resolve auth (safe-default: require one or the other) ---
    let auth = build_auth_config(args)?;

    // --- Load the constitution ---
    let toml_src = std::fs::read_to_string(c_path)
        .with_context(|| format!("reading constitution {}", c_path.display()))?;
    let constitution = parse_toml(&toml_src)
        .with_context(|| format!("parsing constitution {}", c_path.display()))?;

    // --- Pick the log backend (step 26: persistent if --db) ---
    if let Some(db_path) = args.db.as_deref() {
        // Persistent (SQLite-backed) proposal mode. Reconcile the
        // kernel's pubkey with the DB's pinned issuer:
        // - Fresh DB: pin to the kernel pubkey now.
        // - Existing DB: kernel pubkey MUST match the pinned issuer
        //   (chain integrity). The kernel won't be able to append
        //   under another issuer anyway, but we fail fast at
        //   startup with a clear error rather than producing a
        //   confusing AppendError later.
        if let Some(existing) = SqliteReceiptLog::peek_issuer(db_path)
            .context("inspecting existing SQLite log for pinned issuer")?
            && existing != issuer
        {
            let existing_prefix = issuer_prefix(&existing);
            let kernel_prefix = issuer_prefix(&issuer);
            bail!(
                "kernel signing key (issuer {kernel_prefix}…) does not match the \
                 pinned issuer of the SQLite log at {} (issuer {existing_prefix}…). \
                 Refusing to fork the chain. Use the original signing seed, or \
                 start a new DB at a different path.",
                db_path.display(),
            );
        }
        let log = SqliteReceiptLog::open(db_path, issuer)
            .with_context(|| format!("opening SQLite log at {}", db_path.display()))?;
        let source = db_path.display().to_string();
        serve_proposal_mode(
            "sqlite",
            &source,
            c_path,
            signer,
            constitution,
            log,
            issuer,
            auth,
            args.bind,
        )
        .await
    } else {
        // Default: in-memory log (existing pre-step-26 behavior;
        // restart loses the chain).
        let log = InMemoryReceiptLog::new(issuer);
        serve_proposal_mode(
            "in-memory",
            "transient",
            c_path,
            signer,
            constitution,
            log,
            issuer,
            auth,
            args.bind,
        )
        .await
    }
}

/// Serve proposal-mode requests against a concrete log backend.
/// Generic over `L` so the same wiring works for `InMemoryReceiptLog`
/// (transient) and `SqliteReceiptLog` (persistent, step 26).
#[allow(clippy::too_many_arguments)]
async fn serve_proposal_mode<L>(
    backend: &str,
    source: &str,
    c_path: &Path,
    signer: Ed25519Signer,
    constitution: boardproof_constitution::InMemoryConstitution,
    log: L,
    issuer: PublicKey,
    auth: boardproof_host::api::AuthConfig,
    bind: SocketAddr,
) -> Result<()>
where
    L: ReceiptLog + Send + Sync + 'static,
{
    // Step 26: resume kernel state from the log's head when the log
    // is non-empty (SQLite-backed persistence path). Empty log →
    // genesis state (existing in-memory behavior, byte-identical).
    let kernel = build_kernel_from_log(&log, signer, constitution);
    let log = Arc::new(RwLock::new(log));
    let state = ApiState::new(kernel, log.clone());

    let api = api_router(state, auth.clone());
    let readonly = router(log.clone());
    let app: Router = readonly.merge(api);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;
    let issuer_prefix = issuer_prefix(&issuer);

    eprintln!(
        "boardproof-host: backend={backend} source={source} constitution={} \
         (issuer {issuer_prefix}…) listening on http://{local}",
        c_path.display(),
    );
    if auth.requires_auth() {
        eprintln!("boardproof-host: /v1 proposal API requires Authorization: Bearer <token>");
    } else {
        eprintln!(
            "boardproof-host: WARN /v1 proposal API is UNAUTHENTICATED (--insecure-no-auth) — \
             keep this bound to loopback or a fully-trusted network segment.",
        );
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("boardproof-host: shutting down");
        })
        .await?;

    Ok(())
}

async fn serve_readonly<L>(backend: &str, source: String, bind: SocketAddr, log: L) -> Result<()>
where
    L: ReceiptLog + Send + Sync + 'static,
{
    let count = log.len();
    let issuer = log.issuer();
    let app = router(Arc::new(RwLock::new(log)));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;
    let issuer_prefix = issuer_prefix(&issuer);

    eprintln!(
        "boardproof-host: backend={backend} source={source} \
         serving {count} receipt(s) (issuer {issuer_prefix}…) on http://{local}"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("boardproof-host: shutting down");
        })
        .await?;

    Ok(())
}

fn issuer_prefix(issuer: &PublicKey) -> String {
    let mut s = String::with_capacity(8);
    for b in &issuer.0[0..4] {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Resolve the issuer for a SQLite-backed log:
///
/// - If the DB already pins an issuer, use it (and ignore the env var,
///   which would otherwise let an operator silently re-pin and lose
///   chain continuity).
/// - Otherwise (fresh DB), require `UNICLAW_HOST_ISSUER` to be set.
fn read_or_require_issuer(db_path: &Path) -> Result<PublicKey> {
    if let Some(existing) = SqliteReceiptLog::peek_issuer(db_path)
        .context("inspecting existing SQLite log for pinned issuer")?
    {
        return Ok(existing);
    }
    let s = std::env::var("UNICLAW_HOST_ISSUER")
        .context("fresh SQLite log; set UNICLAW_HOST_ISSUER=<64-hex> to pin it")?;
    let bytes = boardproof_receipt::Digest::from_hex(&s)
        .context("UNICLAW_HOST_ISSUER must be 64 hex characters")?;
    Ok(PublicKey(bytes.0))
}

fn load_receipts_dir(dir: &PathBuf) -> Result<InMemoryReceiptLog> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }

    let mut entries: Vec<(u64, Receipt)> = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let receipt: Receipt = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse receipt {}", path.display()))?;
        entries.push((receipt.body.merkle_leaf.sequence, receipt));
    }
    entries.sort_by_key(|(seq, _)| *seq);

    if entries.is_empty() {
        let issuer = pin_issuer_from_env()
            .context("empty receipts dir; set UNICLAW_HOST_ISSUER=<64-hex> to pin the log")?;
        return Ok(InMemoryReceiptLog::new(issuer));
    }

    let pinned = entries[0].1.issuer;
    let mut log = InMemoryReceiptLog::new(pinned);
    for (_, r) in entries {
        log.append(r)
            .context("append failed during load — chain broken or out of order")?;
    }
    Ok(log)
}

fn pin_issuer_from_env() -> Result<PublicKey> {
    let s = std::env::var("UNICLAW_HOST_ISSUER")?;
    let bytes = boardproof_receipt::Digest::from_hex(&s)
        .context("UNICLAW_HOST_ISSUER must be 64 hex characters")?;
    Ok(PublicKey(bytes.0))
}

/// Resolve proposal-mode auth from CLI flags. Safe default: one of
/// `--bearer-token-hex` / `--insecure-no-auth` must be present, and
/// they're mutually exclusive.
fn build_auth_config(args: &Args) -> Result<AuthConfig> {
    if args.bearer_token_hex.is_some() && args.insecure_no_auth {
        bail!("--bearer-token-hex and --insecure-no-auth are mutually exclusive — pick one");
    }
    if let Some(token_hex) = args.bearer_token_hex.as_deref() {
        let digest = boardproof_receipt::Digest::from_hex(token_hex)
            .context("--bearer-token-hex must be exactly 64 hex characters (32 bytes)")?;
        let token =
            AuthConfig::with_token(digest.0.to_vec()).context("invalid bearer token length")?;
        return Ok(token);
    }
    if args.insecure_no_auth {
        return Ok(AuthConfig::insecure());
    }
    bail!(
        "proposal mode (--constitution) requires either \
         --bearer-token-hex <64-hex> (recommended) or \
         --insecure-no-auth (loopback / fully-trusted network only). \
         Refusing to expose /v1 unauthenticated by default.",
    );
}
