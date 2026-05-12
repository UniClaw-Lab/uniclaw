//! `uniclaw-host` — small server that serves Uniclaw receipts.
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

use uniclaw_constitution::parse_toml;
use uniclaw_host::api::{ApiState, AuthConfig, api_router};
use uniclaw_host::clock::SystemClock;
use uniclaw_host::router;
use uniclaw_host::signer::Ed25519Signer;
use uniclaw_kernel::Signer;
use uniclaw_receipt::{PublicKey, Receipt};
use uniclaw_store::{InMemoryReceiptLog, ReceiptLog};
use uniclaw_store_sqlite::SqliteReceiptLog;

#[derive(Parser, Debug)]
#[command(
    name = "uniclaw-host",
    about = "Serve Uniclaw receipts at uniclaw://receipt/<hash> over HTTP."
)]
#[command(group(
    ArgGroup::new("backend")
        .args(["db", "receipts_dir"])
        .multiple(false)
        .required(false)
))]
struct Args {
    /// Persistent SQLite-backed receipt log. Survives restarts.
    /// On first run set `UNICLAW_HOST_ISSUER=<64-hex>` to pin the log.
    ///
    /// **Cannot be combined with `--constitution`** — the proposal
    /// API uses an in-memory log so the kernel can append directly.
    /// Persistence for proposal mode is a future-step.
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
        if args.db.is_some() {
            bail!(
                "--constitution is incompatible with --db: \
                 proposal mode uses an in-memory log; persistent storage \
                 for minted receipts is a future-step",
            );
        }
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
    let seed_digest = uniclaw_receipt::Digest::from_hex(seed_hex)
        .context("--signer-seed-hex must be 64 hex characters")?;
    let signer = Ed25519Signer::from_seed(&seed_digest.0);
    let issuer = signer.public_key();

    // --- Resolve auth (safe-default: require one or the other) ---
    let auth = build_auth_config(args)?;

    // --- Load the constitution ---
    let toml_src = std::fs::read_to_string(c_path)
        .with_context(|| format!("reading constitution {}", c_path.display()))?;
    let constitution = parse_toml(&toml_src)
        .with_context(|| format!("parsing constitution {}", c_path.display()))?;

    // --- Wire kernel + shared log ---
    let kernel = uniclaw_kernel::Kernel::new(signer, SystemClock, constitution);
    let log = Arc::new(RwLock::new(InMemoryReceiptLog::new(issuer)));
    let state = ApiState::new(kernel, log.clone());

    // --- Build merged router ---
    let api = api_router(state, auth.clone());
    let readonly = router(log.clone());
    let app: Router = readonly.merge(api);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    let local = listener.local_addr()?;
    let issuer_prefix = issuer_prefix(&issuer);

    eprintln!(
        "uniclaw-host: backend=in-memory constitution={} \
         (issuer {issuer_prefix}…) listening on http://{local}",
        c_path.display(),
    );
    if auth.requires_auth() {
        eprintln!("uniclaw-host: /v1 proposal API requires Authorization: Bearer <token>");
    } else {
        eprintln!(
            "uniclaw-host: WARN /v1 proposal API is UNAUTHENTICATED (--insecure-no-auth) — \
             keep this bound to loopback or a fully-trusted network segment.",
        );
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("uniclaw-host: shutting down");
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
        "uniclaw-host: backend={backend} source={source} \
         serving {count} receipt(s) (issuer {issuer_prefix}…) on http://{local}"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("uniclaw-host: shutting down");
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
    let bytes = uniclaw_receipt::Digest::from_hex(&s)
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
    let bytes = uniclaw_receipt::Digest::from_hex(&s)
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
        let digest = uniclaw_receipt::Digest::from_hex(token_hex)
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
