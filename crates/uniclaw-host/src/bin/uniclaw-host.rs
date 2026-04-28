//! `uniclaw-host` — small server that serves Uniclaw receipts.
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
//! Both modes serve the same axum router from `uniclaw-host` (lib).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Parser};
use tokio::sync::RwLock;

use uniclaw_host::router;
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
    #[arg(long)]
    db: Option<PathBuf>,

    /// Directory of `*.json` receipts (in-memory backend, default mode).
    #[arg(long, default_value = "./receipts")]
    receipts_dir: PathBuf,

    /// Address to bind the HTTP listener on.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(db_path) = args.db.as_deref() {
        let issuer = read_or_require_issuer(db_path)?;
        let log = SqliteReceiptLog::open(db_path, issuer)
            .with_context(|| format!("opening SQLite log at {}", db_path.display()))?;
        serve("sqlite", db_path.display().to_string(), args.bind, log).await
    } else {
        let log = load_receipts_dir(&args.receipts_dir)
            .with_context(|| format!("loading receipts from {}", args.receipts_dir.display()))?;
        serve(
            "in-memory",
            args.receipts_dir.display().to_string(),
            args.bind,
            log,
        )
        .await
    }
}

async fn serve<L>(backend: &str, source: String, bind: SocketAddr, log: L) -> Result<()>
where
    L: ReceiptLog + Send + Sync + 'static,
{
    let count = log.len();
    let issuer = log.issuer();
    let app = router(Arc::new(RwLock::new(log)));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;

    let issuer_prefix = {
        let mut s = String::with_capacity(8);
        for b in &issuer.0[0..4] {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    };
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
