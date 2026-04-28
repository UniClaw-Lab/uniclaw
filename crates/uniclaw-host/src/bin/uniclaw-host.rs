//! `uniclaw-host` — small server that serves receipts from a directory.
//!
//! Loads every `*.json` file under `--receipts-dir` into an in-memory log
//! at startup, validates the chain, and binds an HTTP listener on
//! `--bind`. Useful for demos and as a reference impl until the
//! SQLite-backed receipt log lands.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::sync::RwLock;

use uniclaw_host::router;
use uniclaw_receipt::{PublicKey, Receipt};
use uniclaw_store::{InMemoryReceiptLog, ReceiptLog};

#[derive(Parser, Debug)]
#[command(
    name = "uniclaw-host",
    about = "Serve Uniclaw receipts at uniclaw://receipt/<hash> over HTTP."
)]
struct Args {
    /// Directory of `*.json` receipt files to load at startup.
    #[arg(long, default_value = "./receipts")]
    receipts_dir: PathBuf,

    /// Address to bind the HTTP listener on.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log = load_receipts_dir(&args.receipts_dir)
        .with_context(|| format!("loading receipts from {}", args.receipts_dir.display()))?;
    let count = log.len();
    let issuer = log.issuer();

    let app = router(Arc::new(RwLock::new(log)));

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
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
        "uniclaw-host: serving {count} receipt(s) (issuer {issuer_prefix}) on http://{local}"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("uniclaw-host: shutting down");
        })
        .await?;

    Ok(())
}

fn load_receipts_dir(dir: &PathBuf) -> Result<InMemoryReceiptLog> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }

    // Read every *.json file, sort by the receipt's sequence so the chain
    // appends in order, then construct the log.
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
        // Empty log is fine — useful for demoing /healthz against an empty
        // store. Caller picks the issuer key in that case via env var.
        let issuer = pin_issuer_from_env()?;
        return Ok(InMemoryReceiptLog::new(issuer));
    }

    // Pin the log to the issuer of the first receipt; append validates
    // every subsequent receipt against the pinned issuer + chain.
    let pinned = entries[0].1.issuer;
    let mut log = InMemoryReceiptLog::new(pinned);
    for (_, r) in entries {
        log.append(r)
            .context("append failed during load — chain broken or out of order")?;
    }
    Ok(log)
}

fn pin_issuer_from_env() -> Result<PublicKey> {
    // For an empty log, a public key has to come from somewhere. Read it
    // from `UNICLAW_HOST_ISSUER` (64-char hex). If unset, refuse to start
    // — silently picking a zero key would be a security smell.
    let s = std::env::var("UNICLAW_HOST_ISSUER")
        .context("empty receipts dir; set UNICLAW_HOST_ISSUER=<64-hex> to pin the log")?;
    let bytes = uniclaw_receipt::Digest::from_hex(&s)
        .context("UNICLAW_HOST_ISSUER must be 64 hex characters")?;
    Ok(PublicKey(bytes.0))
}
