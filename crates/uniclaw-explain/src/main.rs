//! `uniclaw-explain` — print a human-readable decision tree for any receipt.
//!
//! Reads a receipt from a file (or `-` for stdin), verifies its signature,
//! and prints either plain text (default) or pretty JSON (`--json`).

use anyhow::{Context, Result};
use clap::Parser;
use uniclaw_receipt::Receipt;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a JSON-encoded receipt. Use `-` for stdin.
    receipt: String,

    /// Emit pretty JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let bytes = read_input(&cli.receipt).context("read receipt input")?;
    let receipt: Receipt = serde_json::from_slice(&bytes).context("parse receipt JSON")?;

    let exp = uniclaw_explain::explain(&receipt);

    let out = if cli.json {
        uniclaw_explain::render_json(&exp)
    } else {
        uniclaw_explain::render_text(&exp)
    };
    println!("{out}");

    // Exit non-zero if the signature failed, so this binary is scriptable
    // ("explain succeeded only if the receipt is authentic").
    if matches!(exp.signature, uniclaw_explain::SignatureStatus::Failed(_)) {
        std::process::exit(2);
    }
    Ok(())
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(Into::into)
    }
}
