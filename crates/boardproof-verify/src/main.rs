//! `boardproof-verify` — the standalone receipt verifier.
//!
//! One job: take a receipt (JSON), verify its Ed25519 signature, and report
//! pass/fail. All cryptographic logic lives in `boardproof-receipt::crypto`; this
//! binary is just a thin CLI wrapper, kept tiny so anyone can install it
//! without pulling in the kernel.

use anyhow::{Context, Result};
use boardproof_receipt::Receipt;
use clap::Parser;

/// Verify a BoardProof receipt.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a JSON-encoded receipt. Use `-` for stdin.
    receipt: String,

    /// Print the verified body as pretty JSON on success.
    #[arg(long)]
    print: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let bytes = read_input(&cli.receipt).context("read receipt input")?;
    let receipt: Receipt = serde_json::from_slice(&bytes).context("parse receipt JSON")?;

    boardproof_receipt::crypto::verify(&receipt).context("verify receipt")?;

    println!("ok: receipt {} verified", hex(&receipt.content_id().0));

    if cli.print {
        let pretty = serde_json::to_string_pretty(&receipt.body)?;
        println!("{pretty}");
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

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(nib(b >> 4));
        s.push(nib(b & 0xf));
    }
    s
}

fn nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}
