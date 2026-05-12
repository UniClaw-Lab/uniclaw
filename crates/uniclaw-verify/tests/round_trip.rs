//! Integration tests: sign a receipt, then verify it by spawning the actual
//! `uniclaw-verify` binary as a subprocess. This is the milestone exit
//! criterion for Phase 0 — *first end-to-end public receipt verified*.

use std::io::Write;
use std::process::{Command, Stdio};

use ed25519_dalek::SigningKey;
use uniclaw_receipt::{
    Action, Decision, Digest, MerkleLeaf, ProvenanceEdge, RECEIPT_FORMAT_VERSION, ReceiptBody,
    RuleRef, crypto,
};

const VERIFY_BIN: &str = env!("CARGO_BIN_EXE_uniclaw-verify");

fn fresh_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn sample_body() -> ReceiptBody {
    ReceiptBody {
        schema_version: RECEIPT_FORMAT_VERSION,
        issued_at: "2026-04-26T00:00:00Z".into(),
        action: Action {
            kind: "http.fetch".into(),
            target: "https://example.com/".into(),
            input_hash: Digest([0u8; 32]),
        },
        decision: Decision::Allowed,
        constitution_rules: vec![RuleRef {
            id: "solo-dev/no-shell-without-approval".into(),
            matched: false,
        }],
        provenance: vec![ProvenanceEdge {
            from: "user".into(),
            to: "model".into(),
            kind: "request".into(),
        }],
        redactor_stack_hash: None,
        key_id: None,
        merkle_leaf: MerkleLeaf {
            sequence: 0,
            leaf_hash: Digest([0u8; 32]),
            prev_hash: Digest([0u8; 32]),
        },
    }
}

fn run_verify(json: &str, extra: &[&str]) -> std::process::Output {
    let mut child = Command::new(VERIFY_BIN)
        .args(extra)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn uniclaw-verify");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(json.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        let n = |x: u8| match x {
            0..=9 => (b'0' + x) as char,
            10..=15 => (b'a' + x - 10) as char,
            _ => unreachable!(),
        };
        s.push(n(b >> 4));
        s.push(n(b & 0xf));
    }
    s
}

#[test]
fn signed_receipt_round_trips_through_binary() {
    let key = fresh_key();
    let receipt = crypto::sign(sample_body(), &key);

    let json = serde_json::to_string(&receipt).expect("encode");
    let out = run_verify(&json, &[]);

    assert!(
        out.status.success(),
        "verifier should succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let expected_id = hex32(&receipt.content_id().0);
    assert!(
        stdout.contains(&expected_id),
        "stdout {stdout} must contain content id {expected_id}",
    );
    assert!(stdout.contains("verified"));
}

#[test]
fn print_flag_emits_pretty_body() {
    let receipt = crypto::sign(sample_body(), &fresh_key());
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run_verify(&json, &["--print"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"action\": {"));
    assert!(stdout.contains("\"target\": \"https://example.com/\""));
}

#[test]
fn tampered_body_fails() {
    let mut receipt = crypto::sign(sample_body(), &fresh_key());
    // Mutate the action target after signing — signature was over the original.
    receipt.body.action.target = "https://evil.example.com/".into();
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run_verify(&json, &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("signature did not verify"),
        "expected signature failure in stderr; got: {stderr}",
    );
}

#[test]
fn tampered_signature_fails() {
    let mut receipt = crypto::sign(sample_body(), &fresh_key());
    receipt.signature.0[0] ^= 0xff;
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run_verify(&json, &[]);
    assert!(!out.status.success());
}

#[test]
fn wrong_issuer_fails() {
    let mut receipt = crypto::sign(sample_body(), &fresh_key());
    let other = SigningKey::from_bytes(&[9u8; 32]);
    receipt.issuer = uniclaw_receipt::PublicKey(other.verifying_key().to_bytes());
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run_verify(&json, &[]);
    assert!(!out.status.success());
}

#[test]
fn unsupported_version_fails() {
    let mut receipt = crypto::sign(sample_body(), &fresh_key());
    receipt.version = u32::MAX;
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run_verify(&json, &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported receipt version"),
        "expected version-mismatch failure in stderr; got: {stderr}",
    );
}

#[test]
fn malformed_json_fails() {
    let out = run_verify("this is not json", &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("parse receipt JSON"));
}

#[test]
fn missing_file_fails() {
    let out = Command::new(VERIFY_BIN)
        .arg("/this/path/does/not/exist")
        .output()
        .expect("spawn");
    assert!(!out.status.success());
}
