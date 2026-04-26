//! Integration tests: drive the actual `uniclaw-explain` binary as a
//! subprocess against freshly-minted receipts.

use std::io::Write;
use std::process::{Command, Stdio};

use ed25519_dalek::SigningKey;
use uniclaw_receipt::{
    Action, Decision, Digest, MerkleLeaf, ProvenanceEdge, RECEIPT_FORMAT_VERSION, Receipt,
    ReceiptBody, RuleRef, crypto,
};

const EXPLAIN_BIN: &str = env!("CARGO_BIN_EXE_uniclaw-explain");

fn sign(body: ReceiptBody) -> Receipt {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    crypto::sign(body, &key)
}

fn allowed_body() -> ReceiptBody {
    ReceiptBody {
        schema_version: RECEIPT_FORMAT_VERSION,
        issued_at: "2026-04-26T12:00:00Z".into(),
        action: Action {
            kind: "http.fetch".into(),
            target: "https://example.com/foo".into(),
            input_hash: Digest([0u8; 32]),
        },
        decision: Decision::Allowed,
        constitution_rules: vec![],
        provenance: vec![ProvenanceEdge {
            from: "user".into(),
            to: "model".into(),
            kind: "request".into(),
        }],
        redactor_stack_hash: None,
        merkle_leaf: MerkleLeaf {
            sequence: 0,
            leaf_hash: Digest([0xAB; 32]),
            prev_hash: Digest([0u8; 32]),
        },
    }
}

fn denied_by_constitution_body() -> ReceiptBody {
    let mut b = allowed_body();
    b.action.kind = "shell.exec".into();
    b.action.target = "rm -rf /".into();
    b.decision = Decision::Denied;
    b.constitution_rules = vec![RuleRef {
        id: "solo-dev/no-shell".into(),
        matched: true,
    }];
    b
}

fn denied_by_budget_body() -> ReceiptBody {
    let mut b = allowed_body();
    b.decision = Decision::Denied;
    b.constitution_rules = vec![RuleRef {
        id: "$kernel/budget/net_bytes_exhausted".into(),
        matched: true,
    }];
    b
}

fn run(json: &str, extra: &[&str]) -> std::process::Output {
    let mut child = Command::new(EXPLAIN_BIN)
        .args(extra)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn uniclaw-explain");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(json.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

#[test]
fn explains_an_allowed_receipt_in_text_mode() {
    let receipt = sign(allowed_body());
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run(&json, &[]);
    assert!(
        out.status.success(),
        "exit={}, stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("ALLOWED"));
    assert!(stdout.contains("Signature  verified"));
    assert!(stdout.contains("http.fetch -> https://example.com/foo"));
    assert!(stdout.contains("genesis"));
}

#[test]
fn explains_a_denied_by_constitution_receipt() {
    let receipt = sign(denied_by_constitution_body());
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run(&json, &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("DENIED"));
    assert!(stdout.contains("solo-dev/no-shell"));
    assert!(stdout.contains("constitution rule"));
}

#[test]
fn explains_a_denied_by_budget_receipt() {
    let receipt = sign(denied_by_budget_body());
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run(&json, &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("DENIED"));
    assert!(stdout.contains("capability lease"));
    assert!(stdout.contains("net_bytes"));
}

#[test]
fn json_mode_emits_parseable_json() {
    let receipt = sign(allowed_body());
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run(&json, &["--json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must parse");
    assert_eq!(parsed["decision"], "allowed");
    assert_eq!(parsed["signature"]["status"], "verified");
    assert!(
        parsed["canonical_url"]
            .as_str()
            .unwrap()
            .starts_with("uniclaw://receipt/")
    );
}

#[test]
fn tampered_receipt_exits_2_and_warns_in_text() {
    let mut receipt = sign(allowed_body());
    receipt.body.action.target = "https://evil.example/".into();
    let json = serde_json::to_string(&receipt).unwrap();
    let out = run(&json, &[]);
    // Exit code 2 = signature failed (per main.rs contract).
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("SIGNATURE INVALID"));
    assert!(stdout.contains("FAILED"));
}

#[test]
fn malformed_json_fails_with_clear_error() {
    let out = run("this is not json", &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("parse receipt JSON"));
}
