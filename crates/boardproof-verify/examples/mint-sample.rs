//! Mint a sample receipt and print it as JSON to stdout.
//!
//! Useful as documentation ("how do I produce a receipt?") and as a building
//! block for benchmarking: pipe the output into `boardproof-verify -` to time a
//! verification.
//!
//! ```text
//! cargo run --release --example mint-sample > sample.json
//! cargo run --release --bin boardproof-verify -- sample.json
//! ```

use boardproof_receipt::{
    Action, Decision, Digest, MerkleLeaf, ProvenanceEdge, RECEIPT_FORMAT_VERSION, ReceiptBody,
    RuleRef, crypto,
};
use ed25519_dalek::SigningKey;

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);

    let body = ReceiptBody {
        schema_version: RECEIPT_FORMAT_VERSION,
        issued_at: "2026-04-26T12:00:00Z".into(),
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
    };

    let receipt = crypto::sign(body, &key);
    let json = serde_json::to_string(&receipt).expect("encode receipt");
    println!("{json}");
}
