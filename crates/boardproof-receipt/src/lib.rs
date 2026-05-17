//! Receipt format types for the BoardProof verifiable agent runtime.
//!
//! A receipt is a signed, verifiable record that an agent action occurred.
//! Receipts are addressable by their content hash: `boardproof://receipt/<hash>`.
//!
//! Type definitions are always available. Cryptographic signing and verifying
//! helpers live behind the `crypto` feature so this crate stays tiny when only
//! the wire format is needed.
//!
//! Receipt format spec: see `RFCS/0001-receipt-format.md`.
//!
//! ## Canonicalization (v2 +)
//!
//! Receipts at `schema_version >= 2` use **RFC 8785 JSON
//! Canonicalization Scheme** for content-id and signature bytes
//! (see [`canonical`]). The canonical encoding is deterministic
//! across implementations and languages — this is what makes
//! "verify a BoardProof receipt with a 200-LOC binary in any
//! language" actually work in practice. v1 receipts (minted by
//! pre-step-19 kernels) use `serde_json`'s default encoding for
//! backwards compatibility; verifier dispatches on
//! `body.schema_version`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

pub mod canonical;

/// Wire-format version. Bumped on any breaking schema change.
///
/// - **v1** (Phase 0-step-18): `serde_json`'s default JSON encoding;
///   field order = struct declaration order. Deterministic in
///   Rust but not portable across languages.
/// - **v2** (Phase 3.5 / step 19+): RFC 8785 JCS. Same logical
///   shape as v1; canonicalization is the wire change. Lexicographic
///   key ordering, normalized number formatting, standard string
///   escapes. Cross-language interoperable.
///
/// Verifier dispatches on `body.schema_version`. v1 receipts in
/// the wild continue to verify under v1 rules; new receipts go
/// out as v2.
pub const RECEIPT_FORMAT_VERSION: u32 = 2;

/// A 32-byte BLAKE3 digest, used for content addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "hex_array")] pub [u8; 32]);

/// A 64-byte Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "hex_array_64")] pub [u8; 64]);

/// A 32-byte Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "hex_array")] pub [u8; 32]);

/// A signed receipt. The kernel's primary verifiable output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Wire-format version.
    pub version: u32,
    /// Body of the receipt — what the signature covers.
    pub body: ReceiptBody,
    /// Issuer's Ed25519 public key.
    pub issuer: PublicKey,
    /// Ed25519 signature over the canonical encoding of `body`.
    pub signature: Signature,
}

/// The signed portion of a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Receipt schema version.
    pub schema_version: u32,
    /// RFC 3339 timestamp.
    pub issued_at: String,
    /// Action that produced this receipt.
    pub action: Action,
    /// Decision the kernel made.
    pub decision: Decision,
    /// Constitution rule IDs that fired (if any).
    pub constitution_rules: Vec<RuleRef>,
    /// Provenance edges recorded for this action.
    pub provenance: Vec<ProvenanceEdge>,
    /// Hash of the redactor stack that ran on the output (if any).
    pub redactor_stack_hash: Option<Digest>,
    /// Opaque, operator-chosen identifier for the signing key
    /// that minted this receipt (step 19a).
    ///
    /// Treated as audit-only metadata: the *bytes* of the issuer
    /// public key remain the trust anchor for signature
    /// verification. `key_id` lets an auditor correlate the
    /// receipt with an external key directory entry — e.g.
    /// `"prod-2026"` rotated to `"prod-2027"` on 2027-01-01,
    /// `"hsm-3"` revoked on incident X — without trusting bytes
    /// blindly.
    ///
    /// Wire-format additive: when `None`, the field is omitted
    /// from the canonical bytes (`#[serde(skip_serializing_if =
    /// "Option::is_none")]`). Old receipts (no `key_id`) keep
    /// verifying byte-identically against pre-19a verifiers.
    /// New receipts with `key_id` set are byte-different but
    /// still parse and verify under any verifier that handles
    /// unknown / extra fields (Rust serde-default, the TS / Python
    /// JCS canonicalizers — all three of which sort + emit
    /// whatever keys are present).
    ///
    /// The `schema_version` is NOT bumped: this is an additive
    /// change to the v2 wire shape, not a new version. The RFC
    /// notes the spec revision as "2.1" but the wire field stays 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Position of this action in the Merkle audit chain.
    pub merkle_leaf: MerkleLeaf,
}

/// What the agent attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub kind: String,
    pub target: String,
    pub input_hash: Digest,
}

/// The kernel's decision on the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    Denied,
    Approved,
    Pending,
}

/// Reference to a Constitution rule by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub id: String,
    pub matched: bool,
}

/// Typed edge in the provenance graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

/// One redactor rule's match-count after a redaction pass.
///
/// Phase 3 step 18 audit primitive. Recorded in
/// [`RedactionReport::matches`] and emitted by the kernel as a
/// `redaction_applied` provenance edge per rule with `count > 0`.
///
/// The `rule_id` is the operator-stable identifier of the rule
/// (e.g. `"github_pat"`, `"openai_key"`). Auditors correlate
/// `rule_id` ↔ rule definition via the operator's published
/// redactor configuration, OR via the future `$kernel/policy/redactor`
/// receipt class (Phase 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub count: u32,
}

/// Pre-receipt audit data describing what a redactor stack did to
/// a tool's output. Produced *outside* the kernel (by code that
/// has access to the raw bytes) and submitted alongside a tool
/// execution event. The kernel reads three fields:
///
/// - `redacted_output_hash` becomes the receipt's `output_hash`
///   (committing the receipt to the post-redaction form).
/// - `matches` becomes one `redaction_applied` provenance edge
///   per rule with `count > 0`.
/// - `stack_hash` populates [`ReceiptBody::redactor_stack_hash`].
///
/// The original (un-redacted) bytes are NEVER part of this
/// struct — they only exist transiently in the producer's
/// memory. The receipt commits to the redacted form by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionReport {
    /// BLAKE3 of the redacted output bytes. The kernel uses this
    /// as `output_hash` instead of the un-redacted hash.
    pub redacted_output_hash: Digest,

    /// Per-rule match counts. Rules with `count == 0` may be
    /// omitted; the kernel only emits provenance edges for
    /// non-zero counts.
    pub matches: Vec<RuleMatch>,

    /// Stable hash committing to which redactor stack ran.
    /// Convention: BLAKE3 over the joined rule IDs in order
    /// (separator-defined by the producer; see
    /// `boardproof-redact::RedactorStack::stack_hash`).
    pub stack_hash: Digest,
}

/// Position of this action in the Merkle audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleLeaf {
    pub sequence: u64,
    pub leaf_hash: Digest,
    pub prev_hash: Digest,
}

impl Receipt {
    /// Compute the content-addressable id of the receipt.
    ///
    /// The id is BLAKE3 of the canonical encoding of the body.
    /// Canonicalization rules dispatch on `body.schema_version`:
    ///
    /// - v1: `serde_json`'s default JSON encoding (struct-declaration
    ///   key order). Pre-step-19 receipts in the wild verify under
    ///   these rules.
    /// - v2 +: RFC 8785 JCS (lexicographic key order, normalized
    ///   numbers, standard string escapes). Cross-language
    ///   interoperable.
    ///
    /// (Content-addressing the body, not the wrapper, lets us add
    /// fields to the wrapper later without breaking existing
    /// receipt URLs.)
    #[must_use]
    pub fn content_id(&self) -> Digest {
        let canonical = canonicalize_for_schema(&self.body);
        Digest(*blake3::hash(&canonical).as_bytes())
    }
}

/// Dispatch a [`ReceiptBody`] through the canonicalizer matching
/// its `schema_version`.
///
/// Behavior:
/// - `schema_version <= 1` → `serde_json`'s default JSON encoding
///   (the pre-step-19 byte format). Receipts already in the wild
///   keep verifying.
/// - `schema_version >= 2` → RFC 8785 JCS via [`canonical::to_vec`].
///
/// Both paths produce a `Vec<u8>` suitable for hashing or signing.
pub(crate) fn canonicalize_for_schema(body: &ReceiptBody) -> Vec<u8> {
    if body.schema_version <= 1 {
        // Legacy path: serde_json default. We expect this to never
        // fail on a well-formed `ReceiptBody`; the panic-on-error
        // matches the previous behavior of `expect("canonical body
        // must encode")`.
        serde_json::to_vec(body).expect("legacy canonicalization must encode")
    } else {
        canonical::to_vec(body).expect("v2 JCS canonicalization must encode")
    }
}

/// Why a hex string could not be parsed into a fixed-size byte array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexDecodeError {
    /// The string had the wrong length for the target type.
    InvalidLength { expected: usize, got: usize },
    /// The string contained a non-hex character.
    InvalidCharacter,
}

impl core::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "invalid hex length: expected {expected}, got {got}")
            }
            Self::InvalidCharacter => f.write_str("invalid hex character"),
        }
    }
}

impl core::error::Error for HexDecodeError {}

impl Digest {
    /// Encode the 32-byte digest as a 64-character lowercase hex string.
    /// Used by the `boardproof://receipt/<hash>` URL form and the public-URL
    /// hosting endpoint (`/receipts/<hex>`).
    #[must_use]
    pub fn to_hex(&self) -> alloc::string::String {
        let mut out = alloc::string::String::with_capacity(64);
        for &b in &self.0 {
            out.push(hex_nib(b >> 4));
            out.push(hex_nib(b & 0xf));
        }
        out
    }

    /// Parse a 64-character lowercase or uppercase hex string into a digest.
    ///
    /// # Errors
    ///
    /// Returns `HexDecodeError::InvalidLength` if the input is not exactly
    /// 64 characters, or `HexDecodeError::InvalidCharacter` if it contains
    /// a non-hex byte.
    pub fn from_hex(s: &str) -> Result<Self, HexDecodeError> {
        if s.len() != 64 {
            return Err(HexDecodeError::InvalidLength {
                expected: 64,
                got: s.len(),
            });
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = hex_unnib(bytes[i * 2])?;
            let lo = hex_unnib(bytes[i * 2 + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Digest(out))
    }
}

fn hex_nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

fn hex_unnib(c: u8) -> Result<u8, HexDecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexDecodeError::InvalidCharacter),
    }
}

// --- helpers for hex-encoding fixed-size arrays in JSON ---

mod hex_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        encode_hex::<32>(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = alloc::string::String::deserialize(d)?;
        decode_hex::<32>(&s).map_err(serde::de::Error::custom)
    }

    fn encode_hex<const N: usize>(bytes: &[u8; N]) -> alloc::string::String {
        let mut out = alloc::string::String::with_capacity(N * 2);
        for &b in bytes {
            out.push(nib(b >> 4));
            out.push(nib(b & 0xf));
        }
        out
    }

    fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
        if s.len() != N * 2 {
            return Err("invalid hex length");
        }
        let mut out = [0u8; N];
        let bytes = s.as_bytes();
        for i in 0..N {
            out[i] = (un(bytes[i * 2])? << 4) | un(bytes[i * 2 + 1])?;
        }
        Ok(out)
    }

    fn nib(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            10..=15 => (b'a' + n - 10) as char,
            _ => unreachable!(),
        }
    }

    fn un(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

mod hex_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = alloc::string::String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }

    fn encode(bytes: &[u8; 64]) -> alloc::string::String {
        let mut out = alloc::string::String::with_capacity(128);
        for &b in bytes {
            out.push(nib(b >> 4));
            out.push(nib(b & 0xf));
        }
        out
    }

    fn decode(s: &str) -> Result<[u8; 64], &'static str> {
        if s.len() != 128 {
            return Err("invalid hex length");
        }
        let mut out = [0u8; 64];
        let bytes = s.as_bytes();
        for i in 0..64 {
            out[i] = (un(bytes[i * 2])? << 4) | un(bytes[i * 2 + 1])?;
        }
        Ok(out)
    }

    fn nib(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            10..=15 => (b'a' + n - 10) as char,
            _ => unreachable!(),
        }
    }

    fn un(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

// --- crypto helpers (feature-gated) ---

/// Errors that can occur while verifying a receipt's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Issuer public key did not parse as a valid Ed25519 key.
    InvalidIssuerKey,
    /// Signature did not match the body under the issuer key.
    SignatureMismatch,
    /// Wire-format version is not understood by this verifier.
    UnsupportedVersion { found: u32, expected: u32 },
    /// Body could not be canonically encoded for verification.
    EncodingFailed,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidIssuerKey => f.write_str("invalid issuer public key"),
            Self::SignatureMismatch => f.write_str("signature did not verify"),
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported receipt version {found} (verifier supports {expected})"
                )
            }
            Self::EncodingFailed => f.write_str("could not canonically encode receipt body"),
        }
    }
}

impl core::error::Error for VerifyError {}

/// Ed25519 signing and verifying helpers. Enable with the `crypto` feature.
#[cfg(any(feature = "crypto", test))]
pub mod crypto {
    use super::{
        PublicKey, RECEIPT_FORMAT_VERSION, Receipt, ReceiptBody, Signature, VerifyError,
        canonicalize_for_schema,
    };
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

    /// Sign a receipt body with the given Ed25519 key.
    ///
    /// The signature covers the canonical encoding of `body` —
    /// either `serde_json` default (`schema_version <= 1`) or
    /// RFC 8785 JCS (`schema_version >= 2`). Verifiers in any
    /// language can recompute the same canonical bytes from the
    /// receipt body's logical structure and check the signature.
    #[must_use]
    pub fn sign(body: ReceiptBody, signing_key: &SigningKey) -> Receipt {
        let body_bytes = canonicalize_for_schema(&body);
        let sig = signing_key.sign(&body_bytes);
        Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body,
            issuer: PublicKey(signing_key.verifying_key().to_bytes()),
            signature: Signature(sig.to_bytes()),
        }
    }

    /// Verify a receipt's Ed25519 signature against its embedded
    /// issuer key.
    ///
    /// Wire-format version policy: this build understands
    /// `RECEIPT_FORMAT_VERSION` (currently 2). Receipts with
    /// `version <= RECEIPT_FORMAT_VERSION` verify; receipts with
    /// a higher version are rejected with `UnsupportedVersion`
    /// (the verifier can't know how to canonicalize a future
    /// schema). The actual canonicalization rule is selected by
    /// `body.schema_version` so v1 receipts continue to verify
    /// under v1 rules (legacy `serde_json`) while v2 receipts use
    /// JCS — both paths run in this same binary.
    pub fn verify(receipt: &Receipt) -> Result<(), VerifyError> {
        if receipt.version > RECEIPT_FORMAT_VERSION {
            return Err(VerifyError::UnsupportedVersion {
                found: receipt.version,
                expected: RECEIPT_FORMAT_VERSION,
            });
        }

        let body_bytes = canonicalize_for_schema(&receipt.body);

        let key = VerifyingKey::from_bytes(&receipt.issuer.0)
            .map_err(|_| VerifyError::InvalidIssuerKey)?;

        let signature = ed25519_dalek::Signature::from_bytes(&receipt.signature.0);

        key.verify(&body_bytes, &signature)
            .map_err(|_| VerifyError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
            constitution_rules: vec![],
            provenance: vec![],
            redactor_stack_hash: None,
            key_id: None,
            merkle_leaf: MerkleLeaf {
                sequence: 0,
                leaf_hash: Digest([0u8; 32]),
                prev_hash: Digest([0u8; 32]),
            },
        }
    }

    #[test]
    fn body_round_trips_through_json() {
        let body = sample_body();
        let encoded = serde_json::to_string(&body).expect("encode");
        let decoded: ReceiptBody = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(body, decoded);
    }

    #[test]
    fn content_id_is_deterministic() {
        let receipt = Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body: sample_body(),
            issuer: PublicKey([1u8; 32]),
            signature: Signature([2u8; 64]),
        };
        let id1 = receipt.content_id();
        let id2 = receipt.content_id();
        assert_eq!(id1, id2);
        // Different body → different id.
        let mut other = receipt.clone();
        other.body.merkle_leaf.sequence = 1;
        assert_ne!(receipt.content_id(), other.content_id());
    }

    #[test]
    fn digest_hex_round_trips() {
        let d = Digest([
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c,
        ]);
        let hex = d.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("deadbeef"));
        let parsed = Digest::from_hex(&hex).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn digest_from_hex_accepts_uppercase() {
        let lower = Digest([0xab; 32]).to_hex();
        let upper = lower.to_uppercase();
        assert_eq!(Digest::from_hex(&upper).unwrap(), Digest([0xab; 32]));
    }

    #[test]
    fn digest_from_hex_rejects_wrong_length_and_bad_chars() {
        assert!(matches!(
            Digest::from_hex("abcd"),
            Err(HexDecodeError::InvalidLength {
                expected: 64,
                got: 4
            }),
        ));
        let bad = "z".repeat(64);
        assert_eq!(
            Digest::from_hex(&bad),
            Err(HexDecodeError::InvalidCharacter)
        );
    }

    #[test]
    fn content_id_ignores_signature_changes() {
        // Two receipts with identical bodies but different signatures
        // share the same content id, by design.
        let a = Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body: sample_body(),
            issuer: PublicKey([1u8; 32]),
            signature: Signature([2u8; 64]),
        };
        let mut b = a.clone();
        b.signature = Signature([3u8; 64]);
        assert_eq!(a.content_id(), b.content_id());
    }

    mod crypto_tests {
        use super::*;
        use ed25519_dalek::SigningKey;

        fn key() -> SigningKey {
            SigningKey::from_bytes(&[7u8; 32])
        }

        #[test]
        fn sign_then_verify_roundtrips() {
            let receipt = crate::crypto::sign(sample_body(), &key());
            crate::crypto::verify(&receipt).expect("freshly signed receipt must verify");
        }

        #[test]
        fn tampered_body_fails_verification() {
            let mut receipt = crate::crypto::sign(sample_body(), &key());
            // Mutate the action target after signing — signature was over the original.
            receipt.body.action.target = "https://evil.example.com/".into();
            assert_eq!(
                crate::crypto::verify(&receipt),
                Err(crate::VerifyError::SignatureMismatch),
            );
        }

        #[test]
        fn tampered_signature_fails_verification() {
            let mut receipt = crate::crypto::sign(sample_body(), &key());
            receipt.signature.0[0] ^= 0xff;
            assert_eq!(
                crate::crypto::verify(&receipt),
                Err(crate::VerifyError::SignatureMismatch),
            );
        }

        #[test]
        fn wrong_issuer_fails_verification() {
            let mut receipt = crate::crypto::sign(sample_body(), &key());
            // Replace issuer with the public half of a different signing key.
            let other = SigningKey::from_bytes(&[9u8; 32]);
            receipt.issuer = PublicKey(other.verifying_key().to_bytes());
            assert_eq!(
                crate::crypto::verify(&receipt),
                Err(crate::VerifyError::SignatureMismatch),
            );
        }

        #[test]
        fn unsupported_version_is_rejected() {
            let mut receipt = crate::crypto::sign(sample_body(), &key());
            receipt.version = u32::MAX;
            assert!(matches!(
                crate::crypto::verify(&receipt),
                Err(crate::VerifyError::UnsupportedVersion { .. }),
            ));
        }
    }
}
