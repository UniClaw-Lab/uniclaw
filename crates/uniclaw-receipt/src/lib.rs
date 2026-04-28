//! Receipt format types for the Uniclaw verifiable agent runtime.
//!
//! A receipt is a signed, verifiable record that an agent action occurred.
//! Receipts are addressable by their content hash: `uniclaw://receipt/<hash>`.
//!
//! Type definitions are always available. Cryptographic signing and verifying
//! helpers live behind the `crypto` feature so this crate stays tiny when only
//! the wire format is needed.
//!
//! Receipt format spec: see `RFCS/0001-receipt-format.md`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Wire-format version. Bumped on any breaking schema change.
pub const RECEIPT_FORMAT_VERSION: u32 = 1;

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
    /// The id is BLAKE3 of the canonical JSON encoding of the body.
    /// (Content-addressing the body, not the wrapper, lets us add fields to
    /// the wrapper later without breaking existing receipt URLs.)
    #[must_use]
    pub fn content_id(&self) -> Digest {
        let canonical = serde_json::to_vec(&self.body).expect("canonical body must encode");
        Digest(*blake3::hash(&canonical).as_bytes())
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
    /// Used by the `uniclaw://receipt/<hash>` URL form and the public-URL
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
    use super::{PublicKey, RECEIPT_FORMAT_VERSION, Receipt, ReceiptBody, Signature, VerifyError};
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

    /// Sign a receipt body with the given Ed25519 key.
    ///
    /// The signature covers the canonical JSON encoding of `body`.
    #[must_use]
    pub fn sign(body: ReceiptBody, signing_key: &SigningKey) -> Receipt {
        let body_bytes = serde_json::to_vec(&body).expect("canonical body must encode");
        let sig = signing_key.sign(&body_bytes);
        Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body,
            issuer: PublicKey(signing_key.verifying_key().to_bytes()),
            signature: Signature(sig.to_bytes()),
        }
    }

    /// Verify a receipt's Ed25519 signature against its embedded issuer key.
    ///
    /// Also checks that the wire-format version is one this build understands.
    pub fn verify(receipt: &Receipt) -> Result<(), VerifyError> {
        if receipt.version != RECEIPT_FORMAT_VERSION {
            return Err(VerifyError::UnsupportedVersion {
                found: receipt.version,
                expected: RECEIPT_FORMAT_VERSION,
            });
        }

        let body_bytes =
            serde_json::to_vec(&receipt.body).map_err(|_| VerifyError::EncodingFailed)?;

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
