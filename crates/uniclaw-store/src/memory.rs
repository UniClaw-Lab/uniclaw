//! `InMemoryReceiptLog` — `Vec<Receipt>`-backed implementation with a
//! `BTreeMap` index for content-id lookups. Default for unit tests and
//! short-lived runtimes; the SQLite-backed impl arrives in a follow-up.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use uniclaw_receipt::{Digest, PublicKey, RECEIPT_FORMAT_VERSION, Receipt, crypto};

use crate::log::{AppendError, ReceiptLog, VerifyChainError};

/// Receipt log backed by an in-memory `Vec`.
#[derive(Debug, Clone)]
pub struct InMemoryReceiptLog {
    issuer: PublicKey,
    receipts: Vec<Receipt>,
    /// Index from receipt content id to position in `receipts`.
    by_id: BTreeMap<[u8; 32], usize>,
}

impl InMemoryReceiptLog {
    /// Construct an empty log pinned to `issuer`.
    #[must_use]
    pub fn new(issuer: PublicKey) -> Self {
        Self {
            issuer,
            receipts: Vec::new(),
            by_id: BTreeMap::new(),
        }
    }

    /// Read-only view of the underlying receipts in chain order.
    #[must_use]
    pub fn as_slice(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Iterate over the receipts in chain order.
    pub fn iter(&self) -> core::slice::Iter<'_, Receipt> {
        self.receipts.iter()
    }
}

impl<'a> IntoIterator for &'a InMemoryReceiptLog {
    type Item = &'a Receipt;
    type IntoIter = core::slice::Iter<'a, Receipt>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl ReceiptLog for InMemoryReceiptLog {
    fn issuer(&self) -> PublicKey {
        self.issuer
    }

    fn append(&mut self, receipt: Receipt) -> Result<(), AppendError> {
        // 1. Wire-format version check.
        if receipt.version != RECEIPT_FORMAT_VERSION {
            return Err(AppendError::UnsupportedVersion {
                found: receipt.version,
                expected: RECEIPT_FORMAT_VERSION,
            });
        }

        // 2. Issuer pin check — receipt must be from the same kernel.
        if receipt.issuer != self.issuer {
            return Err(AppendError::IssuerMismatch {
                expected: self.issuer,
                got: receipt.issuer,
            });
        }

        // 3. Sequence + chain check.
        let expected_seq = self.receipts.len() as u64;
        let got_seq = receipt.body.merkle_leaf.sequence;
        if got_seq != expected_seq {
            return Err(AppendError::OutOfOrder {
                expected: expected_seq,
                got: got_seq,
            });
        }
        let expected_prev = self
            .receipts
            .last()
            .map_or(Digest([0u8; 32]), |r| r.body.merkle_leaf.leaf_hash);
        let got_prev = receipt.body.merkle_leaf.prev_hash;
        if got_prev != expected_prev {
            return Err(AppendError::ChainBroken {
                expected: expected_prev,
                got: got_prev,
            });
        }

        // 4. Signature check — last because it's the most expensive.
        crypto::verify(&receipt).map_err(|_| AppendError::SignatureInvalid)?;

        // 5. Duplicate-id check. Defensive; in practice a verified
        //    chained receipt at the right sequence cannot duplicate an
        //    earlier id.
        let id = receipt.content_id().0;
        if self.by_id.contains_key(&id) {
            return Err(AppendError::DuplicateId(receipt.content_id()));
        }

        let position = self.receipts.len();
        self.receipts.push(receipt);
        self.by_id.insert(id, position);
        Ok(())
    }

    fn len(&self) -> usize {
        self.receipts.len()
    }

    fn last(&self) -> Option<&Receipt> {
        self.receipts.last()
    }

    fn get_by_sequence(&self, sequence: u64) -> Option<&Receipt> {
        let idx = usize::try_from(sequence).ok()?;
        self.receipts.get(idx)
    }

    fn get_by_id(&self, id: &Digest) -> Option<&Receipt> {
        let position = *self.by_id.get(&id.0)?;
        self.receipts.get(position)
    }

    fn verify_chain(&self) -> Result<(), VerifyChainError> {
        let mut expected_prev = Digest([0u8; 32]);
        for (i, receipt) in self.receipts.iter().enumerate() {
            let expected_seq = i as u64;
            let got_seq = receipt.body.merkle_leaf.sequence;
            if got_seq != expected_seq {
                return Err(VerifyChainError::SequenceGapAt {
                    expected: expected_seq,
                    got: got_seq,
                });
            }
            let got_prev = receipt.body.merkle_leaf.prev_hash;
            if got_prev != expected_prev {
                return Err(VerifyChainError::BrokenAt {
                    sequence: got_seq,
                    expected: expected_prev,
                    got: got_prev,
                });
            }
            crypto::verify(receipt)
                .map_err(|_| VerifyChainError::SignatureInvalidAt { sequence: got_seq })?;
            expected_prev = receipt.body.merkle_leaf.leaf_hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::SigningKey;
    use uniclaw_receipt::{Action, Decision, Digest, MerkleLeaf, ReceiptBody, Signature};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pubkey(k: &SigningKey) -> PublicKey {
        PublicKey(k.verifying_key().to_bytes())
    }

    fn body_at(seq: u64, prev_hash: Digest, target: &str) -> ReceiptBody {
        let mut body = ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at: alloc::format!("2026-04-27T00:00:{seq:02}Z"),
            action: Action {
                kind: "http.fetch".into(),
                target: target.into(),
                input_hash: Digest([0u8; 32]),
            },
            decision: Decision::Allowed,
            constitution_rules: vec![],
            provenance: vec![],
            redactor_stack_hash: None,
            merkle_leaf: MerkleLeaf {
                sequence: seq,
                leaf_hash: Digest([0u8; 32]),
                prev_hash,
            },
        };
        // Compute a stable leaf_hash so the chain links cleanly. Real
        // kernels use compute_leaf_hash; for these tests any deterministic
        // function of the body suffices.
        let canonical = serde_json::to_vec(&body).expect("encode body");
        body.merkle_leaf.leaf_hash = Digest(*blake3::hash(&canonical).as_bytes());
        body
    }

    fn signed_at(k: &SigningKey, seq: u64, prev_hash: Digest, target: &str) -> Receipt {
        crypto::sign(body_at(seq, prev_hash, target), k)
    }

    #[test]
    fn empty_log_reports_correct_state() {
        let log = InMemoryReceiptLog::new(pubkey(&key()));
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.last().is_none());
        assert!(log.get_by_sequence(0).is_none());
        assert!(log.get_by_id(&Digest([0u8; 32])).is_none());
        log.verify_chain().unwrap();
    }

    #[test]
    fn append_in_order_works_and_chains() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let r0 = signed_at(&k, 0, Digest([0u8; 32]), "a");
        let leaf0 = r0.body.merkle_leaf.leaf_hash;
        log.append(r0.clone()).unwrap();
        let r1 = signed_at(&k, 1, leaf0, "b");
        log.append(r1.clone()).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log.last().unwrap().body.action.target, "b");
        log.verify_chain().unwrap();
    }

    #[test]
    fn out_of_order_rejected_without_modifying_log() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let r0 = signed_at(&k, 0, Digest([0u8; 32]), "a");
        log.append(r0).unwrap();
        // Skip seq 1; submit seq 2.
        let r2 = signed_at(&k, 2, Digest([0xAA; 32]), "c");
        let err = log.append(r2).unwrap_err();
        assert_eq!(
            err,
            AppendError::OutOfOrder {
                expected: 1,
                got: 2
            }
        );
        assert_eq!(log.len(), 1, "rejected append must not modify log");
    }

    #[test]
    fn chain_break_rejected() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let r0 = signed_at(&k, 0, Digest([0u8; 32]), "a");
        log.append(r0).unwrap();
        // Wrong prev_hash on seq 1.
        let r1_bad = signed_at(&k, 1, Digest([0xFF; 32]), "b");
        let err = log.append(r1_bad).unwrap_err();
        assert!(matches!(err, AppendError::ChainBroken { .. }));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let k_log = key();
        let k_other = SigningKey::from_bytes(&[9u8; 32]);
        let mut log = InMemoryReceiptLog::new(pubkey(&k_log));
        let foreign = signed_at(&k_other, 0, Digest([0u8; 32]), "x");
        let err = log.append(foreign).unwrap_err();
        assert!(matches!(err, AppendError::IssuerMismatch { .. }));
    }

    #[test]
    fn unsupported_version_rejected() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let mut r = signed_at(&k, 0, Digest([0u8; 32]), "a");
        r.version = u32::MAX;
        let err = log.append(r).unwrap_err();
        assert!(matches!(err, AppendError::UnsupportedVersion { .. }));
    }

    #[test]
    fn signature_invalid_rejected_after_other_checks_pass() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let mut r = signed_at(&k, 0, Digest([0u8; 32]), "a");
        // Tamper signature.
        r.signature = Signature([0xFF; 64]);
        let err = log.append(r).unwrap_err();
        assert_eq!(err, AppendError::SignatureInvalid);
    }

    #[test]
    fn lookup_by_sequence_and_by_id_works() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let r0 = signed_at(&k, 0, Digest([0u8; 32]), "a");
        let id0 = r0.content_id();
        let leaf0 = r0.body.merkle_leaf.leaf_hash;
        log.append(r0).unwrap();
        let r1 = signed_at(&k, 1, leaf0, "b");
        let id1 = r1.content_id();
        log.append(r1).unwrap();

        assert_eq!(log.get_by_sequence(0).unwrap().body.action.target, "a");
        assert_eq!(log.get_by_sequence(1).unwrap().body.action.target, "b");
        assert!(log.get_by_sequence(2).is_none());
        assert_eq!(log.get_by_id(&id0).unwrap().body.action.target, "a");
        assert_eq!(log.get_by_id(&id1).unwrap().body.action.target, "b");
        assert!(log.get_by_id(&Digest([0xAB; 32])).is_none());
    }

    #[test]
    fn verify_chain_catches_post_facto_tampering() {
        let k = key();
        let mut log = InMemoryReceiptLog::new(pubkey(&k));
        let r0 = signed_at(&k, 0, Digest([0u8; 32]), "a");
        let leaf0 = r0.body.merkle_leaf.leaf_hash;
        log.append(r0).unwrap();
        let r1 = signed_at(&k, 1, leaf0, "b");
        log.append(r1).unwrap();
        log.verify_chain().unwrap();

        // Mutate the second receipt's body in storage. This bypasses
        // append's checks — verify_chain catches it.
        log.receipts[1].body.action.target = "evil".into();
        let err = log.verify_chain().unwrap_err();
        assert!(matches!(err, VerifyChainError::SignatureInvalidAt { .. }));
    }
}
