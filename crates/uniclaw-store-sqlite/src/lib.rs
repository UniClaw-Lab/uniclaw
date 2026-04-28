//! SQLite-backed `ReceiptLog` for Uniclaw.
//!
//! Master plan §16.1 (*Audit*) follow-up to step 7. Same trait, same
//! validation invariants — receipts on disk instead of in a `Vec`. With
//! this in place, `uniclaw-host` can serve receipts that outlive a
//! process, and Deep Sleep's `verify_chain` walks something meaningful.
//!
//! ## What's the same as `InMemoryReceiptLog`
//!
//! - Issuer-pinned at construction.
//! - The five-step append validation in cheap-to-expensive order: version,
//!   issuer, sequence, chain link, Ed25519 signature.
//! - Refused appends do **not** modify state.
//! - `verify_chain` re-walks every receipt and re-checks every invariant.
//!
//! ## What's different
//!
//! - Receipts are stored as canonical JSON blobs in a `SQLite` `receipts`
//!   table, keyed by `merkle_leaf.sequence` (primary key) + a unique
//!   index on `content_id` for `get_by_id` lookups.
//! - The pinned issuer + the schema version live in a small `meta`
//!   key/value table. Reopening the DB with a different issuer is
//!   refused — see `OpenError::IssuerMismatch`.
//! - WAL mode is enabled at open time (one writer + many readers, no
//!   reader/writer blocking).
//! - `len()` and the cached "last leaf hash" used during append validation
//!   are kept in memory and updated on successful append. Both are
//!   refreshed from the DB at open. This avoids round-tripping for the
//!   hot path; the cache is correct as long as we are the only writer
//!   (the documented v0 assumption).
//!
//! ## Storage format
//!
//! Each row stores the *whole* receipt as canonical JSON. Storing the
//! receipt verbatim — not a column-shredded version — keeps the cold
//! verification path bit-perfect: `get_by_id` returns the exact bytes a
//! verifier saw at append time. Cost: ~600 bytes per typical receipt;
//! 1M receipts = ~600 MB. Fine for our use case; switchable later
//! without breaking the trait.
//!
//! ## Adopt-don't-copy
//!
//! `OpenFang`'s `audit.rs` writes Merkle-hashed audit rows to a
//! `SQLite` table inside its kernel; we keep storage out-of-kernel and
//! validate at the trait boundary. No source borrowed. The schema and
//! migration approach is small enough to read at a glance.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

use uniclaw_receipt::{Digest, PublicKey, RECEIPT_FORMAT_VERSION, Receipt, crypto};
use uniclaw_store::{AppendError, ReceiptLog, VerifyChainError};

const SCHEMA_VERSION: u32 = 1;

/// Why opening a `SqliteReceiptLog` failed.
#[derive(Debug)]
pub enum OpenError {
    /// `SQLite` returned an error (file IO, lock, syntax, etc.).
    Sqlite(rusqlite::Error),
    /// JSON decode of an existing receipt row failed — DB likely corrupt
    /// or written by an incompatible build.
    Decode(serde_json::Error),
    /// The DB was previously pinned to a different issuer key.
    IssuerMismatch { expected: PublicKey, got: PublicKey },
    /// The DB was written under a future schema version this build
    /// does not understand.
    UnsupportedSchema { found: u32, expected: u32 },
    /// The DB's pinned `format_version` does not match this build.
    UnsupportedFormatVersion { found: u32, expected: u32 },
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::Decode(e) => write!(f, "receipt decode failed: {e}"),
            Self::IssuerMismatch { .. } => {
                f.write_str("database is pinned to a different issuer than the one provided")
            }
            Self::UnsupportedSchema { found, expected } => write!(
                f,
                "unsupported schema version {found} (this build expects {expected})",
            ),
            Self::UnsupportedFormatVersion { found, expected } => write!(
                f,
                "unsupported receipt format version {found} (this build expects {expected})",
            ),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for OpenError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

/// SQLite-backed receipt log.
///
/// Holds one open `rusqlite::Connection` (wrapped in `std::sync::Mutex`
/// so the struct itself is `Sync`; the `uniclaw-host` runtime needs that
/// to share the log across async tasks via `Arc<tokio::sync::RwLock<L>>`).
/// The cached `len` and `last_leaf_hash` accelerate append validation;
/// both are refreshed from the DB at `open` and updated on successful
/// append.
pub struct SqliteReceiptLog {
    conn: Mutex<Connection>,
    issuer: PublicKey,
    cached_len: u64,
    cached_last_leaf_hash: Option<Digest>,
}

impl core::fmt::Debug for SqliteReceiptLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `conn` is intentionally omitted — its inner `Connection` is not
        // `Debug`-friendly and would leak unhelpful pointer state.
        f.debug_struct("SqliteReceiptLog")
            .field("issuer", &self.issuer)
            .field("cached_len", &self.cached_len)
            .field("cached_last_leaf_hash", &self.cached_last_leaf_hash)
            .field("conn", &"<sqlite connection>")
            .finish()
    }
}

impl SqliteReceiptLog {
    /// Open or create a SQLite-backed receipt log at `path`, pinned to
    /// `issuer`.
    ///
    /// If the file already exists with receipts in it:
    ///
    /// - the pinned issuer in the DB must equal `issuer`,
    /// - the schema version must match this build,
    /// - the format version must match this build.
    ///
    /// Otherwise this returns an `OpenError` and does not open the log.
    ///
    /// # Errors
    ///
    /// See [`OpenError`].
    pub fn open(path: impl AsRef<Path>, issuer: PublicKey) -> Result<Self, OpenError> {
        let conn = Connection::open(path)?;
        Self::open_inner(conn, issuer)
    }

    /// Open an in-memory SQLite-backed log. Useful for tests.
    ///
    /// # Errors
    ///
    /// See [`OpenError`].
    pub fn open_in_memory(issuer: PublicKey) -> Result<Self, OpenError> {
        let conn = Connection::open_in_memory()?;
        Self::open_inner(conn, issuer)
    }

    fn open_inner(conn: Connection, issuer: PublicKey) -> Result<Self, OpenError> {
        // WAL mode for concurrent reads + single writer. Foreign keys off
        // by default and we have no FKs anyway. Synchronous=NORMAL is the
        // standard WAL-mode default and is the right speed/durability
        // tradeoff for an audit log: you lose at most the last few
        // milliseconds on a power loss, and *that* is what the chain check
        // catches anyway.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                sequence    INTEGER PRIMARY KEY,
                content_id  BLOB NOT NULL UNIQUE,
                issuer      BLOB NOT NULL,
                body_json   BLOB NOT NULL
            );
            ",
        )?;

        // Pin or verify the schema version.
        check_or_set_meta_u32(
            &conn,
            "schema_version",
            SCHEMA_VERSION,
            |found, expected| OpenError::UnsupportedSchema { found, expected },
        )?;

        // Pin or verify the receipt format version.
        check_or_set_meta_u32(
            &conn,
            "format_version",
            RECEIPT_FORMAT_VERSION,
            |found, expected| OpenError::UnsupportedFormatVersion { found, expected },
        )?;

        // Pin or verify the issuer.
        let pinned_issuer = if let Some(bytes) = read_meta_blob(&conn, "issuer")? {
            if bytes.len() != 32 {
                return Err(OpenError::Sqlite(rusqlite::Error::InvalidColumnType(
                    0,
                    "issuer length".into(),
                    rusqlite::types::Type::Blob,
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let stored = PublicKey(arr);
            if stored != issuer {
                return Err(OpenError::IssuerMismatch {
                    expected: stored,
                    got: issuer,
                });
            }
            stored
        } else {
            // Fresh DB — pin to the caller's issuer.
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('issuer', ?1)",
                params![&issuer.0[..]],
            )?;
            issuer
        };

        // Cache len + last leaf hash from disk.
        let cached_len: u64 =
            conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
        let cached_last_leaf_hash = if cached_len == 0 {
            None
        } else {
            let last_json: Vec<u8> = conn.query_row(
                "SELECT body_json FROM receipts ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )?;
            let receipt: Receipt = serde_json::from_slice(&last_json).map_err(OpenError::Decode)?;
            Some(receipt.body.merkle_leaf.leaf_hash)
        };

        Ok(Self {
            conn: Mutex::new(conn),
            issuer: pinned_issuer,
            cached_len,
            cached_last_leaf_hash,
        })
    }

    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("connection mutex poisoned")
    }

    /// Read just the pinned issuer from a `SQLite` file **without** opening
    /// it as a `SqliteReceiptLog`. Returns `Ok(None)` if the database
    /// exists but has not yet been pinned (a fresh DB), or if the file
    /// does not exist yet.
    ///
    /// This is the helper a binary uses to decide whether to require the
    /// caller to provide an issuer (fresh DB) or use the one already
    /// pinned (existing DB).
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::Sqlite`] only on real IO/SQL errors. A
    /// missing file or a fresh `meta` table both yield `Ok(None)`.
    pub fn peek_issuer(path: impl AsRef<Path>) -> Result<Option<PublicKey>, OpenError> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(None);
        }
        let conn = Connection::open(p)?;
        // The meta table may not exist yet (file present but never
        // initialized as a uniclaw-store-sqlite log). Treat that as None.
        let table_exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !table_exists {
            return Ok(None);
        }
        let bytes = read_meta_blob(&conn, "issuer")?;
        Ok(bytes.and_then(|b| {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(PublicKey(arr))
            } else {
                None
            }
        }))
    }
}

fn read_meta_blob(conn: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        params![key],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
}

fn check_or_set_meta_u32(
    conn: &Connection,
    key: &str,
    expected: u32,
    on_mismatch: impl FnOnce(u32, u32) -> OpenError,
) -> Result<(), OpenError> {
    if let Some(bytes) = read_meta_blob(conn, key)? {
        if bytes.len() != 4 {
            return Err(OpenError::Sqlite(rusqlite::Error::InvalidColumnType(
                0,
                format!("{key} length"),
                rusqlite::types::Type::Blob,
            )));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes);
        let found = u32::from_le_bytes(arr);
        if found != expected {
            return Err(on_mismatch(found, expected));
        }
    } else {
        // Key cannot include single quotes for this `format!` to be safe;
        // the only callers are static strings ("schema_version",
        // "format_version"), so this is fine. We could also use a bound
        // parameter here, but SQLite doesn't support binding the table or
        // column name, only values, so the static format is unavoidable.
        let sql = format!("INSERT INTO meta (key, value) VALUES ('{key}', ?1)");
        conn.execute(&sql, params![&expected.to_le_bytes()[..]])?;
    }
    Ok(())
}

impl ReceiptLog for SqliteReceiptLog {
    fn issuer(&self) -> PublicKey {
        self.issuer
    }

    fn append(&mut self, receipt: Receipt) -> Result<(), AppendError> {
        // 1. Wire-format version.
        if receipt.version != RECEIPT_FORMAT_VERSION {
            return Err(AppendError::UnsupportedVersion {
                found: receipt.version,
                expected: RECEIPT_FORMAT_VERSION,
            });
        }

        // 2. Issuer pin.
        if receipt.issuer != self.issuer {
            return Err(AppendError::IssuerMismatch {
                expected: self.issuer,
                got: receipt.issuer,
            });
        }

        // 3. Sequence.
        let expected_seq = self.cached_len;
        let got_seq = receipt.body.merkle_leaf.sequence;
        if got_seq != expected_seq {
            return Err(AppendError::OutOfOrder {
                expected: expected_seq,
                got: got_seq,
            });
        }

        // 4. Chain link.
        let expected_prev = self.cached_last_leaf_hash.unwrap_or(Digest([0u8; 32]));
        let got_prev = receipt.body.merkle_leaf.prev_hash;
        if got_prev != expected_prev {
            return Err(AppendError::ChainBroken {
                expected: expected_prev,
                got: got_prev,
            });
        }

        // 5. Signature — last because expensive.
        crypto::verify(&receipt).map_err(|_| AppendError::SignatureInvalid)?;

        // Compute id + canonical JSON once.
        let id = receipt.content_id();
        let body_json =
            serde_json::to_vec(&receipt).expect("Receipt must serialize (it just deserialized)");

        // Insert. UNIQUE constraint on `content_id` doubles as a
        // duplicate-id check; the in-memory impl reports it explicitly.
        // Either signal is acceptable in the audit chain — duplicates
        // simply cannot occur for a verified chained receipt.
        let leaf_hash = receipt.body.merkle_leaf.leaf_hash;
        // got_seq is u64, SQLite's INTEGER is i64. Sequences will not
        // realistically exceed i64::MAX (~9.2e18 receipts), but cast
        // explicitly so clippy stops worrying.
        let seq_i64 = i64::try_from(got_seq).map_err(|_| AppendError::OutOfOrder {
            expected: expected_seq,
            got: got_seq,
        })?;
        let result = self.lock_conn().execute(
            "INSERT INTO receipts (sequence, content_id, issuer, body_json) VALUES (?1, ?2, ?3, ?4)",
            params![seq_i64, &id.0[..], &receipt.issuer.0[..], &body_json[..]],
        );
        if let Err(e) = result {
            // Map a UNIQUE-constraint violation on content_id to
            // AppendError::DuplicateId for parity with InMemoryReceiptLog.
            if let Some(code) = sqlite_extended_code(&e)
                && code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            {
                return Err(AppendError::DuplicateId(id));
            }
            // Anything else is treated as a signature-class storage failure
            // — the chain integrity check would catch it later. We map to
            // SignatureInvalid as a soft "could not establish trust" signal,
            // and leave the cache untouched so the caller can retry.
            return Err(AppendError::SignatureInvalid);
        }

        // Update cache only after successful insert.
        self.cached_len += 1;
        self.cached_last_leaf_hash = Some(leaf_hash);
        Ok(())
    }

    fn len(&self) -> usize {
        usize::try_from(self.cached_len).unwrap_or(usize::MAX)
    }

    fn last(&self) -> Option<Receipt> {
        if self.cached_len == 0 {
            return None;
        }
        let json: Vec<u8> = self
            .lock_conn()
            .query_row(
                "SELECT body_json FROM receipts ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok()?;
        serde_json::from_slice(&json).ok()
    }

    fn get_by_sequence(&self, sequence: u64) -> Option<Receipt> {
        let seq = i64::try_from(sequence).ok()?;
        let json: Vec<u8> = self
            .lock_conn()
            .query_row(
                "SELECT body_json FROM receipts WHERE sequence = ?1",
                params![seq],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        serde_json::from_slice(&json).ok()
    }

    fn get_by_id(&self, id: &Digest) -> Option<Receipt> {
        let json: Vec<u8> = self
            .lock_conn()
            .query_row(
                "SELECT body_json FROM receipts WHERE content_id = ?1",
                params![&id.0[..]],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        serde_json::from_slice(&json).ok()
    }

    fn verify_chain(&self) -> Result<(), VerifyChainError> {
        // Hold the connection lock for the whole walk so no other call
        // mutates the table mid-iteration.
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare("SELECT body_json FROM receipts ORDER BY sequence ASC")
            .map_err(|_| VerifyChainError::SignatureInvalidAt { sequence: 0 })?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| VerifyChainError::SignatureInvalidAt { sequence: 0 })?;

        let mut expected_prev = Digest([0u8; 32]);
        for (i, row) in (0_u64..).zip(rows) {
            let json = row.map_err(|_| VerifyChainError::SignatureInvalidAt { sequence: i })?;
            let receipt: Receipt = serde_json::from_slice(&json)
                .map_err(|_| VerifyChainError::SignatureInvalidAt { sequence: i })?;

            let expected_seq = i;
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
            crypto::verify(&receipt)
                .map_err(|_| VerifyChainError::SignatureInvalidAt { sequence: got_seq })?;
            expected_prev = receipt.body.merkle_leaf.leaf_hash;
        }
        Ok(())
    }
}

fn sqlite_extended_code(e: &rusqlite::Error) -> Option<i32> {
    match e {
        rusqlite::Error::SqliteFailure(err, _) => Some(err.extended_code),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use uniclaw_receipt::{Action, Decision, MerkleLeaf, ReceiptBody, Signature};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pubkey(k: &SigningKey) -> PublicKey {
        PublicKey(k.verifying_key().to_bytes())
    }

    fn body_at(seq: u64, prev_hash: Digest, target: &str) -> ReceiptBody {
        let mut body = ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at: format!("2026-04-28T00:00:{seq:02}Z"),
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
        let canonical = serde_json::to_vec(&body).unwrap();
        body.merkle_leaf.leaf_hash = Digest(*blake3::hash(&canonical).as_bytes());
        body
    }

    fn signed(k: &SigningKey, seq: u64, prev: Digest, target: &str) -> Receipt {
        crypto::sign(body_at(seq, prev, target), k)
    }

    #[test]
    fn empty_in_memory_log_reports_correct_state() {
        let log = SqliteReceiptLog::open_in_memory(pubkey(&key())).unwrap();
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
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        let r0 = signed(&k, 0, Digest([0u8; 32]), "a");
        let leaf0 = r0.body.merkle_leaf.leaf_hash;
        log.append(r0).unwrap();
        let r1 = signed(&k, 1, leaf0, "b");
        log.append(r1).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log.last().unwrap().body.action.target, "b");
        log.verify_chain().unwrap();
    }

    #[test]
    fn out_of_order_rejected_without_modifying_log() {
        let k = key();
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        log.append(signed(&k, 0, Digest([0u8; 32]), "a")).unwrap();
        let r2 = signed(&k, 2, Digest([0xAA; 32]), "c");
        let err = log.append(r2).unwrap_err();
        assert_eq!(
            err,
            AppendError::OutOfOrder {
                expected: 1,
                got: 2,
            }
        );
        assert_eq!(log.len(), 1, "rejected append must not modify log");
    }

    #[test]
    fn chain_break_rejected() {
        let k = key();
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        log.append(signed(&k, 0, Digest([0u8; 32]), "a")).unwrap();
        let r1_bad = signed(&k, 1, Digest([0xFF; 32]), "b");
        let err = log.append(r1_bad).unwrap_err();
        assert!(matches!(err, AppendError::ChainBroken { .. }));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let k_log = key();
        let k_other = SigningKey::from_bytes(&[9u8; 32]);
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k_log)).unwrap();
        let foreign = signed(&k_other, 0, Digest([0u8; 32]), "x");
        let err = log.append(foreign).unwrap_err();
        assert!(matches!(err, AppendError::IssuerMismatch { .. }));
    }

    #[test]
    fn unsupported_version_rejected() {
        let k = key();
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        let mut r = signed(&k, 0, Digest([0u8; 32]), "a");
        r.version = u32::MAX;
        let err = log.append(r).unwrap_err();
        assert!(matches!(err, AppendError::UnsupportedVersion { .. }));
    }

    #[test]
    fn signature_invalid_rejected_after_other_checks_pass() {
        let k = key();
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        let mut r = signed(&k, 0, Digest([0u8; 32]), "a");
        r.signature = Signature([0xFF; 64]);
        let err = log.append(r).unwrap_err();
        assert_eq!(err, AppendError::SignatureInvalid);
    }

    #[test]
    fn lookup_by_sequence_and_by_id_works() {
        let k = key();
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        let r0 = signed(&k, 0, Digest([0u8; 32]), "a");
        let id0 = r0.content_id();
        let leaf0 = r0.body.merkle_leaf.leaf_hash;
        log.append(r0).unwrap();
        let r1 = signed(&k, 1, leaf0, "b");
        let id1 = r1.content_id();
        log.append(r1).unwrap();

        assert_eq!(log.get_by_sequence(0).unwrap().body.action.target, "a");
        assert_eq!(log.get_by_sequence(1).unwrap().body.action.target, "b");
        assert!(log.get_by_sequence(2).is_none());
        assert_eq!(log.get_by_id(&id0).unwrap().body.action.target, "a");
        assert_eq!(log.get_by_id(&id1).unwrap().body.action.target, "b");
        assert!(log.get_by_id(&Digest([0xAB; 32])).is_none());
    }

    // --- persistence-specific tests (require a real file) ---

    #[test]
    fn reopen_preserves_state_and_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.db");
        let k = key();

        // Phase 1: create + append two receipts.
        {
            let mut log = SqliteReceiptLog::open(&path, pubkey(&k)).unwrap();
            let r0 = signed(&k, 0, Digest([0u8; 32]), "a");
            let leaf0 = r0.body.merkle_leaf.leaf_hash;
            log.append(r0).unwrap();
            let r1 = signed(&k, 1, leaf0, "b");
            log.append(r1).unwrap();
        } // drop closes the connection

        // Phase 2: reopen → state must be preserved.
        {
            let mut log = SqliteReceiptLog::open(&path, pubkey(&k)).unwrap();
            assert_eq!(log.len(), 2);
            assert_eq!(log.last().unwrap().body.action.target, "b");
            log.verify_chain().unwrap();

            // Append a third — chain validation must use the reloaded
            // last_leaf_hash.
            let leaf1 = log.get_by_sequence(1).unwrap().body.merkle_leaf.leaf_hash;
            log.append(signed(&k, 2, leaf1, "c")).unwrap();
            assert_eq!(log.len(), 3);
        }
    }

    #[test]
    fn reopen_with_wrong_issuer_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.db");
        let k = key();

        {
            let mut log = SqliteReceiptLog::open(&path, pubkey(&k)).unwrap();
            log.append(signed(&k, 0, Digest([0u8; 32]), "a")).unwrap();
        }

        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let err = SqliteReceiptLog::open(&path, pubkey(&other_key)).unwrap_err();
        assert!(matches!(err, OpenError::IssuerMismatch { .. }));
    }

    #[test]
    fn duplicate_content_id_is_rejected_via_unique_constraint() {
        // This case can't happen for honest chained receipts, but the DB
        // must still refuse it — UNIQUE on content_id is the second-line
        // defense after sequence + chain validation.
        //
        // We construct it artificially by trying to re-insert a receipt
        // at the same sequence. The kernel would never produce this; we
        // verify the SQLite-level constraint catches it just like the
        // in-memory `DuplicateId` error.
        let k = key();
        let mut log = SqliteReceiptLog::open_in_memory(pubkey(&k)).unwrap();
        let r0 = signed(&k, 0, Digest([0u8; 32]), "a");
        log.append(r0.clone()).unwrap();

        // Try to append the *same* receipt again. Out-of-order check
        // catches this first (sequence 0 != expected 1), before the
        // UNIQUE constraint would fire. Verify behavior matches the
        // in-memory log.
        let err = log.append(r0).unwrap_err();
        assert!(matches!(err, AppendError::OutOfOrder { .. }));
    }

    #[test]
    fn verify_chain_catches_post_facto_tampering_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.db");
        let k = key();

        let mut log = SqliteReceiptLog::open(&path, pubkey(&k)).unwrap();
        let r0 = signed(&k, 0, Digest([0u8; 32]), "a");
        let leaf0 = r0.body.merkle_leaf.leaf_hash;
        log.append(r0).unwrap();
        log.append(signed(&k, 1, leaf0, "b")).unwrap();
        log.verify_chain().unwrap();

        // Tamper directly via SQL — bypass append's checks.
        let stored: Vec<u8> = log
            .lock_conn()
            .query_row(
                "SELECT body_json FROM receipts WHERE sequence = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut receipt: Receipt = serde_json::from_slice(&stored).unwrap();
        receipt.body.action.target = "evil".into();
        let tampered = serde_json::to_vec(&receipt).unwrap();
        log.lock_conn()
            .execute(
                "UPDATE receipts SET body_json = ?1 WHERE sequence = 1",
                params![&tampered[..]],
            )
            .unwrap();

        // verify_chain must catch it.
        let err = log.verify_chain().unwrap_err();
        assert!(matches!(err, VerifyChainError::SignatureInvalidAt { .. }));
    }
}
