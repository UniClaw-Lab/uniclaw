// Receipt shape mirrors `crates/uniclaw-receipt/src/lib.rs`:
//   pub struct Receipt    { version, body, issuer, signature }
//   pub struct ReceiptBody { schema_version, issued_at, action,
//                            decision, constitution_rules, provenance,
//                            redactor_stack_hash, merkle_leaf }
//
// The TypeScript types here are *receive-only* — the package never
// constructs receipts, only verifies what a Uniclaw kernel produced.
// Fields are kept loose (no enum unions for `decision`, no `unknown`
// for `action.target`) so future schema additions don't reject in
// the type checker before they reach the canonicalizer.

export interface Receipt {
  version: number;
  body: ReceiptBody;
  issuer: string;     // 64 hex chars (32-byte Ed25519 public key)
  signature: string;  // 128 hex chars (64-byte Ed25519 signature)
}

export interface ReceiptBody {
  schema_version: number;
  issued_at: string;
  action: ReceiptAction;
  decision: string;
  constitution_rules: RuleRef[];
  provenance: ProvenanceEdge[];
  redactor_stack_hash: string | null;
  // Step 19a: optional operator-chosen identifier for the signing
  // key (e.g. `"prod-2026"`, `"hsm-3"`). Absent on pre-19a receipts
  // and on signers that don't set one. The bytes of the issuer
  // public key remain the trust anchor for signature verification;
  // `key_id` is audit-only metadata for correlating with an
  // external key directory entry.
  key_id?: string;
  merkle_leaf: MerkleLeaf;
  // Forward-compatible: future schema additions land here without
  // breaking older verifiers.
  [k: string]: unknown;
}

export interface ReceiptAction {
  kind: string;
  target: string;
  input_hash: string;  // 64 hex chars (32-byte BLAKE3)
  [k: string]: unknown;
}

export interface RuleRef {
  id: string;
  matched: boolean;
  [k: string]: unknown;
}

export interface ProvenanceEdge {
  from: string;
  to: string;
  kind: string;
  [k: string]: unknown;
}

export interface MerkleLeaf {
  sequence: number;
  leaf_hash: string;   // 64 hex chars
  prev_hash: string;   // 64 hex chars
  [k: string]: unknown;
}

// Result of verifying a receipt. `ok === true` iff the signature
// validates under the embedded issuer key over the canonical body
// bytes. `contentIdHex` is recomputed locally — it is *not* trusted
// from any URL or external source.
export interface VerifyResult {
  ok: boolean;
  contentIdHex: string;
  issuerHex: string;
  schemaVersion: number;
  decision: string;
  // Step 19a: surfaced when present in `body.key_id`. Auditors
  // use this to correlate with an external key directory entry
  // (rotation, revocation, expiry). `undefined` on pre-19a
  // receipts and on signers that don't set one.
  keyId?: string;
  // Populated when `ok === false` to explain the failure mode.
  error?: string;
}

// Lower-level value type accepted by the canonicalizer. Receipts
// flow through as parsed JSON objects, but the canonicalizer also
// accepts arbitrary subtrees so callers can canonicalize fragments
// for testing.
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };
