// Public API for `@boardproof/verifier`.
//
// The package surface is intentionally narrow: canonicalize a
// body, recompute the content_id, verify a receipt. Everything
// else is internal.
//
// See the README and `docs/steps/20a-typescript-verifier.md` in
// the parent repository for how this fits the wedge.

export { canonicalizeBody, canonicalizeJcs } from "./canonical.js";
export { computeContentIdBytes, computeContentIdHex } from "./content-id.js";
export { bytesToHex, hexToBytes } from "./hex.js";
export {
  verifyReceipt,
  verifyReceiptJson,
  verifyReceiptUrl,
} from "./verify.js";

export type {
  JsonValue,
  MerkleLeaf,
  ProvenanceEdge,
  Receipt,
  ReceiptAction,
  ReceiptBody,
  RuleRef,
  VerifyResult,
} from "./types.js";
