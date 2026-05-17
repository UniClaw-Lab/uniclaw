// Compute the BLAKE3 content_id of a receipt body. The kernel's
// `Receipt::content_id` (in `crates/boardproof-receipt/src/lib.rs`)
// is BLAKE3 over the canonical body bytes; this function is the
// TS mirror.

import { blake3 } from "@noble/hashes/blake3";
import { canonicalizeBody } from "./canonical.js";
import { bytesToHex } from "./hex.js";
import type { ReceiptBody } from "./types.js";

export function computeContentIdBytes(body: ReceiptBody): Uint8Array {
  const canonical = canonicalizeBody(body);
  return blake3(canonical);
}

export function computeContentIdHex(body: ReceiptBody): string {
  return bytesToHex(computeContentIdBytes(body));
}
