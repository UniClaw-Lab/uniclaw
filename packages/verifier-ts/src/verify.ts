// Verify a Uniclaw receipt: recompute the canonical body bytes,
// recompute the content_id (BLAKE3), and check the Ed25519
// signature against the embedded issuer key.
//
// This is the trust property the wedge rests on — every step here
// runs locally; nothing is delegated to the host that served the
// receipt. See `crates/uniclaw-host/src/verify.html` for the
// browser sibling that does the same thing using
// `crypto.subtle.verify`. The TS package uses `@noble/curves`
// (audited, browser+Node, no native deps) for parity.

import { ed25519 } from "@noble/curves/ed25519";
import { canonicalizeBody } from "./canonical.js";
import { computeContentIdHex } from "./content-id.js";
import { hexToBytes } from "./hex.js";
import type { Receipt, VerifyResult } from "./types.js";

// Verify a parsed Receipt object.
//
// Caller note for v1 receipts: the legacy canonicalization path
// uses `JSON.stringify(body)`, which depends on JS object key
// order. If you `JSON.parse` the receipt JSON yourself and pass
// the result here, ES2015 preserves insertion order and the bytes
// still match. If you reconstruct the receipt object some other
// way (e.g. by mapping each field through your own type), you
// risk reordering keys; for that case, prefer
// `verifyReceiptJson` below which controls parsing internally.
export async function verifyReceipt(receipt: Receipt): Promise<VerifyResult> {
  const result: VerifyResult = {
    ok: false,
    contentIdHex: "",
    issuerHex: "",
    schemaVersion: 0,
    decision: "",
  };

  if (typeof receipt !== "object" || receipt === null) {
    return { ...result, error: "input is not a JSON object" };
  }
  if (typeof receipt.body !== "object" || receipt.body === null) {
    return { ...result, error: "receipt is missing a body" };
  }
  if (typeof receipt.issuer !== "string") {
    return { ...result, error: "issuer must be a hex string" };
  }
  if (typeof receipt.signature !== "string") {
    return { ...result, error: "signature must be a hex string" };
  }

  result.issuerHex = receipt.issuer;
  result.schemaVersion = receipt.body.schema_version ?? 0;
  result.decision = receipt.body.decision ?? "";
  // Step 19a: surface the operator-chosen key identifier when
  // the signer set one. Absent on pre-19a receipts.
  if (typeof receipt.body.key_id === "string") {
    result.keyId = receipt.body.key_id;
  }

  let issuerBytes: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    issuerBytes = hexToBytes(receipt.issuer);
    signatureBytes = hexToBytes(receipt.signature);
  } catch (e) {
    return { ...result, error: (e as Error).message };
  }
  if (issuerBytes.length !== 32) {
    return {
      ...result,
      error: `issuer must be 32 bytes (got ${issuerBytes.length})`,
    };
  }
  if (signatureBytes.length !== 64) {
    return {
      ...result,
      error: `signature must be 64 bytes (got ${signatureBytes.length})`,
    };
  }

  let canonicalBytes: Uint8Array;
  try {
    canonicalBytes = canonicalizeBody(receipt.body);
  } catch (e) {
    return { ...result, error: `canonicalize: ${(e as Error).message}` };
  }

  let contentIdHex: string;
  try {
    contentIdHex = computeContentIdHex(receipt.body);
  } catch (e) {
    return { ...result, error: `content_id: ${(e as Error).message}` };
  }
  result.contentIdHex = contentIdHex;

  let signatureOk: boolean;
  try {
    signatureOk = ed25519.verify(signatureBytes, canonicalBytes, issuerBytes);
  } catch (e) {
    return { ...result, error: `verify: ${(e as Error).message}` };
  }

  if (!signatureOk) {
    return {
      ...result,
      error: "signature did not verify under the embedded issuer key",
    };
  }

  return { ...result, ok: true };
}

// Parse + verify a raw receipt JSON string. Use this when you
// fetched the receipt from a URL (the typical case) — it preserves
// JSON-text key order through parsing, so v1 legacy canonicalization
// matches Rust's struct-declaration order without effort.
export async function verifyReceiptJson(json: string): Promise<VerifyResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    return {
      ok: false,
      contentIdHex: "",
      issuerHex: "",
      schemaVersion: 0,
      decision: "",
      error: `invalid JSON: ${(e as Error).message}`,
    };
  }
  return verifyReceipt(parsed as Receipt);
}

// Fetch a receipt URL (e.g. uniclaw-host's `/receipts/<hash>`) and
// verify it. Uses the global `fetch`; works on Node 20+, Deno,
// Bun, and browsers.
export async function verifyReceiptUrl(url: string): Promise<VerifyResult> {
  let response: Response;
  try {
    response = await fetch(url);
  } catch (e) {
    return {
      ok: false,
      contentIdHex: "",
      issuerHex: "",
      schemaVersion: 0,
      decision: "",
      error: `fetch: ${(e as Error).message}`,
    };
  }
  if (!response.ok) {
    return {
      ok: false,
      contentIdHex: "",
      issuerHex: "",
      schemaVersion: 0,
      decision: "",
      error: `fetch: HTTP ${response.status}`,
    };
  }
  const text = await response.text();
  return verifyReceiptJson(text);
}
