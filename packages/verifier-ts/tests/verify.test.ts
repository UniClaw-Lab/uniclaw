// Sign+verify roundtrip tests. The package can't construct
// receipts (it's a verifier, not a kernel), but we can synthesize
// signed receipts inside the test using `@noble/curves` to prove
// the verify path is consistent with the canonicalize path —
// i.e. anything that signs a JCS-canonicalized body with a known
// key will verify under that key, and anything that doesn't will
// be rejected.
//
// Cross-implementation Ed25519 conformance is guaranteed by the
// algorithm spec (RFC 8032); both `@noble/curves` and the Rust
// `ed25519-dalek` produce/consume identical bytes.

import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import { canonicalizeBody } from "../src/canonical.js";
import { computeContentIdHex } from "../src/content-id.js";
import { bytesToHex, hexToBytes } from "../src/hex.js";
import {
  verifyReceipt,
  verifyReceiptJson,
} from "../src/verify.js";
import type { Receipt, ReceiptBody } from "../src/types.js";

// Same deterministic seed the demo binary uses
// (`crates/boardproof-host/examples/end-to-end-demo.rs`).
const DEMO_SEED = new Uint8Array(32).fill(42);

function sampleBody(seq = 0): ReceiptBody {
  return {
    schema_version: 2,
    issued_at: "2026-05-09T12:00:00Z",
    action: {
      kind: "http.fetch",
      target: "https://example.com/",
      input_hash: "00".repeat(32),
    },
    decision: "allowed",
    constitution_rules: [],
    provenance: [],
    redactor_stack_hash: null,
    merkle_leaf: {
      sequence: seq,
      leaf_hash: "01".repeat(32),
      prev_hash: "00".repeat(32),
    },
  };
}

function signReceipt(body: ReceiptBody, seed: Uint8Array): Receipt {
  const publicKey = ed25519.getPublicKey(seed);
  const canonical = canonicalizeBody(body);
  const signature = ed25519.sign(canonical, seed);
  return {
    version: 1,
    body,
    issuer: bytesToHex(publicKey),
    signature: bytesToHex(signature),
  };
}

describe("verifyReceipt — happy path", () => {
  it("accepts a freshly signed receipt", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const result = await verifyReceipt(r);
    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.schemaVersion).toBe(2);
    expect(result.decision).toBe("allowed");
    expect(result.contentIdHex).toBe(computeContentIdHex(r.body));
    expect(result.issuerHex).toBe(r.issuer);
  });

  it("verifies multiple sequence numbers with stable issuer", async () => {
    for (let seq = 0; seq < 3; seq++) {
      const r = signReceipt(sampleBody(seq), DEMO_SEED);
      const result = await verifyReceipt(r);
      expect(result.ok, `sequence ${seq}`).toBe(true);
    }
  });
});

describe("verifyReceipt — tamper detection", () => {
  it("rejects body mutation (single field)", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const tampered: Receipt = {
      ...r,
      body: { ...r.body, decision: "denied" },
    };
    const result = await verifyReceipt(tampered);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/did not verify/);
  });

  it("rejects sequence-number swap inside merkle_leaf", async () => {
    const r = signReceipt(sampleBody(7), DEMO_SEED);
    const tampered: Receipt = {
      ...r,
      body: {
        ...r.body,
        merkle_leaf: { ...r.body.merkle_leaf, sequence: 8 },
      },
    };
    const result = await verifyReceipt(tampered);
    expect(result.ok).toBe(false);
  });

  it("rejects signature with one bit flipped", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const sigBytes = hexToBytes(r.signature);
    const flipped = sigBytes[0];
    if (flipped === undefined) throw new Error("empty signature");
    sigBytes[0] = flipped ^ 0x01;
    const result = await verifyReceipt({ ...r, signature: bytesToHex(sigBytes) });
    expect(result.ok).toBe(false);
  });

  it("rejects a signature signed by a different key", async () => {
    const otherSeed = new Uint8Array(32).fill(7);
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const wrongPub = bytesToHex(ed25519.getPublicKey(otherSeed));
    const result = await verifyReceipt({ ...r, issuer: wrongPub });
    expect(result.ok).toBe(false);
  });
});

describe("verifyReceipt — input validation", () => {
  it("rejects non-object input", async () => {
    const result = await verifyReceipt(null as unknown as Receipt);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not a JSON object/);
  });

  it("rejects missing body", async () => {
    const result = await verifyReceipt({
      version: 1,
      issuer: "00".repeat(32),
      signature: "00".repeat(64),
    } as unknown as Receipt);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/missing a body/);
  });

  it("rejects malformed issuer hex", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const result = await verifyReceipt({ ...r, issuer: "zz" });
    expect(result.ok).toBe(false);
  });

  it("rejects wrong-length issuer", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const result = await verifyReceipt({ ...r, issuer: "00".repeat(16) });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/32 bytes/);
  });

  it("rejects wrong-length signature", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const result = await verifyReceipt({ ...r, signature: "00".repeat(32) });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/64 bytes/);
  });
});

describe("verifyReceiptJson", () => {
  it("parses + verifies a JSON string", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const json = JSON.stringify(r);
    const result = await verifyReceiptJson(json);
    expect(result.ok).toBe(true);
  });

  it("reports a parse error on invalid JSON", async () => {
    const result = await verifyReceiptJson("not json");
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/invalid JSON/);
  });
});

describe("verifyReceipt — key_id (step 19a)", () => {
  it("surfaces body.key_id in VerifyResult.keyId when present", async () => {
    const body: ReceiptBody = {
      ...sampleBody(),
      key_id: "prod-2026",
    };
    const r = signReceipt(body, DEMO_SEED);
    const result = await verifyReceipt(r);
    expect(result.ok).toBe(true);
    expect(result.keyId).toBe("prod-2026");
  });

  it("leaves VerifyResult.keyId undefined when absent", async () => {
    const r = signReceipt(sampleBody(), DEMO_SEED);
    const result = await verifyReceipt(r);
    expect(result.ok).toBe(true);
    expect(result.keyId).toBeUndefined();
  });

  it("treats two receipts with different key_id as different canonical bytes", async () => {
    // The same logical action with a different key_id must produce
    // a different content_id (since key_id is part of the signed
    // body). Defense-in-depth confirmation that the field is in
    // the canonical surface.
    const body_a: ReceiptBody = { ...sampleBody(), key_id: "prod-2026" };
    const body_b: ReceiptBody = { ...sampleBody(), key_id: "hsm-3" };
    const ra = signReceipt(body_a, DEMO_SEED);
    const rb = signReceipt(body_b, DEMO_SEED);
    const va = await verifyReceipt(ra);
    const vb = await verifyReceipt(rb);
    expect(va.ok).toBe(true);
    expect(vb.ok).toBe(true);
    expect(va.contentIdHex).not.toBe(vb.contentIdHex);
  });

  it("tampering with key_id breaks the signature", async () => {
    const body: ReceiptBody = { ...sampleBody(), key_id: "prod-2026" };
    const r = signReceipt(body, DEMO_SEED);
    // Mutate key_id post-sign — the signature was over the
    // original bytes; this must fail to verify.
    const tampered = {
      ...r,
      body: { ...r.body, key_id: "rogue-key" },
    };
    const result = await verifyReceipt(tampered);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/did not verify/);
  });
});
