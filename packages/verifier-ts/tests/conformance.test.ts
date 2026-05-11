// Cross-language conformance test. Loads
// `crates/uniclaw-receipt/tests/vectors/canonical-v2.json` — the
// SAME fixture the Rust snapshot test uses — and asserts that
// every vector's canonical bytes and BLAKE3 hash match the
// committed expected values.
//
// If this passes here AND in Rust, the two implementations agree
// byte-for-byte. If it fails, the canonicalizers have drifted and
// the browser verifier (which embeds an equivalent JS port) will
// fail in lockstep.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalizeJcs } from "../src/canonical.js";
import { computeContentIdHex } from "../src/content-id.js";
import { bytesToHex } from "../src/hex.js";
import type { ReceiptBody } from "../src/types.js";

interface ConformanceFixture {
  format: string;
  vectors: Array<{
    name: string;
    body: ReceiptBody;
    canonical_hex: string;
    blake3_hex: string;
  }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(
  here,
  "../../../crates/uniclaw-receipt/tests/vectors/canonical-v2.json",
);
const fixture = JSON.parse(
  readFileSync(fixturePath, "utf8"),
) as ConformanceFixture;

describe("canonical-v2.json cross-language conformance", () => {
  it("loads the expected fixture format", () => {
    expect(fixture.format).toBe("uniclaw-canonical-v2");
    expect(fixture.vectors.length).toBeGreaterThanOrEqual(5);
  });

  it.each(fixture.vectors.map((v) => [v.name, v]))(
    "vector %s — canonical bytes match",
    (_name, v) => {
      const str = canonicalizeJcs(v.body as never);
      const bytes = new TextEncoder().encode(str);
      expect(bytesToHex(bytes)).toBe(v.canonical_hex);
    },
  );

  it.each(fixture.vectors.map((v) => [v.name, v]))(
    "vector %s — BLAKE3 content_id matches",
    (_name, v) => {
      expect(computeContentIdHex(v.body)).toBe(v.blake3_hex);
    },
  );
});
