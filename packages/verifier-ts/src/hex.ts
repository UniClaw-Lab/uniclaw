// Hex helpers. Kept tiny and dependency-free so the package
// surface stays auditable.

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new TypeError("hex must be a string");
  }
  if (hex.length % 2 !== 0) {
    throw new Error("hex must have even length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex character at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    // `bytes[i]` is `number | undefined` under noUncheckedIndexedAccess;
    // we just bounded `i` against `.length` so it's defined.
    const b = bytes[i];
    if (b === undefined) {
      throw new Error("bytesToHex: out-of-range index (should be unreachable)");
    }
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}
