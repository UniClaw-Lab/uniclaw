// RFC 8785 JCS canonicalizer for BoardProof receipt bodies.
//
// This is the TypeScript port of `crates/boardproof-receipt/src/canonical.rs`.
// The browser verifier (`crates/boardproof-host/src/verify.html`) and
// the Node conformance smoke
// (`crates/boardproof-receipt/tests/vectors/conformance-smoke.mjs`)
// embed equivalent JS implementations; this package is the
// canonical TypeScript reference.
//
// Cross-language byte-identity is enforced by
// `tests/conformance.test.ts`, which loads the same fixture file
// (`canonical-v2.json`) the Rust snapshot test loads. If the
// fixture passes here AND in Rust, both implementations agree.
//
// Scope: handles the shape BoardProof receipts actually use — string
// keys, integer numbers only, ASCII-mostly strings. Floats throw
// rather than emit potentially wrong bytes (matches Rust behavior,
// since the schema has no float fields and a future addition must
// update both canonicalizers in lockstep).

import type { JsonValue, ReceiptBody } from "./types.js";

// Encode `body` to canonical bytes the kernel signed.
//
// Dispatches on `body.schema_version`:
//   - schema_version <= 1: use the legacy `JSON.stringify(body)`
//     path. ES2015 preserves insertion order, and a body re-parsed
//     from JSON-as-served-by-the-host keeps Rust's struct-declaration
//     order — so the bytes match.
//   - schema_version >= 2: use RFC 8785 JCS (lexicographic key
//     sort, normalized integers, standard string escapes).
export function canonicalizeBody(body: ReceiptBody): Uint8Array {
  const str =
    typeof body === "object" && body !== null && (body.schema_version ?? 0) >= 2
      ? canonicalizeJcs(body as unknown as JsonValue)
      : JSON.stringify(body);
  return new TextEncoder().encode(str);
}

// Canonicalize an arbitrary JSON value using RFC 8785 JCS rules.
// Exported for tests and for callers who want to canonicalize a
// fragment for debugging.
export function canonicalizeJcs(value: JsonValue): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(`JCS: expected integer, got float ${value}`);
    }
    return String(value);
  }
  if (typeof value === "string") {
    return canonicalizeJcsString(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeJcs).join(",") + "]";
  }
  if (typeof value === "object") {
    // Sort keys by UTF-16 code unit order. JS's default `sort()` on
    // strings does abstract relational comparison, which is the
    // UTF-16 code unit ordering JCS specifies.
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map((k) => {
          const v = (value as { [k: string]: JsonValue })[k];
          // `noUncheckedIndexedAccess` widens to `JsonValue | undefined`;
          // we just listed `k` from `Object.keys`, so it's defined.
          if (v === undefined) {
            throw new Error(`JCS: key disappeared during sort: ${k}`);
          }
          return canonicalizeJcsString(k) + ":" + canonicalizeJcs(v);
        })
        .join(",") +
      "}"
    );
  }
  throw new Error(`JCS: unsupported value type ${typeof value}`);
}

function canonicalizeJcsString(s: string): string {
  let out = '"';
  for (const c of s) {
    switch (c) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default: {
        const code = c.codePointAt(0);
        if (code === undefined) {
          throw new Error("JCS: empty code point");
        }
        if (code < 0x20) {
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += c;
        }
      }
    }
  }
  return out + '"';
}
