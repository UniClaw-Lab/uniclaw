// Cross-language conformance smoke test for v2 canonicalization.
//
// Loads `canonical-v2.json` and re-canonicalizes each `body` with
// the same JCS implementation embedded in
// `crates/boardproof-host/src/verify.html`. The bytes MUST match
// `canonical_hex` for every vector. If they don't, the JS
// canonicalizer has drifted from the Rust canonicalizer and the
// browser verifier will silently fail to verify v2 receipts.
//
// Run:
//   node crates/boardproof-receipt/tests/vectors/conformance-smoke.mjs
//
// Doesn't run in `cargo test` — it's a manual cross-language
// conformance check. Future work could wire it into CI via a
// `node` setup step.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = resolve(here, "canonical-v2.json");
const data = JSON.parse(readFileSync(fixture, "utf8"));

// --- inlined JCS canonicalizer (matches verify.html) ---

function canonicalizeJcs(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("JCS: expected integer, got float " + value);
    }
    return String(value);
  }
  if (typeof value === "string") return canonicalizeJcsString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeJcs).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map(k =>
      canonicalizeJcsString(k) + ":" + canonicalizeJcs(value[k])
    ).join(",") + "}";
  }
  throw new Error("JCS: unsupported type " + typeof value);
}

function canonicalizeJcsString(s) {
  let out = '"';
  for (const c of s) {
    const code = c.codePointAt(0);
    switch (c) {
      case '"':  out += '\\"';  break;
      case '\\': out += '\\\\'; break;
      case '\b': out += '\\b';  break;
      case '\f': out += '\\f';  break;
      case '\n': out += '\\n';  break;
      case '\r': out += '\\r';  break;
      case '\t': out += '\\t';  break;
      default:
        if (code < 0x20) {
          out += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          out += c;
        }
    }
  }
  return out + '"';
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// --- run ---

if (data.format !== "boardproof-canonical-v2") {
  console.error("unexpected fixture format:", data.format);
  process.exit(1);
}

let passed = 0, failed = 0;
for (const v of data.vectors) {
  const canonicalStr = canonicalizeJcs(v.body);
  const canonicalBytes = new TextEncoder().encode(canonicalStr);
  const ourHex = bytesToHex(canonicalBytes);
  if (ourHex === v.canonical_hex) {
    console.log(`  ok  ${v.name}`);
    passed += 1;
  } else {
    console.error(`  FAIL ${v.name}`);
    console.error(`    expected: ${v.canonical_hex.slice(0, 80)}...`);
    console.error(`    got:      ${ourHex.slice(0, 80)}...`);
    failed += 1;
  }
}

console.log(`\nresults: ${passed} passed, ${failed} failed (out of ${data.vectors.length})`);
process.exit(failed > 0 ? 1 : 0);
