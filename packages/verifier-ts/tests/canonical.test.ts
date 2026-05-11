// Unit tests for the JCS canonicalizer. Mirrors the Rust unit
// tests in `crates/uniclaw-receipt/src/canonical.rs`.

import { describe, expect, it } from "vitest";
import { canonicalizeJcs } from "../src/canonical.js";
import type { JsonValue } from "../src/types.js";

describe("canonicalizeJcs primitives", () => {
  it("encodes null/true/false/integers", () => {
    expect(canonicalizeJcs(null)).toBe("null");
    expect(canonicalizeJcs(true)).toBe("true");
    expect(canonicalizeJcs(false)).toBe("false");
    expect(canonicalizeJcs(0)).toBe("0");
    expect(canonicalizeJcs(-1)).toBe("-1");
    expect(canonicalizeJcs(42)).toBe("42");
  });

  it("rejects floats", () => {
    expect(() => canonicalizeJcs(1.5)).toThrow(/integer/);
    expect(() => canonicalizeJcs(Number.NaN)).toThrow(/integer/);
    expect(() => canonicalizeJcs(Number.POSITIVE_INFINITY)).toThrow(/integer/);
  });
});

describe("canonicalizeJcs strings", () => {
  it("encodes plain ascii", () => {
    expect(canonicalizeJcs("hello")).toBe('"hello"');
  });

  it("escapes the standard JSON named chars", () => {
    expect(canonicalizeJcs('he said "hi"')).toBe('"he said \\"hi\\""');
    expect(canonicalizeJcs("a\\b")).toBe('"a\\\\b"');
    expect(canonicalizeJcs("a\nb")).toBe('"a\\nb"');
    expect(canonicalizeJcs("a\rb")).toBe('"a\\rb"');
    expect(canonicalizeJcs("a\tb")).toBe('"a\\tb"');
    expect(canonicalizeJcs("a\bb")).toBe('"a\\bb"');
    expect(canonicalizeJcs("a\fb")).toBe('"a\\fb"');
  });

  it("uses \\uXXXX for other controls below 0x20", () => {
    expect(canonicalizeJcs("")).toBe('"\\u0001"');
    expect(canonicalizeJcs("")).toBe('"\\u001f"');
  });

  it("does not escape forward slash", () => {
    expect(canonicalizeJcs("https://example.com/path")).toBe(
      '"https://example.com/path"',
    );
  });
});

describe("canonicalizeJcs containers", () => {
  it("encodes arrays in element order", () => {
    expect(canonicalizeJcs([1, 2, 3])).toBe("[1,2,3]");
    expect(canonicalizeJcs([])).toBe("[]");
    expect(canonicalizeJcs(["a", "b"])).toBe('["a","b"]');
  });

  it("sorts object keys lexicographically (UTF-16 code units)", () => {
    const obj: JsonValue = { b: 1, a: 2 };
    expect(canonicalizeJcs(obj)).toBe('{"a":2,"b":1}');
  });

  it("produces identical output regardless of construction order", () => {
    const a: JsonValue = { foo: 1, bar: 2 };
    const b: JsonValue = { bar: 2, foo: 1 };
    expect(canonicalizeJcs(a)).toBe(canonicalizeJcs(b));
  });

  it("recurses into nested structures", () => {
    const nested: JsonValue = { z: [1, { b: 2, a: 3 }], y: null };
    expect(canonicalizeJcs(nested)).toBe('{"y":null,"z":[1,{"a":3,"b":2}]}');
  });
});
