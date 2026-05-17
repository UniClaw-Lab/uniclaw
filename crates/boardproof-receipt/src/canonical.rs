//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! JCS produces byte-identical encodings of the same logical JSON
//! across implementations and languages. Two verifiers — one in Rust,
//! one in TypeScript, one in Go — that both run a JCS encoder over
//! the same `serde_json::Value` MUST emit the same bytes. That's
//! what makes "verify a BoardProof receipt with a 200-LOC binary in
//! any language" actually work.
//!
//! ## What JCS guarantees (and we implement)
//!
//! - **Object keys sorted by UTF-16 code unit order.** RFC 8785
//!   §3.2.3. For ASCII-only keys (which every key in our schema is)
//!   this matches byte order; for non-ASCII keys we use the actual
//!   UTF-16 sort below.
//! - **Number formatting per ECMA-262 §7.1.12.1.** Integers emit as
//!   their decimal representation with no leading zeros, no `+`
//!   sign, no exponent. Floats use the shortest round-trip
//!   representation. **Our schema has no floats** — every number is
//!   `u32`, `u64`, or `i64` — so the implementation panics on any
//!   non-integer Number. If a future field adds a float, this
//!   guards us against silently producing wrong bytes.
//! - **Strings emitted with the JCS escape rules** (RFC 8785 §3.2.2):
//!   `"` → `\"`, `\\` → `\\\\`, control chars (U+0000..U+001F) → `\uXXXX`,
//!   `\b` `\f` `\n` `\r` `\t` use their named escapes, everything else
//!   UTF-8 verbatim. The slash `/` is NOT escaped (some non-canonical
//!   encoders emit `\/`; JCS does not).
//! - **No whitespace.** No spaces, no newlines, no indentation. The
//!   encoded bytes are minimal.
//!
//! ## What we don't support (deliberately)
//!
//! - **Floats.** Panics. If a future schema field adds a float,
//!   this is a load-bearing assertion that someone has to think
//!   about float canonicalization before the format ships.
//! - **Custom serializers.** Input is a `serde_json::Value`. Caller
//!   produces it via `serde_json::to_value(&body)`. If the
//!   `Serialize` impl emits something weird (e.g. duplicate keys —
//!   not possible in `serde_json::Map` but the type-system-level
//!   guard exists for cousins), the resulting Value's invariants
//!   are what we encode.
//!
//! ## Adopt-don't-copy
//!
//! - **RFC 8785 (Cyberphone)** is the canonical reference. Algorithm
//!   is small enough we implement it directly here rather than pull
//!   `serde_jcs` (which depends on full `std`-mode `serde_json` and
//!   has its own canonicalization choices we'd want to verify rather
//!   than trust). ~100 LOC; the test vectors at the bottom check
//!   against fixtures derived from RFC 8785's published examples.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use serde::Serialize;
use serde_json::Value;

/// Canonicalize a `serde::Serialize` value to JCS bytes.
///
/// Two-step: serialize to `serde_json::Value`, then walk the Value
/// tree emitting canonical bytes.
///
/// # Errors
/// Returns `serde_json::Error` if the value cannot be serialized.
///
/// # Panics
/// Panics if a non-integer JSON number appears. Our schema doesn't
/// use floats; the panic is a load-bearing assertion against future
/// drift.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let mut out = Vec::with_capacity(256);
    write_canonical(&v, &mut out);
    Ok(out)
}

/// Canonicalize a `serde_json::Value` directly. Skips the
/// serialize step.
#[must_use]
pub fn to_vec_from_value(v: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out),
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            let mut first = true;
            for item in arr {
                if !first {
                    out.push(b',');
                }
                first = false;
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Collect keys, sort by UTF-16 code unit order.
            // serde_json::Map preserves insertion order; canonicalization
            // requires sorted output.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| compare_utf16(a, b));

            out.push(b'{');
            let mut first = true;
            for k in keys {
                if !first {
                    out.push(b',');
                }
                first = false;
                write_string(k, out);
                out.push(b':');
                write_canonical(&map[k], out);
            }
            out.push(b'}');
        }
    }
}

/// Compare two strings by UTF-16 code unit order. Required by
/// RFC 8785 §3.2.3 for object key sorting. For ASCII strings the
/// result is identical to byte comparison; for strings with
/// non-BMP characters (surrogate pairs) the UTF-16 ordering can
/// differ from UTF-8 byte ordering.
///
/// All keys in BoardProof's receipt schema are ASCII, but we
/// implement the full algorithm so future fields don't silently
/// break canonicalization.
fn compare_utf16(a: &str, b: &str) -> core::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return core::cmp::Ordering::Equal,
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(&y);
                }
            }
        }
    }
}

fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) {
    if let Some(i) = n.as_i64() {
        let mut s = String::with_capacity(20);
        let _ = write!(s, "{i}");
        out.extend_from_slice(s.as_bytes());
    } else if let Some(u) = n.as_u64() {
        let mut s = String::with_capacity(20);
        let _ = write!(s, "{u}");
        out.extend_from_slice(s.as_bytes());
    } else {
        // serde_json's Number can be f64. Our schema has no floats;
        // a float here means someone added a non-integer field
        // and didn't update this canonicalizer to handle JCS's
        // ECMA-262 minimal-form rules. Refuse rather than emit
        // wrong bytes.
        panic!(
            "JCS canonicalization requires integer numbers; got float {n}. \
             Update canonical.rs to handle floats per RFC 8785 §3.2.2.4 \
             (ECMA-262 §7.1.12.1) before adding float fields to the receipt schema."
        );
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                // Other control chars: \uXXXX (4 hex digits, lowercase).
                let mut hex = String::with_capacity(6);
                let _ = write!(hex, "\\u{:04x}", c as u32);
                out.extend_from_slice(hex.as_bytes());
            }
            c => {
                // Everything else passes through as UTF-8 verbatim.
                // Note: JCS does NOT escape `/` (some non-canonical
                // encoders do; we do not). JCS also does not escape
                // non-ASCII characters; it emits them as UTF-8 bytes.
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object_is_braces() {
        assert_eq!(to_vec_from_value(&json!({})), b"{}");
    }

    #[test]
    fn empty_array_is_brackets() {
        assert_eq!(to_vec_from_value(&json!([])), b"[]");
    }

    #[test]
    fn keys_sorted_lexicographically() {
        // serde_json::Map preserves insertion order. JCS requires
        // sorted output. The output below has `a` before `b` even
        // though we constructed in `b, a` order.
        let v = json!({"b": 1, "a": 2});
        assert_eq!(to_vec_from_value(&v), br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn nested_keys_sorted_at_each_level() {
        let v = json!({
            "outer": {
                "z": 1,
                "a": 2,
            },
            "alpha": "value",
        });
        assert_eq!(
            to_vec_from_value(&v),
            br#"{"alpha":"value","outer":{"a":2,"z":1}}"#,
        );
    }

    #[test]
    fn arrays_preserve_order() {
        // Array order is part of the data; JCS doesn't reorder.
        let v = json!(["c", "a", "b"]);
        assert_eq!(to_vec_from_value(&v), br#"["c","a","b"]"#);
    }

    #[test]
    fn integers_emit_as_decimal_no_signs_or_exponents() {
        assert_eq!(to_vec_from_value(&json!(0)), b"0");
        assert_eq!(to_vec_from_value(&json!(1)), b"1");
        assert_eq!(to_vec_from_value(&json!(-1)), b"-1");
        assert_eq!(to_vec_from_value(&json!(123_456_789i64)), b"123456789");
        assert_eq!(to_vec_from_value(&json!(u64::MAX)), b"18446744073709551615");
    }

    #[test]
    fn strings_use_named_escapes_for_short_controls() {
        assert_eq!(to_vec_from_value(&json!("\"")), br#""\"""#, "double quote");
        assert_eq!(to_vec_from_value(&json!("\\")), br#""\\""#, "backslash");
        assert_eq!(to_vec_from_value(&json!("\n")), br#""\n""#, "newline");
        assert_eq!(
            to_vec_from_value(&json!("\r")),
            br#""\r""#,
            "carriage return"
        );
        assert_eq!(to_vec_from_value(&json!("\t")), br#""\t""#, "tab");
        // \b and \f via raw escape.
        assert_eq!(
            to_vec_from_value(&json!("\u{0008}")),
            br#""\b""#,
            "backspace",
        );
        assert_eq!(
            to_vec_from_value(&json!("\u{000C}")),
            br#""\f""#,
            "form feed",
        );
    }

    #[test]
    fn other_control_chars_use_lowercase_unicode_escape() {
        assert_eq!(to_vec_from_value(&json!("\u{0001}")), b"\"\\u0001\"");
        assert_eq!(to_vec_from_value(&json!("\u{001F}")), b"\"\\u001f\"");
    }

    #[test]
    fn slash_is_not_escaped() {
        // RFC 8785: forward slash is NOT escaped (unlike some
        // non-canonical encoders).
        assert_eq!(to_vec_from_value(&json!("/")), br#""/""#);
    }

    #[test]
    fn non_ascii_passes_through_as_utf8() {
        // RFC 8785 §3.2.2: non-ASCII chars are NOT escaped.
        let v = json!("héllo");
        let bytes = to_vec_from_value(&v);
        // Output is `"héllo"` as raw UTF-8 bytes.
        assert_eq!(&bytes[..1], b"\"");
        assert_eq!(&bytes[bytes.len() - 1..], b"\"");
        let inner = &bytes[1..bytes.len() - 1];
        assert_eq!(core::str::from_utf8(inner).unwrap(), "héllo");
    }

    #[test]
    fn null_emits_null() {
        assert_eq!(to_vec_from_value(&json!(null)), b"null");
    }

    #[test]
    fn booleans() {
        assert_eq!(to_vec_from_value(&json!(true)), b"true");
        assert_eq!(to_vec_from_value(&json!(false)), b"false");
    }

    #[test]
    #[should_panic(expected = "JCS canonicalization requires integer")]
    fn floats_panic() {
        // Our schema has no floats; canonicalization panics rather
        // than silently emit wrong bytes. Future-proofs against
        // someone adding a float field.
        let _ = to_vec_from_value(&json!(1.5));
    }

    #[test]
    fn rfc8785_appendix_b_minimal_example() {
        // RFC 8785 Appendix B has a worked example; this is a
        // simplified version covering object key sort + integers.
        // Input:
        //   { "numbers": [333333333.33333329, 1E30, 4.50, ...], ... }
        // (we substitute integers because we don't support floats.)
        let v = json!({
            "numbers": [1, 2, 3],
            "literal-true": true,
            "literal-false": false,
            "string": "hello",
            "nested": {
                "z": 1,
                "a": 2,
            },
        });
        let canonical = to_vec_from_value(&v);
        let s = core::str::from_utf8(&canonical).unwrap();
        // Keys sorted: literal-false, literal-true, nested, numbers, string
        assert_eq!(
            s,
            r#"{"literal-false":false,"literal-true":true,"nested":{"a":2,"z":1},"numbers":[1,2,3],"string":"hello"}"#,
        );
    }

    #[test]
    fn deterministic_two_runs_produce_same_bytes() {
        // Sanity. Build the same Value twice from different
        // construction orders; confirm the canonical bytes are
        // identical.
        let a = json!({
            "z": 1,
            "y": 2,
            "x": 3,
        });
        let b = json!({
            "x": 3,
            "y": 2,
            "z": 1,
        });
        assert_eq!(to_vec_from_value(&a), to_vec_from_value(&b));
    }

    #[test]
    fn serializes_a_real_struct() {
        #[derive(serde::Serialize)]
        struct Foo {
            zoo: u32,
            apple: String,
        }
        let foo = Foo {
            zoo: 1,
            apple: "fruit".to_string(),
        };
        let bytes = to_vec(&foo).unwrap();
        // Keys sorted: apple, zoo (regardless of struct declaration).
        assert_eq!(bytes, br#"{"apple":"fruit","zoo":1}"#);
    }
}
