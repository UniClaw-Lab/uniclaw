//! JSON shapes for `HttpFetchTool`'s input and output.
//!
//! v0 supports GET only. The input is just a URL; the output carries
//! the HTTP status, headers as a list of `[name, value]` pairs (order
//! preserved, duplicates allowed — needed for `Set-Cookie` etc.), and
//! the response body as a base64-encoded string (so it round-trips
//! through JSON byte-for-byte regardless of UTF-8 validity).
//!
//! ## Why base64 for the body
//!
//! Response bodies aren't guaranteed UTF-8 (image, binary, archive,
//! …). JSON strings are UTF-8 — escaping arbitrary bytes inside a
//! JSON string is awkward and not byte-perfect. Base64 sidesteps
//! both: any byte sequence becomes printable, and decode is exact.
//!
//! Cost: ~33 % size inflation in the receipt's input/output
//! representation. Acceptable for a v0 tool whose users will
//! typically fetch small public-data responses.

use serde::{Deserialize, Serialize};

/// Tool input: just a URL for v0. Future fields (method, headers,
/// body) live behind `#[serde(default)]` so older receipts stay
/// parseable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpFetchInput {
    /// Absolute URL to GET. Must include scheme (`http://` or
    /// `https://`).
    pub url: String,
}

/// Tool output: HTTP status, response headers, body bytes (base64).
///
/// The body is base64-encoded so the JSON round-trips exact bytes;
/// callers decode on their side. The `Receipt::output_hash` is
/// computed over the **JSON envelope bytes**, not the raw body —
/// so a verifier that re-runs the tool with the same input gets a
/// deterministic match on the whole envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpFetchOutput {
    /// HTTP status code (200, 404, 500, …).
    pub status: u16,
    /// Response headers as ordered `[name, value]` pairs. Names are
    /// lower-cased (HTTP/1.1 §4.2 and HTTP/2 §8.1.2 say header field
    /// names are case-insensitive; we normalize to lowercase for
    /// stable comparisons).
    pub headers: Vec<(String, String)>,
    /// Response body, base64-encoded with the standard alphabet
    /// (RFC 4648 §4) and **no padding stripping** — `=` characters
    /// are preserved so a decoder that requires them works.
    pub body_b64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_round_trips_through_json() {
        let inp = HttpFetchInput {
            url: "https://example.com/".into(),
        };
        let s = serde_json::to_string(&inp).unwrap();
        let back: HttpFetchInput = serde_json::from_str(&s).unwrap();
        assert_eq!(inp, back);
    }

    #[test]
    fn output_round_trips_through_json() {
        let out = HttpFetchOutput {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/plain".into()),
                ("x-custom".into(), "value".into()),
            ],
            body_b64: "aGVsbG8=".into(),
        };
        let s = serde_json::to_string(&out).unwrap();
        let back: HttpFetchOutput = serde_json::from_str(&s).unwrap();
        assert_eq!(out, back);
    }

    #[test]
    fn output_preserves_duplicate_header_names() {
        // Set-Cookie can appear multiple times; the Vec preserves
        // order and duplicates.
        let out = HttpFetchOutput {
            status: 200,
            headers: vec![
                ("set-cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
            ],
            body_b64: String::new(),
        };
        let s = serde_json::to_string(&out).unwrap();
        let back: HttpFetchOutput = serde_json::from_str(&s).unwrap();
        assert_eq!(back.headers.len(), 2);
        assert_eq!(back.headers[0].0, "set-cookie");
        assert_eq!(back.headers[1].0, "set-cookie");
    }

    #[test]
    fn parses_minimal_input_json() {
        let s = r#"{"url":"https://example.com/"}"#;
        let inp: HttpFetchInput = serde_json::from_str(s).unwrap();
        assert_eq!(inp.url, "https://example.com/");
    }
}
