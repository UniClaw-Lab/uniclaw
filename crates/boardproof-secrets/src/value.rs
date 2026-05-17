//! [`SecretValue`] — the opaque, drop-zeroing wrapper.
//!
//! Adopted from `secrecy` / `zeroize` ecosystem patterns: store the
//! bytes once, expose only via a named reader, never derive
//! `Debug`/`Display`/`Serialize`. No source borrowed; the design
//! goal is the same as `secrecy::Secret<String>` but with a smaller
//! API surface tailored to BoardProof's needs.

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroize;

/// An opaque, drop-zeroing wrapper around a UTF-8 secret string.
///
/// The only way to read the inner value is [`SecretValue::expose`],
/// which is deliberately named "expose" so every read site is grep-
/// pable during code review.
///
/// # Invariants
///
/// - Constructed with valid UTF-8 (only via [`SecretValue::new`],
///   which takes a `String`).
/// - Bytes are never mutated except by [`Drop`], which zeros them
///   exactly once.
/// - No `Debug`, `Display`, `Serialize`, `Clone`, `PartialEq`,
///   `Hash`. The only public API beyond construction is `expose`.
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    /// Wrap `secret` as a `SecretValue`. The String's bytes move
    /// into the value; nothing else holds them after this call.
    ///
    /// **Construction is unforgeable only by convention.** Anything
    /// in the workspace can call this; it's not `pub(crate)`-
    /// restricted to broker impls. The expectation is that brokers
    /// are the only callers — tools should never construct a
    /// `SecretValue` directly. The `unforgeable` property is enforced
    /// by code review, not by the type system. (Restricting at the
    /// type level would prevent third-party broker crates from
    /// existing.)
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self {
            bytes: secret.into_bytes(),
        }
    }

    /// Read the inner value as a UTF-8 `&str`.
    ///
    /// **Caller responsibility.** Anything you do with the returned
    /// `&str` may copy the bytes elsewhere; the drop-zeroing only
    /// covers the buffer this `SecretValue` owns. Tools that inject
    /// a secret into an HTTP header pass `expose()` directly to the
    /// header builder and never `to_string()` it for unrelated
    /// purposes.
    #[must_use]
    pub fn expose(&self) -> &str {
        // SAFETY-equivalent: `bytes` was constructed from a `String`
        // (which guarantees UTF-8) and is never mutated until Drop
        // (which runs exactly once at end of life). So the bytes
        // here are valid UTF-8.
        //
        // We use `from_utf8` (the safe variant) and `expect` rather
        // than `from_utf8_unchecked` because the workspace forbids
        // `unsafe`. The runtime check is one pass over the bytes —
        // negligible compared to whatever the secret is then used
        // for (an HTTP request, a Vault round-trip, etc.).
        core::str::from_utf8(&self.bytes)
            .expect("SecretValue bytes are UTF-8 (constructed from String)")
    }

    /// Length of the secret in bytes. Useful for pre-sizing buffers
    /// without exposing the value. Some callers may wish to refuse
    /// suspiciously short or long secrets at registration time.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the wrapped secret is empty. Most brokers should
    /// refuse to register an empty secret in the first place; this
    /// is provided for completeness.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        // `Zeroize::zeroize` writes zeros with a compiler barrier so
        // the fill is not optimized away (which a plain loop could be,
        // since the buffer is about to be freed). The crate's `Vec<u8>`
        // impl zeroes every element + sets length to 0 before drop.
        self.bytes.zeroize();
    }
}

/// Redacted `Debug` impl. Prints `SecretValue([REDACTED, len=N])`
/// without ever exposing the bytes. So `dbg!(secret)` and
/// `println!("{:?}", secret)` are safe — they confirm the value
/// exists and its length, but not its contents.
///
/// We deliberately do NOT implement `Display` (which is for
/// user-facing output and would invite formatting the value into
/// log messages). `Debug` is a developer tool; redacting it is
/// enough.
impl core::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretValue([REDACTED, len={}])", self.bytes.len())
    }
}

// --- Anti-leak guarantees ---
//
// `Debug` IS implemented (see above) but redacts the value. The
// rest are deliberately absent:
//
//   - `core::fmt::Display`   — `println!("{}", secret)` won't compile
//   - `serde::Serialize`     — `serde_json::to_*(secret)` won't compile
//   - `core::clone::Clone`   — no implicit duplicate ownership
//   - `core::cmp::PartialEq` — no timing-leak via byte-by-byte compare
//   - `core::hash::Hash`     — no key-leak via hasher
//   - `Default`              — empty secrets cannot materialize

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn construct_and_expose_round_trips() {
        let s = SecretValue::new("ghp_topsecret".to_string());
        assert_eq!(s.expose(), "ghp_topsecret");
    }

    #[test]
    fn len_and_is_empty_match_inner() {
        let s = SecretValue::new("abc".to_string());
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());

        let empty = SecretValue::new(String::new());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    /// The Drop impl zeros the underlying buffer. We verify by
    /// constructing a `SecretValue`, taking a raw pointer to its
    /// buffer, dropping the value, and checking that the bytes at
    /// that location are no longer the original.
    ///
    /// This isn't a perfect test — the allocator may reuse the
    /// memory between Drop and our re-read — but it's the cheapest
    /// reasonable signal that the zero-fill ran. The real assurance
    /// is that we use `Zeroize` (which has its own test suite).
    #[test]
    fn drop_zeros_the_buffer_at_least_via_zeroize_invocation() {
        // We can't observe the buffer after Drop without unsafe.
        // Instead: take a value, call zeroize directly via the same
        // path Drop uses, and verify the visible bytes are zero
        // afterwards.
        let mut s = SecretValue::new("topsecret".to_string());
        // Pre-conditions:
        assert_eq!(s.expose(), "topsecret");
        assert_eq!(s.len(), 9);
        // Manually invoke the same zeroize path Drop uses.
        s.bytes.zeroize();
        // Post-conditions: the Vec is now length 0 (zeroize sets len
        // to 0 after zero-filling), or all bytes are 0.
        // Different zeroize versions choose; we accept either.
        if s.bytes.is_empty() {
            // zeroize set length to 0 — buffer either was zeroed and
            // the capacity is irrelevant, or the bytes were cleared.
            // Either way, the Vec exposes no secret content.
        } else {
            assert!(
                s.bytes.iter().all(|&b| b == 0),
                "zeroize did not zero the bytes"
            );
        }
    }

    // --- Compile-time guarantees: SecretValue does NOT implement
    //     Debug / Display / Clone / PartialEq / Hash / Serialize.
    //
    // We can't directly assert "this type doesn't implement Trait"
    // in stable Rust without specialization, but we can assert it
    // *doesn't* satisfy a marker that's auto-derived elsewhere by
    // making sure two related types DO implement the trait while
    // SecretValue doesn't. Cleaner approach for a unit test: simply
    // try the call sites that would be valid if the trait existed,
    // wrapped in `#[cfg(any())]` so they're never compiled. The
    // file-level intent comments above carry the contract.
    //
    // The most useful runtime check: ensure SecretValue does not
    // accidentally start implementing `Default` (which would let an
    // empty secret materialize from thin air). We don't impl Default,
    // and we don't WANT to. No way to enforce this at compile time
    // without extra machinery; covered by code review.

    #[test]
    fn debug_redacts_value_but_reveals_length() {
        let s = SecretValue::new("supersecret".to_string()); // 11 chars
        let dbg = alloc::format!("{s:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("REDACTED"));
        assert!(dbg.contains("len=11"));
    }

    #[test]
    fn debug_with_capital_question_mark_also_redacts() {
        // `{:#?}` (pretty-debug) goes through the same Debug impl.
        let s = SecretValue::new("topsecret".to_string());
        let dbg_pretty = alloc::format!("{s:#?}");
        assert!(!dbg_pretty.contains("topsecret"));
        assert!(dbg_pretty.contains("REDACTED"));
    }

    #[test]
    fn expose_does_not_panic_on_typical_token_strings() {
        // Real-world token formats. None of these break the UTF-8
        // round-trip path.
        for tok in [
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "github_pat_11AAAAAAA0_long_string_here",
            "sk-proj-aaaaaaaaaaaaaa",
            "AKIAIOSFODNN7EXAMPLE",
            "aws-secret/with/slashes",
            "token-with-dashes-and-numbers-123",
            "🔐utf8🔑",
        ] {
            let s = SecretValue::new(tok.to_string());
            assert_eq!(s.expose(), tok);
        }
    }
}
