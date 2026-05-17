//! Output sanitization for BoardProof tool outputs.
//!
//! Phase 3 step 18 (master plan §28). Tools return bytes that
//! might contain credential values — the OAuth token an API
//! echoed back, the bearer header a misbehaving service logged,
//! the `Set-Cookie: session=...` line a debug endpoint included.
//! Without sanitization, those bytes go into the receipt's
//! output, get hashed, and become part of the audit trail
//! forever.
//!
//! `boardproof-redact` runs operator-configured pattern matching
//! over tool-output bytes BEFORE the kernel hashes them, replacing
//! matches with `[REDACTED:<rule-id>]` placeholders. The output is
//! a [`RedactionResult`]: the redacted bytes plus a
//! [`boardproof_receipt::RedactionReport`] that the kernel records on
//! the receipt — including a stable [`RedactorStack::stack_hash`],
//! per-rule match counts, and the BLAKE3 of the redacted bytes
//! that becomes the receipt's `output_hash`.
//!
//! ## What's here
//!
//! - [`Redactor`] — the trait every backend implements.
//!   `Send + Sync`. One method: `redact(&self, bytes: &[u8])`.
//! - [`RedactionResult`] — the redactor's full output: bytes for
//!   the caller plus a [`boardproof_receipt::RedactionReport`] for
//!   the kernel.
//! - [`PatternRedactor`] — the v0 reference impl. Compiles a
//!   [`Vec<PatternRule>`] at construction; each rule is an
//!   identifier plus a [`regex::Regex`]. Default-rule helpers
//!   ship a corpus of common credential prefixes (GitHub PATs,
//!   OpenAI/Anthropic keys, Slack bot tokens, AWS access keys,
//!   JWTs, generic `Bearer …` headers).
//! - [`RedactorStack`] — composition. Apply each redactor in
//!   sequence; aggregate match counts. `stack_hash()` produces
//!   the canonical hash that lands in `ReceiptBody::redactor_stack_hash`.
//!
//! ## Trust model
//!
//! - Redaction runs **outside the kernel**. The kernel takes the
//!   resulting [`boardproof_receipt::RedactionReport`] as audit
//!   data and signs it. This keeps the kernel `no_std` and
//!   independent of `regex`.
//! - The original (un-redacted) bytes never touch the receipt
//!   chain. They exist transiently in the producer's memory and
//!   then go where the producer decides — typically dropped or
//!   used for the producer's own purpose. The receipt commits
//!   only to the redacted form.
//! - Operators choose what gets redacted. The default rule set
//!   is a defense-in-depth starting point; deployments are
//!   expected to extend it via [`PatternRedactor::with_rules`]
//!   and stack-compose.
//!
//! ## What this crate does *not* do (yet)
//!
//! - **No secret-value scanning.** v0 only matches *patterns*.
//!   A future step ties into `boardproof-secrets` to scan for the
//!   literal values of currently-registered secrets — risky
//!   because it requires the redactor to handle live secret
//!   material; defer until 18b.
//! - **No structural / JSON-path redaction.** Regex-only for
//!   v0; structural redaction would need deserialization and
//!   a path DSL. Future step.
//! - **No redaction-policy receipt.** The operator's chosen
//!   stack is committed to via `stack_hash`, but there's no
//!   `$kernel/policy/redactor` receipt class yet for "operator
//!   configured stack X at time T." Phase 6 governance.
//!
//! ## Adopt-don't-copy
//!
//! - **`IronClaw`'s `crates/ironclaw_safety/` redaction
//!   discipline** — the *philosophy* of "scan output for
//!   known secret patterns, redact, sign the result" is
//!   adopted. Their pattern corpus is a useful informational
//!   reference; our default rule set is a leaner v0 subset.
//!   No source borrowed.

#![forbid(unsafe_code)]

mod pattern;
mod redactor;
mod stack;

pub use pattern::{PatternRedactor, PatternRule, default_rules};
pub use redactor::{RedactionResult, Redactor};
pub use stack::RedactorStack;

// Re-export the audit-data types from `boardproof-receipt` so callers
// using the redactor have a single import path.
pub use boardproof_receipt::{RedactionReport, RuleMatch};
