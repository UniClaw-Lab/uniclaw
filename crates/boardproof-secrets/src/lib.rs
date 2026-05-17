//! Secret broker for BoardProof.
//!
//! This crate ships **the trait surface and one or two simple
//! backends**, not a production secret store. Real backends (Vault,
//! AWS Secrets Manager, GCP Secret Manager, 1Password Connect) plug
//! in by implementing [`SecretBroker`] — they live in their own
//! crates that depend on this one.
//!
//! ## What's here
//!
//! - [`SecretValue`] — opaque, drop-zeroing wrapper around a UTF-8
//!   secret string. **No `Debug`, no `Display`, no `Serialize`, no
//!   `Clone`.** The only way to read the inner string is
//!   [`SecretValue::expose`], which is named to make every read site
//!   easy to grep for during code review.
//! - [`SecretBroker`] — the trait every backend implements. One
//!   method: `fetch(name) -> Result<SecretValue, BrokerError>`.
//! - [`BrokerError`] — typed enum (`NotFound`, `AccessDenied`, `Backend`).
//! - [`InMemorySecretBroker`] — `BTreeMap`-backed broker. Suitable for
//!   tests and small static deployments where secrets come from a
//!   config file the operator already trusts.
//! - [`EnvSecretBroker`] — reads from environment variables by name.
//!   Convenient but inherits the env's own threat model (the OS has
//!   the unencrypted value before we ever see it; child processes
//!   may inherit; etc.).
//!
//! ## Trust model
//!
//! Tools that need a secret declare them by **reference name**
//! (e.g. `"github.token"`), not by value. The broker is the only
//! component that ever holds the raw string. The model never sees
//! the value: tools fetch the secret at execution time and inject
//! it into the appropriate place (HTTP header, command-line argument,
//! env var for a subprocess) without exposing it to the agent's
//! prompt or output.
//!
//! Audit receipts record **that** a secret was used, **never the
//! value**. They record the *reference name* so an auditor can
//! correlate with the manifest, but the value stays out of the
//! audit chain by construction (`SecretValue` has no `Serialize`).
//!
//! ## `SecretValue`'s defenses
//!
//! - **Drop-zeroing** via the `zeroize` crate. The compiler is not
//!   allowed to optimize the zero-fill away (a plain loop assigning
//!   `*b = 0` would be a candidate for elimination since the buffer
//!   is about to be freed; `Zeroize::zeroize` uses a barrier).
//! - **No `Debug`** — accidental `dbg!(secret)` cannot leak the
//!   value to a log file.
//! - **No `Display`** — accidental `println!("{}", secret)` cannot
//!   leak the value to stdout.
//! - **No `Serialize`** — `serde_json::to_value(secret)` would not
//!   compile. Means receipts cannot accidentally embed the value.
//! - **No `Clone`** — exposing the value to a second owner would
//!   double the surface area for accidental retention. Tools that
//!   need a secret in two places re-fetch it from the broker.
//!
//! ## Adopt-don't-copy
//!
//! - **`IronClaw`'s execution-time credential injection + fail-closed
//!   on missing required credentials** — adopted at the broker trait
//!   surface. Tools call `broker.fetch(name)?` immediately before
//!   the I/O that needs the secret; a missing or denied secret
//!   surfaces as `ToolError::Failed` (not silently ignored).
//! - **`zeroize` crate** — standard Rust ecosystem dependency for
//!   constant-time zero-fill. We pull it as a dep; we don't borrow
//!   source.
//!
//! Cited in the file headers below where each pattern is applied.
//! No source borrowed from any reference claw.

#![forbid(unsafe_code)]

// `std` is implicit; we keep `extern crate alloc` so the
// `alloc::collections::BTreeMap` paths in `memory.rs` resolve cleanly
// (and so this crate stays one `no_std` retrofit away if a future
// embedded consumer needs `SecretValue` + `InMemorySecretBroker`
// without the env-backed path).
extern crate alloc;

mod broker;
mod env;
mod memory;
mod value;

pub use broker::{BrokerError, SecretBroker};
pub use env::EnvSecretBroker;
pub use memory::InMemorySecretBroker;
pub use value::SecretValue;
