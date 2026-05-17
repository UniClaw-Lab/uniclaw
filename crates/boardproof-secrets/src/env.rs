//! [`EnvSecretBroker`] — reads secrets from process environment
//! variables.
//!
//! Convenient for development, CI, and small deployments where
//! secrets come from a `systemd` unit's `Environment=` directive
//! or a `docker run -e` flag. **Inherits the threat model of the
//! environment**:
//!
//! - The OS already has the unencrypted value before we ever see it;
//!   our drop-zeroing only covers our in-process copy.
//! - Child processes that inherit the env will see the same value.
//! - `/proc/<pid>/environ` is readable by `root` (and on some Linux
//!   configs by the same user). On Windows, the equivalent surface
//!   is `NtQueryInformationProcess`.
//!
//! Use this for tokens that aren't worth a real secret store. For
//! anything else, use a Vault/KMS-backed broker.
//!
//! ## Lookup convention
//!
//! `EnvSecretBroker` lets the caller specify a *prefix* applied to
//! every secret name. So if the prefix is `UNICLAW_SECRET_` and the
//! name is `github.token`, the env var read is
//! `UNICLAW_SECRET_GITHUB_TOKEN`:
//!
//! 1. The prefix is prepended verbatim.
//! 2. `.` and `-` in the name are replaced with `_`.
//! 3. The whole result is uppercased.
//!
//! This avoids accidentally reading any random env var by name (`PATH`,
//! `HOME`, etc. — names that don't start with the prefix won't ever
//! be read). The transform is documented so operators know exactly
//! how to set their env.
//!
//! Not available in `no_std` (env vars are a `std` concept).

use alloc::string::{String, ToString};

use crate::broker::{BrokerError, SecretBroker};
use crate::value::SecretValue;

/// Reads secrets from process environment variables under a
/// configurable prefix.
///
/// Construct via [`EnvSecretBroker::with_prefix`]. The prefix is
/// applied during every fetch (see crate-level docs for the
/// transform).
#[derive(Debug, Clone)]
pub struct EnvSecretBroker {
    prefix: String,
}

impl EnvSecretBroker {
    /// Construct an `EnvSecretBroker` that reads env vars under the
    /// given prefix. The prefix is **not** transformed; it's
    /// prepended verbatim to the transformed secret name.
    ///
    /// Example: `EnvSecretBroker::with_prefix("UNICLAW_SECRET_")`
    /// then `fetch("github.token")` reads
    /// `UNICLAW_SECRET_GITHUB_TOKEN`.
    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// The current prefix, for diagnostics.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The env var name [`SecretBroker::fetch`] would consult for a
    /// given secret reference. Exposed for tests + diagnostics; the
    /// fetch path uses it internally.
    #[must_use]
    pub fn env_var_name(&self, secret_name: &str) -> String {
        let mut out = String::with_capacity(self.prefix.len() + secret_name.len());
        out.push_str(&self.prefix);
        for ch in secret_name.chars() {
            match ch {
                '.' | '-' => out.push('_'),
                c if c.is_ascii_alphanumeric() => out.push(c.to_ascii_uppercase()),
                '_' => out.push('_'),
                // Drop other characters silently — they couldn't be
                // part of a portable env var name anyway. We could
                // alternatively reject; for v0, drop is more
                // forgiving and the environment lookup will simply
                // not match if the operator chose a weird name.
                _ => {}
            }
        }
        out
    }
}

impl SecretBroker for EnvSecretBroker {
    fn fetch(&self, name: &str) -> Result<SecretValue, BrokerError> {
        let var_name = self.env_var_name(name);
        match std::env::var(&var_name) {
            Ok(value) => Ok(SecretValue::new(value)),
            Err(std::env::VarError::NotPresent) => Err(BrokerError::NotFound {
                name: name.to_string(),
            }),
            Err(std::env::VarError::NotUnicode(_)) => Err(BrokerError::Backend(alloc::format!(
                "env var {var_name} is not valid UTF-8"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_name_transforms_dots_dashes_and_uppercases() {
        let b = EnvSecretBroker::with_prefix("UNICLAW_SECRET_");
        assert_eq!(
            b.env_var_name("github.token"),
            "UNICLAW_SECRET_GITHUB_TOKEN"
        );
        assert_eq!(
            b.env_var_name("aws-access-key"),
            "UNICLAW_SECRET_AWS_ACCESS_KEY"
        );
        assert_eq!(b.env_var_name("simple"), "UNICLAW_SECRET_SIMPLE");
    }

    #[test]
    fn env_var_name_preserves_underscores() {
        let b = EnvSecretBroker::with_prefix("X_");
        assert_eq!(b.env_var_name("a_b_c"), "X_A_B_C");
    }

    #[test]
    fn env_var_name_drops_unportable_characters() {
        let b = EnvSecretBroker::with_prefix("X_");
        assert_eq!(b.env_var_name("api/v1/key"), "X_APIV1KEY");
        assert_eq!(b.env_var_name("a:b@c"), "X_ABC");
    }

    #[test]
    fn empty_prefix_is_legal() {
        let b = EnvSecretBroker::with_prefix("");
        assert_eq!(b.env_var_name("X"), "X");
    }

    // `std::env::set_var` is `unsafe` since Rust 1.78 — and the
    // workspace forbids `unsafe_code`, so a "fetch returns the value
    // we just set" unit test would be unable to set up its own
    // fixture. Validating the read path against real env state lives
    // in the integration test in `boardproof-tools-http` (where the
    // tool is exercised end-to-end) and is run via a subprocess
    // launched with the env pre-set in cargo's test invocation.
    //
    // Here we cover only what's safely testable in this crate:
    //
    //   - the env-var-name transform is right (pure function)
    //   - fetch returns NotFound for a name we KNOW isn't set
    //   - construction + accessors don't panic

    #[test]
    fn fetch_returns_not_found_when_env_var_is_unset() {
        // Pick a prefix unique enough that no shell / CI env will
        // ever match it.
        let b = EnvSecretBroker::with_prefix("UNICLAW_NEVER_SET_PREFIX_THAT_NO_ONE_USES_");
        let err = b.fetch("nope").unwrap_err();
        match err {
            BrokerError::NotFound { name } => assert_eq!(name, "nope"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn prefix_accessor_returns_what_was_set() {
        let b = EnvSecretBroker::with_prefix("UNICLAW_X_");
        assert_eq!(b.prefix(), "UNICLAW_X_");
    }
}
