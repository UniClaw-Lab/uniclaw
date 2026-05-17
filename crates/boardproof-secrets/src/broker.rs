//! [`SecretBroker`] trait + [`BrokerError`] enum.
//!
//! Tools that need a secret call `broker.fetch(name)` immediately
//! before the I/O that uses it. A missing or denied secret surfaces
//! as `Err(BrokerError::*)`; tools wrap that into
//! `ToolError::Failed` (fail-closed semantics — adopted from
//! `IronClaw`).

use alloc::string::String;

use crate::value::SecretValue;

/// A backend that maps secret reference names to values.
///
/// Implementations are typically `Send + Sync` (a `SecretBroker` is
/// often shared via `Arc<dyn SecretBroker>` across tool calls). This
/// crate's two impls (`InMemorySecretBroker`, `EnvSecretBroker`)
/// satisfy that. Third-party impls are encouraged to as well.
///
/// # Why a trait?
///
/// Real deployments will plug Vault, AWS Secrets Manager, GCP Secret
/// Manager, 1Password Connect, Azure Key Vault, etc. behind this
/// surface. The trait is intentionally minimal — one method, one
/// error type — so writing a new backend is a small adapter.
pub trait SecretBroker: Send + Sync {
    /// Fetch the secret named `name`. Returns `Ok(SecretValue)` on
    /// success or `Err(BrokerError)` on failure.
    ///
    /// **Tools must fail-closed on `Err`.** The `IronClaw` lesson:
    /// silently treating a missing secret as "no auth" lets an
    /// agent quietly run unauthenticated against an API that needs
    /// auth, where the agent's caller may have assumed auth was in
    /// place. Always surface the error.
    ///
    /// # Errors
    ///
    /// See [`BrokerError`].
    fn fetch(&self, name: &str) -> Result<SecretValue, BrokerError>;
}

/// Why a `SecretBroker::fetch` call failed.
///
/// Carries an owned `String` for the offending name (rather than a
/// `&str` lifetime'd to the broker's storage) so the error can
/// flow through `?` chains without keeping the broker borrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// No secret with that name is registered.
    NotFound { name: String },
    /// The secret exists but the caller's identity / context isn't
    /// allowed to read it. Typically used by ACL-aware backends
    /// (Vault policies, KMS IAM, etc.). v0 brokers don't model
    /// caller identity — they always return `NotFound` if missing
    /// and `Ok` if present — but the variant is part of the trait
    /// surface so future ACL backends fit cleanly.
    AccessDenied { name: String },
    /// Backend-internal error (network failure, malformed
    /// configuration, etc.). The string is human-readable for
    /// diagnosis but should not be assumed machine-stable.
    Backend(String),
}

impl core::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BrokerError::NotFound { name } => write!(f, "secret not found: {name}"),
            BrokerError::AccessDenied { name } => write!(f, "access denied for secret: {name}"),
            BrokerError::Backend(msg) => write!(f, "secret broker backend error: {msg}"),
        }
    }
}

impl core::error::Error for BrokerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn broker_error_display_does_not_leak_a_value() {
        // The display includes the secret NAME but never the value
        // (the value isn't even part of the error type).
        let e = BrokerError::NotFound {
            name: "github.token".to_string(),
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("github.token"));
        assert!(s.contains("not found"));
    }

    #[test]
    fn broker_error_variants_are_distinguishable() {
        let nf = BrokerError::NotFound {
            name: "x".to_string(),
        };
        let ad = BrokerError::AccessDenied {
            name: "x".to_string(),
        };
        let be = BrokerError::Backend("vault unreachable".to_string());
        assert_ne!(nf, ad);
        assert_ne!(ad, be);
        assert_ne!(nf, be);
    }
}
