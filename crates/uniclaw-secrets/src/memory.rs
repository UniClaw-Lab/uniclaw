//! [`InMemorySecretBroker`] — `BTreeMap`-backed broker.
//!
//! Keys (secret names) are stored as plain `String`. Values
//! (`SecretValue`) carry the drop-zeroing guarantees from `value.rs`.
//!
//! Suitable for: tests, single-process deployments where the
//! operator already holds the secrets in a config file they trust.
//!
//! Not suitable for: multi-tenant deployments, anywhere ACL-by-caller
//! matters, anywhere the secret should not be in plaintext on the
//! same host as the agent. Use a real backend (Vault et al.) there.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;

use crate::broker::{BrokerError, SecretBroker};
use crate::value::SecretValue;

/// In-memory broker. Constructed empty; secrets are added with
/// [`InMemorySecretBroker::insert`]. Lookups are O(log n).
#[derive(Default)]
pub struct InMemorySecretBroker {
    secrets: BTreeMap<String, SecretValue>,
}

impl core::fmt::Debug for InMemorySecretBroker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Print only the count — never the names, never the values.
        // Names can themselves be sensitive ("customer_42_api_key");
        // even the count is borderline but seems safe enough.
        f.debug_struct("InMemorySecretBroker")
            .field("registered_count", &self.secrets.len())
            .finish()
    }
}

impl InMemorySecretBroker {
    /// Construct an empty broker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `value` under `name`. If a secret already exists
    /// with that name, the previous `SecretValue` is dropped (and
    /// its bytes zeroed) before the new one is stored.
    pub fn insert(&mut self, name: impl Into<String>, value: SecretValue) {
        // Note: `BTreeMap::insert` returns the previous value, which
        // we drop here. The Drop impl on `SecretValue` zeroes the
        // bytes. So the rotation is clean.
        let _previous = self.secrets.insert(name.into(), value);
    }

    /// Convenience: register a secret from a plain `String`. The
    /// string moves into a freshly-constructed `SecretValue`.
    /// **Don't pass a string literal** — it lives in the binary's
    /// `.rodata` section forever and can't be zeroed. Pass an owned
    /// `String` that the broker takes ownership of.
    pub fn insert_string(&mut self, name: impl Into<String>, secret: String) {
        self.insert(name.into(), SecretValue::new(secret));
    }

    /// Number of registered secrets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// True when no secrets are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl SecretBroker for InMemorySecretBroker {
    fn fetch(&self, name: &str) -> Result<SecretValue, BrokerError> {
        match self.secrets.get(name) {
            // We need to return an *owned* `SecretValue`. The
            // broker keeps its copy; the caller gets a fresh one.
            // This is a *deliberate* re-allocation: cloning a
            // SecretValue is forbidden (no Clone impl), so we
            // construct a new one from the exposed bytes. The
            // exposed bytes briefly exist as a `&str` — that's
            // unavoidable; the new SecretValue's Drop will zero
            // the freshly-allocated buffer when the caller is
            // done.
            Some(v) => Ok(SecretValue::new(v.expose().to_string())),
            None => Err(BrokerError::NotFound {
                name: name.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_broker_returns_not_found() {
        let b = InMemorySecretBroker::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        let err = b.fetch("any").expect_err("empty broker can't fetch");
        match err {
            BrokerError::NotFound { name } => assert_eq!(name, "any"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn insert_and_fetch_round_trips() {
        let mut b = InMemorySecretBroker::new();
        b.insert_string("github.token", "ghp_topsecret".to_string());
        assert_eq!(b.len(), 1);
        let s = b.fetch("github.token").unwrap();
        assert_eq!(s.expose(), "ghp_topsecret");
    }

    #[test]
    fn fetch_returns_a_fresh_owned_value_each_time() {
        // Two fetches of the same name return separate `SecretValue`s.
        // Both expose the same string, but they have independent
        // buffers; dropping one does not affect the other.
        let mut b = InMemorySecretBroker::new();
        b.insert_string("k", "v".to_string());
        let a = b.fetch("k").unwrap();
        let c = b.fetch("k").unwrap();
        assert_eq!(a.expose(), "v");
        assert_eq!(c.expose(), "v");
        // Dropping `a` does not invalidate `c`.
        drop(a);
        assert_eq!(c.expose(), "v");
    }

    #[test]
    fn insert_replaces_previous_value_and_drops_old_secret() {
        let mut b = InMemorySecretBroker::new();
        b.insert_string("k", "old".to_string());
        b.insert_string("k", "new".to_string());
        assert_eq!(b.len(), 1);
        assert_eq!(b.fetch("k").unwrap().expose(), "new");
    }

    #[test]
    fn unknown_name_returns_not_found_with_the_requested_name() {
        let mut b = InMemorySecretBroker::new();
        b.insert_string("a", "1".to_string());
        b.insert_string("b", "2".to_string());
        let err = b.fetch("c").unwrap_err();
        match err {
            BrokerError::NotFound { name } => assert_eq!(name, "c"),
            other => panic!("expected NotFound(c), got {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_print_names_or_values() {
        let mut b = InMemorySecretBroker::new();
        b.insert_string("github.token", "ghp_secret".to_string());
        b.insert_string("openai.key", "sk-secret".to_string());
        let s = alloc::format!("{b:?}");
        assert!(!s.contains("github.token"));
        assert!(!s.contains("openai.key"));
        assert!(!s.contains("ghp_secret"));
        assert!(!s.contains("sk-secret"));
        assert!(s.contains("registered_count"));
        assert!(s.contains('2'));
    }

    /// Compile-time check that `Send + Sync` flow through the trait
    /// object. This is what `Arc<dyn SecretBroker>` requires.
    #[test]
    fn broker_trait_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn SecretBroker>();
        assert_send_sync::<InMemorySecretBroker>();
    }
}
