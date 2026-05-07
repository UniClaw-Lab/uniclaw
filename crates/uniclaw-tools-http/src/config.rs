//! [`HttpFetchConfig`] — runtime knobs for `HttpFetchTool`.

use core::time::Duration;

/// Knobs that affect every fetch the tool does.
///
/// Defaults are conservative enough that a misconfigured deployment
/// can't accidentally make `HttpFetchTool` a useful SSRF probe or a
/// memory bomb:
///
/// - `timeout`: 30 s
/// - `max_response_bytes`: 10 MiB
/// - `user_agent`: `uniclaw-tools-http/<crate-version>`
/// - `allow_private_ips`: `false` (the SSRF defense in
///   [`crate::ssrf`] kicks in for literal-IP private addresses)
#[derive(Debug, Clone)]
pub struct HttpFetchConfig {
    /// Request-level timeout (connect + read).
    pub timeout: Duration,
    /// Maximum bytes the tool will read from a response body before
    /// returning [`uniclaw_tools::ToolError::Failed`].
    pub max_response_bytes: u64,
    /// User-Agent header sent with every request.
    pub user_agent: String,
    /// When `true`, literal-IP requests to private/loopback/link-local
    /// addresses are allowed. Useful for tests against a localhost
    /// mock; **must stay `false` in production**.
    pub allow_private_ips: bool,
}

impl Default for HttpFetchConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_response_bytes: 10 * 1024 * 1024,
            user_agent: format!("uniclaw-tools-http/{}", env!("CARGO_PKG_VERSION")),
            allow_private_ips: false,
        }
    }
}

impl HttpFetchConfig {
    /// Construct a config with `allow_private_ips = true` — for
    /// localhost-only tests where the mock server is on `127.0.0.1`.
    /// **Don't use in production.**
    #[must_use]
    pub fn for_test_localhost() -> Self {
        Self {
            allow_private_ips: true,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_safe() {
        let c = HttpFetchConfig::default();
        assert_eq!(c.timeout, Duration::from_secs(30));
        assert_eq!(c.max_response_bytes, 10 * 1024 * 1024);
        assert!(!c.allow_private_ips, "MUST default to refusing private IPs");
        assert!(c.user_agent.starts_with("uniclaw-tools-http/"));
    }

    #[test]
    fn test_localhost_config_only_flips_the_private_ip_flag() {
        let d = HttpFetchConfig::default();
        let t = HttpFetchConfig::for_test_localhost();
        assert!(t.allow_private_ips);
        assert_eq!(t.timeout, d.timeout);
        assert_eq!(t.max_response_bytes, d.max_response_bytes);
        assert_eq!(t.user_agent, d.user_agent);
    }
}
