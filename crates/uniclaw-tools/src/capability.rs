//! Typed capability declarations + the tiny glob matcher that powers
//! capability scoping.

use alloc::string::String;
use alloc::vec::Vec;

/// A glob pattern over a single string field (a hostname, a path, a
/// command line, an env var name, etc.).
///
/// Supported syntax:
///
/// | Pattern | Matches |
/// |---|---|
/// | `*` | any string (including empty) |
/// | `foo` | exactly `foo` |
/// | `foo*` | any string starting with `foo` |
/// | `*foo` | any string ending with `foo` |
/// | `*foo*` | any string containing `foo` |
/// | `foo*bar` | starts with `foo`, ends with `bar`, anything between |
/// | `foo*bar*baz` | `foo`, then `bar`, then `baz`, in that order |
///
/// Multiple consecutive `*`s collapse (`**` ≡ `*`). The matcher walks
/// the pattern in one pass with no backtracking — pathological inputs
/// can't blow it up.
///
/// Not supported: `?`, `[abc]`, `{a,b,c}`. If you need those, use a
/// real regex crate; this matcher is deliberately tiny so the
/// `no_std` / size-disciplined posture stays clean.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobPattern(pub String);

impl GlobPattern {
    /// Construct a glob pattern from any `Into<String>`.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// The raw pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `candidate` satisfies this glob.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        glob_match(&self.0, candidate)
    }
}

impl From<&str> for GlobPattern {
    fn from(s: &str) -> Self {
        Self(String::from(s))
    }
}

impl From<String> for GlobPattern {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Single-pass glob match: `pattern` against `candidate`.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    // No `*` in the pattern → exact match.
    if parts.len() == 1 {
        return pattern == candidate;
    }

    let last_idx = parts.len() - 1;
    let mut cursor: usize = 0;

    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            // `*foo...` → no anchor at start.
            if !part.is_empty() {
                if !candidate.starts_with(part) {
                    return false;
                }
                cursor = part.len();
            }
        } else if i == last_idx {
            // `...foo*` → no anchor at end; everything after the cursor
            // is wildcard. Otherwise the last part must end the
            // candidate (and not overlap with what we've already
            // consumed).
            if part.is_empty() {
                return true;
            }
            if cursor > candidate.len() {
                return false;
            }
            let remainder = &candidate[cursor..];
            return remainder.len() >= part.len() && remainder.ends_with(part);
        } else {
            // Middle part: must appear in `candidate[cursor..]` somewhere.
            if cursor > candidate.len() {
                return false;
            }
            let remainder = &candidate[cursor..];
            // `find("")` returns `Some(0)`; an empty middle part is a
            // no-op (consecutive `*`s collapse).
            match remainder.find(part) {
                Some(idx) => cursor = cursor + idx + part.len(),
                None => return false,
            }
        }
    }

    // Unreachable in practice — last-part branch always returns. Kept
    // for clarity and as a defensive default.
    true
}

/// What a tool can do, declared up front in its [`ToolManifest`].
///
/// Each variant carries a [`GlobPattern`] over the relevant string
/// (hostname, path, command, env var, etc.). The kernel and host
/// runtime can compare a *granted* capability (the one declared by the
/// tool's author / the constitution) against a *requested* capability
/// (the one a particular call would exercise) via
/// [`Capability::matches_request`].
///
/// Adopted from `OpenFang`'s `Capability` enum (master plan §6.2). We
/// ship seven variants in v0 — Memory{Read,Write} land when the memory
/// subsystem arrives in Phase 4.
///
/// [`ToolManifest`]: crate::ToolManifest
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Make outbound network connections to hosts matching this glob.
    /// Pattern is matched against the hostname (e.g.
    /// `"api.example.com"`). v0 does not gate by port or scheme; later
    /// steps can extend.
    NetConnect(GlobPattern),

    /// Read files at paths matching this glob. Pattern is matched
    /// against the absolute path.
    FileRead(GlobPattern),

    /// Write or create files at paths matching this glob.
    FileWrite(GlobPattern),

    /// Execute shell commands whose argv-joined-by-space matches this
    /// glob. Tools should declare *narrow* shell patterns (e.g.
    /// `"git status"`, `"git log *"`) — broad patterns like `"*"` are a
    /// security smell that the constitution should typically `Deny`.
    ShellExec(GlobPattern),

    /// Read environment variables whose name matches this glob.
    EnvRead(GlobPattern),

    /// Query LLM models whose name matches this glob.
    LlmQuery(GlobPattern),

    /// Read secrets from the secret broker whose key matches this glob.
    /// (The secret broker itself ships in a later step; v0 just defines
    /// the capability shape.)
    SecretRead(GlobPattern),
}

impl Capability {
    /// Does this *granted* capability allow the *requested* one?
    ///
    /// Both sides must be the same variant. The granted side's glob
    /// must match the requested side's pattern *string* (interpreted
    /// as a literal). A request expressed as a glob — e.g. `NetConnect("*")` —
    /// is treated literally; the host should construct requested
    /// capabilities from concrete strings, not globs.
    #[must_use]
    pub fn matches_request(&self, requested: &Capability) -> bool {
        if core::mem::discriminant(self) != core::mem::discriminant(requested) {
            return false;
        }
        self.glob().matches(requested.glob().as_str())
    }

    /// The glob pattern this variant carries, regardless of which
    /// variant it is. Used internally by `matches_request` to compare
    /// across same-variant pairs without an N×N match arm explosion.
    fn glob(&self) -> &GlobPattern {
        match self {
            Capability::NetConnect(g)
            | Capability::FileRead(g)
            | Capability::FileWrite(g)
            | Capability::ShellExec(g)
            | Capability::EnvRead(g)
            | Capability::LlmQuery(g)
            | Capability::SecretRead(g) => g,
        }
    }

    /// Stable short identifier for this variant, suitable for error
    /// messages and receipt provenance edges. Matches no specific
    /// external standard — just our own use.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            Capability::NetConnect(_) => "net_connect",
            Capability::FileRead(_) => "file_read",
            Capability::FileWrite(_) => "file_write",
            Capability::ShellExec(_) => "shell_exec",
            Capability::EnvRead(_) => "env_read",
            Capability::LlmQuery(_) => "llm_query",
            Capability::SecretRead(_) => "secret_read",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // --- glob matcher ---

    #[test]
    fn exact_match_no_wildcard() {
        let p = GlobPattern::new("foo");
        assert!(p.matches("foo"));
        assert!(!p.matches("bar"));
        assert!(!p.matches("foobar"));
        assert!(!p.matches("xfoo"));
        assert!(!p.matches(""));
    }

    #[test]
    fn star_alone_matches_anything() {
        let p = GlobPattern::new("*");
        assert!(p.matches(""));
        assert!(p.matches("a"));
        assert!(p.matches("anything goes here"));
    }

    #[test]
    fn prefix_star() {
        let p = GlobPattern::new("foo*");
        assert!(p.matches("foo"));
        assert!(p.matches("foobar"));
        assert!(p.matches("foo "));
        assert!(!p.matches("xfoo"));
        assert!(!p.matches("fo"));
    }

    #[test]
    fn star_suffix() {
        let p = GlobPattern::new("*foo");
        assert!(p.matches("foo"));
        assert!(p.matches("xfoo"));
        assert!(p.matches("xxxfoo"));
        assert!(!p.matches("foox"));
        assert!(!p.matches("fo"));
    }

    #[test]
    fn star_middle_star() {
        let p = GlobPattern::new("*foo*");
        assert!(p.matches("foo"));
        assert!(p.matches("xfoo"));
        assert!(p.matches("foox"));
        assert!(p.matches("xfooy"));
        assert!(p.matches("xfooyfoo"));
        assert!(!p.matches("fox"));
        assert!(!p.matches(""));
    }

    #[test]
    fn star_in_middle() {
        let p = GlobPattern::new("foo*bar");
        assert!(p.matches("foobar"));
        assert!(p.matches("fooxbar"));
        assert!(p.matches("fooxxxbar"));
        assert!(!p.matches("foo"));
        assert!(!p.matches("bar"));
        assert!(!p.matches("foox")); // missing bar
        assert!(!p.matches("xbar")); // missing foo prefix
    }

    #[test]
    fn many_segments() {
        let p = GlobPattern::new("foo*bar*baz");
        assert!(p.matches("foobarbaz"));
        assert!(p.matches("fooxbarxbaz"));
        assert!(p.matches("foo123bar456baz"));
        assert!(!p.matches("foobazbar")); // wrong order
        assert!(!p.matches("fooxbar")); // missing baz
    }

    #[test]
    fn consecutive_stars_collapse() {
        let p = GlobPattern::new("foo**bar");
        assert!(p.matches("foobar"));
        assert!(p.matches("fooxbar"));
        assert!(p.matches("fooxxxbar"));
    }

    #[test]
    fn pattern_starting_and_ending_with_star() {
        let p = GlobPattern::new("**foo**");
        assert!(p.matches("foo"));
        assert!(p.matches("xfoox"));
    }

    #[test]
    fn realistic_hostname_globs() {
        let p = GlobPattern::new("*.example.com");
        assert!(p.matches("api.example.com"));
        assert!(p.matches("v1.api.example.com"));
        assert!(!p.matches("example.com")); // no leading dot
        assert!(!p.matches("example.com.evil.test"));

        let api = GlobPattern::new("api.example.com");
        assert!(api.matches("api.example.com"));
        assert!(!api.matches("apiexample.com"));
    }

    #[test]
    fn realistic_path_globs() {
        let p = GlobPattern::new("/home/uni/*");
        assert!(p.matches("/home/uni/foo"));
        assert!(p.matches("/home/uni/dir/file"));
        assert!(!p.matches("/home/other/foo"));
    }

    #[test]
    fn empty_pattern_matches_only_empty_candidate() {
        let p = GlobPattern::new("");
        assert!(p.matches(""));
        assert!(!p.matches("anything"));
    }

    #[test]
    fn empty_candidate_against_starless_pattern() {
        let p = GlobPattern::new("foo");
        assert!(!p.matches(""));
    }

    // --- capability matching ---

    #[test]
    fn capability_same_variant_glob_match() {
        let granted = Capability::NetConnect(GlobPattern::new("*.example.com"));
        let req_ok = Capability::NetConnect(GlobPattern::new("api.example.com"));
        let req_no = Capability::NetConnect(GlobPattern::new("evil.test"));
        assert!(granted.matches_request(&req_ok));
        assert!(!granted.matches_request(&req_no));
    }

    #[test]
    fn capability_different_variants_never_match() {
        let granted = Capability::NetConnect(GlobPattern::new("*"));
        let req = Capability::FileRead(GlobPattern::new("/etc/passwd"));
        assert!(!granted.matches_request(&req));
    }

    #[test]
    fn capability_full_wildcard_grants_anything_within_variant() {
        let granted = Capability::ShellExec(GlobPattern::new("*"));
        let req = Capability::ShellExec(GlobPattern::new("rm -rf /"));
        assert!(granted.matches_request(&req));
        // But still not across variants:
        let req_other = Capability::FileWrite(GlobPattern::new("/foo"));
        assert!(!granted.matches_request(&req_other));
    }

    #[test]
    fn capability_narrow_grant_blocks_broad_request() {
        let granted = Capability::ShellExec(GlobPattern::new("git *"));
        assert!(granted.matches_request(&Capability::ShellExec(GlobPattern::new("git status"))));
        assert!(!granted.matches_request(&Capability::ShellExec(GlobPattern::new("rm -rf /"))));
    }

    #[test]
    fn variant_names_are_stable_strings() {
        // These values appear in receipt provenance edges; renaming
        // them is a backwards-incompatible change.
        assert_eq!(
            Capability::NetConnect(GlobPattern::new("x")).variant_name(),
            "net_connect"
        );
        assert_eq!(
            Capability::FileRead(GlobPattern::new("x")).variant_name(),
            "file_read"
        );
        assert_eq!(
            Capability::FileWrite(GlobPattern::new("x")).variant_name(),
            "file_write"
        );
        assert_eq!(
            Capability::ShellExec(GlobPattern::new("x")).variant_name(),
            "shell_exec"
        );
        assert_eq!(
            Capability::EnvRead(GlobPattern::new("x")).variant_name(),
            "env_read"
        );
        assert_eq!(
            Capability::LlmQuery(GlobPattern::new("x")).variant_name(),
            "llm_query"
        );
        assert_eq!(
            Capability::SecretRead(GlobPattern::new("x")).variant_name(),
            "secret_read"
        );
    }

    #[test]
    fn glob_pattern_round_trips_through_string() {
        let p1: GlobPattern = "foo*bar".into();
        let p2: GlobPattern = "foo*bar".to_string().into();
        assert_eq!(p1, p2);
        assert_eq!(p1.as_str(), "foo*bar");
    }
}
