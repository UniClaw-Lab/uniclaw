//! Integration test: load `constitutions/solo-dev.toml` from disk and run
//! a few realistic-looking proposals through it.

use uniclaw_constitution::{Constitution, parse_toml};
use uniclaw_receipt::{Action, Decision, Digest};

fn load_solo_dev() -> impl Constitution {
    // The crate lives at crates/uniclaw-constitution; the constitution file
    // lives at the repo root. CARGO_MANIFEST_DIR points at the crate dir,
    // so step up two levels.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("constitutions")
        .join("solo-dev.toml");
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_toml(&src).expect("solo-dev.toml must parse")
}

fn action(kind: &str, target: &str) -> Action {
    Action {
        kind: kind.into(),
        target: target.into(),
        input_hash: Digest([0u8; 32]),
    }
}

#[test]
fn shell_exec_is_denied() {
    let c = load_solo_dev();
    let v = c.evaluate(&action("shell.exec", "ls -la"));
    assert_eq!(v.override_decision, Some(Decision::Denied));
    assert!(
        v.matched_rules.iter().any(|r| r.id == "solo-dev/no-shell"),
        "expected solo-dev/no-shell to fire; got: {:?}",
        v.matched_rules,
    );
}

#[test]
fn benign_http_get_passes() {
    let c = load_solo_dev();
    let v = c.evaluate(&action("http.get", "https://example.com/"));
    assert!(v.matched_rules.is_empty());
    assert_eq!(v.override_decision, None);
}

#[test]
fn stripe_post_is_denied() {
    let c = load_solo_dev();
    let v = c.evaluate(&action("http.post", "https://api.stripe.com/v1/charges"));
    assert_eq!(v.override_decision, Some(Decision::Denied));
    assert!(
        v.matched_rules
            .iter()
            .any(|r| r.id == "solo-dev/no-finance-stripe")
    );
}

#[test]
fn package_install_is_denied_with_two_rules_recorded() {
    let c = load_solo_dev();
    // Both `solo-dev/no-shell` and `solo-dev/no-package-install` should fire.
    let v = c.evaluate(&action("shell.exec", "sudo apt-get install nmap"));
    assert_eq!(v.override_decision, Some(Decision::Denied));
    let ids: Vec<&str> = v.matched_rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"solo-dev/no-shell"), "ids: {ids:?}");
    assert!(ids.contains(&"solo-dev/no-package-install"), "ids: {ids:?}");
}

#[test]
fn git_push_is_denied_by_no_shell_before_require_approval_runs() {
    // The git-push rule (require_approval) is shadowed by no-shell (deny)
    // because Deny takes precedence over RequireApproval. This is the
    // safe-by-default semantics — confirms that ordering in the TOML
    // doesn't change the final verdict.
    let c = load_solo_dev();
    let v = c.evaluate(&action("shell.exec", "git push origin main"));
    assert_eq!(v.override_decision, Some(Decision::Denied));
    let ids: Vec<&str> = v.matched_rules.iter().map(|r| r.id.as_str()).collect();
    // Both rules are recorded in the audit trail even though Deny wins.
    assert!(ids.contains(&"solo-dev/no-shell"), "ids: {ids:?}");
    assert!(
        ids.contains(&"solo-dev/git-push-needs-approval"),
        "ids: {ids:?}"
    );
}
