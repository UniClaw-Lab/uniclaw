# Phase 1 Step 2 — The Constitution Engine

> **Phase:** 1 — Shippable Core
> **PR:** #3 (bundled with budgets and explainer)
> **Crate introduced:** `uniclaw-constitution`

## What is this step?

This step builds the **rules engine** that decides whether an action should be **allowed**, **denied**, or **paused for human approval**.

The rules are written in a separate file (TOML format), not inside prompts. They are checked by code, not by the model. We call this the **Constitution** because it sits above the model in the same way a constitution sits above a government: even the most powerful agent cannot violate it.

## Where does this fit in the whole Uniclaw?

The Constitution sits between the **model** and the **kernel**:

```
Brain (model)  --proposes-->  Constitution  --verdict-->  Kernel
                                  ^
                                  |
                              solo-dev.toml
                              (your rules)
```

Every time the kernel handles a `Proposal`, it asks the Constitution first. The Constitution looks at the action's `kind` and `target`, walks through your rule list, and returns a verdict.

This separation matters: the model is creative, possibly wrong, possibly compromised. The Constitution is **deterministic** code that you can review, test, and version.

## What problem does it solve technically?

Three problems:

### 1. "How do I keep rules out of the model?"

Putting rules in prompts is a well-known anti-pattern. The model can be tricked, jailbroken, or simply confused. Worse, the rules become invisible to humans who want to audit what the agent is actually allowed to do. By moving rules into TOML, anyone can read them in a text editor and reason about them.

### 2. "How do I make rules testable?"

A rule is just code. You can write a unit test for it: "given action `shell.exec rm -rf /`, this rule must say Deny." We do exactly this in the Rust tests for the constitution crate. Rules become first-class engineering artifacts.

### 3. "How does the kernel record which rule fired?"

Every receipt has a `constitution_rules` field — a list of `RuleRef { id, matched }`. When a rule fires, its ID goes into this list, with `matched: true`. An auditor reading the receipt can see exactly which rule applied and why the decision came out the way it did.

## How does it work in plain words?

A constitution is a list of rules. Each rule has:

- **`id`** — a stable identifier like `solo-dev/no-shell-without-approval`.
- **`description`** — what the rule means in human language.
- **`match_clause`** — what action it applies to (`kind`, `target_contains`).
- **`verdict`** — `Deny` or `RequireApproval`.

A complete starter file (`constitutions/solo-dev.toml`) looks like this (simplified):

```toml
[[rule]]
id = "solo-dev/no-shell-without-approval"
description = "Shell exec needs my green light."
verdict = "RequireApproval"
match_clause.kind = "shell.exec"

[[rule]]
id = "solo-dev/git-push-needs-approval"
description = "Don't push to remote without me."
verdict = "RequireApproval"
match_clause.kind = "git.push"

[[rule]]
id = "solo-dev/no-rm-rf-root"
description = "Never run rm -rf /."
verdict = "Deny"
match_clause.kind = "shell.exec"
match_clause.target_contains = "rm -rf /"
```

The trait surface is small:

```rust
pub trait Constitution {
    fn evaluate(&self, action: &Action) -> ConstitutionVerdict;
}

pub struct ConstitutionVerdict {
    pub override_decision: Option<Decision>, // None, Some(Denied), Some(Pending)
    pub matched_rules: Vec<RuleRef>,
}
```

Two implementations ship today:

- **`EmptyConstitution`** — never matches anything. Useful for tests and bare-runtime setups.
- **`InMemoryConstitution`** — holds a list of rules in memory. Loadable from TOML.

### Precedence

When multiple rules match, precedence is fixed:

1. **`Deny` beats everything.** Even one matching `Deny` rule produces `Decision::Denied`.
2. **`RequireApproval`** is next. If no `Deny` matches but a `RequireApproval` does, the verdict is `Decision::Pending`.
3. **No match** — the kernel falls back to whatever the caller proposed.

This precedence is deliberate. Safety beats convenience.

## Why this design choice and not another?

- **Why TOML, not YAML or JSON?** TOML is unambiguous about types, allows comments, and is trivial to write by hand. YAML has indentation gotchas; JSON has no comments.
- **Why not put rules in a database?** A database adds a dependency, a query language, and a place where rules can be silently changed without a code review. A file in the repo is reviewed when it changes.
- **Why not allow regex or scripting in match clauses?** Regex/scripting opens an injection attack surface. The match clause is intentionally small: exact `kind` plus optional substring `target_contains`. Power that's not needed is power that can be abused.
- **Why does the verdict carry rules, not just a decision?** Because the receipt must record *which* rules fired. A bare `Decision` would lose that information.

## What you can do with this step today

- Author a `constitutions/your-team.toml` file.
- Load it with `InMemoryConstitution::from_toml(...)`.
- Hand it to a `Kernel` and watch it deny or pause actions.
- Unit-test individual rules with simple Rust tests:

```rust
#[test]
fn rm_rf_root_is_denied() {
    let c = load_solo_dev_toml();
    let verdict = c.evaluate(&Action {
        kind: "shell.exec".into(),
        target: "rm -rf /".into(),
        input_hash: Digest([0u8;32]),
    });
    assert_eq!(verdict.override_decision, Some(Decision::Denied));
}
```

## In summary

Step 2 puts your rules where they belong: in version-controlled, code-reviewed, code-tested files. The kernel asks the Constitution before every action. The receipt records which rules applied. Rules become real engineering artifacts, not prompt fragments.
