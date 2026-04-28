# Phase 1 Step 4 — The Receipt Explainer

> **Phase:** 1 — Shippable Core
> **PR:** #3 (bundled with constitution and budgets)
> **Crate introduced:** `uniclaw-explain`

## What is this step?

This step turns a signed receipt into a **plain-English explanation** that a non-engineer can understand.

A receipt is a JSON object with cryptographic fields, hashes, and signatures. That's perfect for a verifier and an audit log, but it is *not* something a manager, regulator, or customer can read. The explainer fixes that.

## Where does this fit in the whole Uniclaw?

The explainer is a **read-only** consumer of receipts. It does not produce them, store them, or affect the chain in any way. It just makes them human-friendly:

```
Receipt JSON  -->  uniclaw-explain  -->  "On 2026-04-27 at 12:00 UTC,
                                          the agent tried to fetch
                                          https://example.com/. The
                                          action was Allowed because no
                                          rule blocked it. Signature:
                                          verified."
```

It exists as both a **library** (`uniclaw-explain` crate, embedded in any Rust program) and a **standalone binary** (`uniclaw-explain` CLI, ~727 KB stripped).

## What problem does it solve technically?

Three problems:

### 1. "How does a non-engineer audit a receipt?"

JSON is fine for machines and engineers. It is poor for compliance officers, lawyers, journalists, and end users. The explainer renders the same information as a paragraph in plain English, plus an optional structured JSON format for tooling.

### 2. "How do we describe *why* a decision was made?"

The receipt records facts (which rules fired, what the decision was). The explainer interprets them: "this action was paused because of rule `solo-dev/no-shell-without-approval`," not just "matched_rules: [{id: 'solo-dev/no-shell-without-approval', matched: true}]."

### 3. "How do we encode 'what category of decision is this'?"

The explainer's `Verdict` enum is the human-readable categorization:

```rust
pub enum Verdict {
    Allowed,
    DeniedByConstitution,
    DeniedByBudget,
    DeniedAsProposed,
    Approved,
    Pending { rules_consulted: u32 },
    DeniedByOperator,
}
```

This is similar to the kernel's `OutcomeKind`, but designed for *cold readers* — someone reading a receipt later, without access to the runtime. The explainer can derive a `Verdict` purely from a stored receipt's contents.

## How does it work in plain words?

The explainer takes a receipt and asks:

1. **What's the decision?** (`Allowed`, `Denied`, `Approved`, `Pending`)
2. **What rules fired?** (Constitution rules vs. virtual budget rules vs. virtual approval rules)
3. **Who is the issuer?** (Public key — show its fingerprint)
4. **Does the signature verify?** (Yes / No / Skipped)
5. **Where in the chain is it?** (`sequence`, `prev_hash`)

It produces an `Explanation` struct that holds these pieces, plus two renderers:

- `render_text(&Explanation) -> String` — paragraph form for humans.
- `render_json(&Explanation) -> String` — structured form for tooling.

### The CLI

```sh
# Render a receipt as plain English
uniclaw-explain --receipt path/to/receipt.json

# Render as structured JSON
uniclaw-explain --receipt path/to/receipt.json --format json

# Verify the signature too (requires --pubkey)
uniclaw-explain --receipt path/to/receipt.json --pubkey <hex>
```

### Rule classification

Constitution rules have human-friendly IDs like `solo-dev/no-shell-without-approval`. The kernel also produces **virtual rules** for budget and approval events — these have IDs that start with `$kernel/`:

- `$kernel/budget/net_bytes_exhausted` → "the network budget was used up"
- `$kernel/budget/file_writes_exhausted` → "the file-write budget was used up"
- `$kernel/approval/denied_by_operator` → "the operator denied this action"

The explainer recognizes these prefixes and renders them with their human meaning, not just the raw ID.

## Why this design choice and not another?

- **Why a separate crate, not part of `uniclaw-receipt`?** Because the explainer needs `serde_json` with `std`, while the receipt format crate stays `no_std`. Keeping them separate keeps the verifier tiny.
- **Why both library and binary?** The library is for any tool that wants to embed explanations (a dashboard, a Slack bot, a PDF renderer). The binary is for the obvious "I have a JSON file, what does it say?" workflow.
- **Why `#[serde(tag, content)]` for `Verdict`?** It produces the JSON shape `{ "kind": "Pending", "data": { "rules_consulted": 3 } }`, which is easy for downstream tools to handle.
- **Why classify rule IDs by string prefix?** Because rule IDs are stable across versions; classifying by prefix means new virtual rules can be added without changing the explainer.

## What you can do with this step today

- Hand any receipt JSON to `uniclaw-explain` and get a plain-English summary.
- Pipe the JSON output of `uniclaw-explain` into other tools.
- Embed the library in your own programs to render explanations in a UI.

```sh
$ uniclaw-explain --receipt approved_after_pending.json

Receipt #1 in chain
Issued at: 2026-04-27T12:00:00Z
Issuer:    fingerprint a1b2c3...
Action:    shell.exec → ls
Verdict:   Approved (after Pending; the operator gave the green light)
Rules consulted:
  - solo-dev/no-shell-without-approval [matched]
Signature: verified ✓
Chain:     sequence 1, links to receipt with leaf_hash 0xabcd…
```

## In summary

Step 4 makes receipts human-readable. It does not change what a receipt means — it just translates it. The library is small, the binary is small, and the rule of separation is clean: cryptography stays in `uniclaw-receipt`; presentation stays here.
