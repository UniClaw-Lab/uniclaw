# Uniclaw Documentation

Plain-English documentation for Uniclaw — the verifiable AI agent runtime.

## Start here

If you've never heard of Uniclaw before, read these in order:

1. **[What is Uniclaw?](01-what-is-uniclaw.md)** — A friendly introduction. After 10 minutes you should know what Uniclaw does, who it's for, and why it's different.
2. **[Uniclaw vs OpenClaw](02-uniclaw-vs-openclaw.md)** — Side-by-side comparison with the most popular agent runtime. Helps you decide which one fits your needs.
3. **[The Roadmap](03-roadmap.md)** — The 8-phase plan and where we are right now.

## Step-by-step deep dive

Each implementation step has its own page in `steps/`. Each one explains, in plain English:

- **What** the step is.
- **Where** it fits in the whole Uniclaw architecture.
- **What problem** it solved technically.
- **How it works** in plain words (with code snippets where they help).
- **What you can do** with it today.

| # | Step | Phase | Doc |
|---|---|---|---|
| 0 | The Receipt Format (foundation) | Phase 0 | [steps/00-foundation-receipts.md](steps/00-foundation-receipts.md) |
| 1 | Kernel State Machine | Phase 1 | [steps/01-kernel-state-machine.md](steps/01-kernel-state-machine.md) |
| 2 | Constitution Engine | Phase 1 | [steps/02-constitution-engine.md](steps/02-constitution-engine.md) |
| 3 | Capability Budgets | Phase 1 | [steps/03-capability-budgets.md](steps/03-capability-budgets.md) |
| 4 | Receipt Explainer | Phase 1 | [steps/04-receipt-explainer.md](steps/04-receipt-explainer.md) |
| 5 | Approval Engine | Phase 1 | [steps/05-approval-engine.md](steps/05-approval-engine.md) |
| 6 | Channel-Aware Approval Routing | Phase 1 | [steps/06-channel-aware-routing.md](steps/06-channel-aware-routing.md) |
| 7 | Receipt Store | Phase 1 | [steps/07-receipt-store.md](steps/07-receipt-store.md) |
| 8 | Light Sleep Cleanup | Phase 1 | [steps/08-light-sleep.md](steps/08-light-sleep.md) |
| 9 | Public-URL Receipt Hosting | Phase 2 | [steps/09-public-url-hosting.md](steps/09-public-url-hosting.md) |
| 10 | SQLite-backed Receipt Store | Phase 2 | [steps/10-sqlite-receipt-store.md](steps/10-sqlite-receipt-store.md) |
| 11 | Deep Sleep Integrity Walk | Phase 2 | [steps/11-deep-sleep.md](steps/11-deep-sleep.md) |
| 12 | HTML Verifier UI | Phase 2 | [steps/12-html-verifier.md](steps/12-html-verifier.md) |

> **Note:** Phase 0 (the receipt format) is foundational and ships before Phase 1 step 1, so it's labeled "Step 0" in this index. Phase 1 has 8 numbered steps. Phase 2 begins at step 9.

## How to navigate

- **Most readers** should start with [01-what-is-uniclaw.md](01-what-is-uniclaw.md) and stop there. That document is enough to understand what Uniclaw is and decide whether to keep reading.
- **Engineers evaluating Uniclaw for production** should read [02-uniclaw-vs-openclaw.md](02-uniclaw-vs-openclaw.md) and then dip into the step docs that match their concerns (e.g., compliance officers want step 7 (Receipt Store) and step 5 (Approval Engine) most).
- **Contributors** should read everything, then check `UNICLAW_PLAN.md` (the canonical master plan) and `CONTRIBUTING.md`.

## Style and conventions

- **Plain English.** Every doc avoids jargon where possible and defines technical terms on first use.
- **Mermaid diagrams.** GitHub renders these as visuals. They are the closest thing to inline images this docs set uses.
- **Code snippets are illustrative.** They show shape, not always the full real signature. The crate-level Rust API docs (`cargo doc --open`) are the source of truth for exact types.
- **Each doc is independent.** You can drop into any single page without reading the others first; cross-references are explicit links.

## When to update these docs

This is a standing rule going forward:

- **Whenever a new implementation step lands**, a new `steps/NN-<topic>.md` doc is added in the same PR (or a follow-up PR before the next step starts).
- **Whenever a fundamental design choice changes**, the relevant top-level doc (`01`, `02`, `03`) gets updated in the same PR that changes the design.
- **Whenever a new public surface (crate, binary, endpoint) ships**, it gets at least a paragraph in the relevant step doc plus a mention in the index above.

The goal: anyone landing in the repo cold should be able to understand, in 30 minutes, what we're building and where we are.

## Other authoritative places

- **`UNICLAW_PLAN.md`** at the repo root — the canonical master plan. Everything in this docs set is a friendly summary of something there.
- **`RFCS/`** at the repo root — the receipt format spec and any future RFCs.
- **`CHANGELOG.md`** at the repo root — what's on `main` right now, in Keep-a-Changelog format.
- **`crates/<name>/src/lib.rs`** — the doc comment at the top of every crate has the technical "where this fits" summary plus adopt-don't-copy citations.
