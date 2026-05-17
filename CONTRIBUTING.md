# Contributing to BoardProof

Thanks for considering a contribution. BoardProof is in pre-alpha and the bar for
correctness is unusually high — we are building a verifiable agent runtime,
which means every shipped change is an attestation about agent behavior.

## Before you start

1. Read the [master plan](../UNICLAW_PLAN.md). Section 24 (*Engineering
   Discipline Rules*) is non-negotiable.
2. Check open issues and the project board for in-flight work.
3. For non-trivial changes, open an issue first to align on direction.

## The Adopt-Don't-Copy rule

BoardProof reads every source claw's code; never imports it. This is hard rule §24.1.

- **Algorithms and math** are fair game — Merkle hashing, capability matching,
  CRDT merges. Reimplement in BoardProof idioms.
- **Test fixtures and adversarial scenarios** should be embedded with
  attribution.
- **Specs and formats** are supported, not embedded — write your own parsers
  for OpenClaw plugin manifests, IronClaw WIT, OpenFang Hand TOML, etc.
- **Cite all inspirations** in code comments:
  `// Pattern adapted from <project>/<file> (<license>)`.

If a PR copies source from another claw runtime, it will be closed without
review, regardless of license compatibility.

## Hard ceilings

CI enforces these. PRs that violate them will be auto-blocked:

| Rule                                      | Limit          |
| ----------------------------------------- | -------------- |
| File size in `boardproof-kernel/`            | ≤ 5 KLOC       |
| Workspace crate count (through Phase 4)   | ≤ 20           |
| Config formats                            | TOML only      |
| Binary / RSS budgets per profile          | per §23 table  |
| State-mutating code without a receipt     | requires `#[no_receipt]` + justifying comment |

## Pull request checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] New code paths emit or consume a receipt (or have `#[no_receipt]`)
- [ ] Inspirations cited if a pattern was adopted from another claw
- [ ] CHANGELOG updated under `[Unreleased]`
- [ ] No copied source from another claw runtime

## Receipt-discipline checklist

For changes touching the kernel, ask in the PR description:

> *What receipt does this change emit, and what does the receipt prove?*

If you cannot answer, the change probably belongs in `lab` rather than `trunk`.

## Two-track development

- **`trunk`** — boring, shippable kernel work. Receipt format, kernel state
  machine, policy gate, capability leases, Merkle chain, sleep stages.
- **`lab`** — experimental work that may fail loudly: ZK receipts, federated
  CRDT memory, mobile-sovereign experiments, GPU acceleration prototypes.

Lab failures must never block trunk shipping. Promotions from lab to trunk
require: hard ceilings green, telemetry from ≥ 2 operators for 30 days, and a
written deprecation plan for the experimental flag.

## Licensing of contributions

By submitting a PR you agree your contribution is licensed under the dual
MIT / Apache-2.0 terms of the project.
