# Uniclaw

> The model proposes. The kernel decides. The tools execute inside a cage. **And the kernel proves it.**

Uniclaw is a verifiable universal agent runtime built in Rust. It produces signed, third-party-verifiable **receipts** for every consequential agent action — so you can hand a regulator, an auditor, a customer, or a judge a URL that proves what your agent did, without trusting the runtime that produced it.

🦀+🦞
## Status

**Pre-alpha.** Phase 0 (Receipt-First Foundation) is in progress.

## Why Uniclaw

Every other agent runtime gives you logs. Uniclaw gives you **receipts** — signed, content-addressed, and verifiable by anyone with a 200-LOC binary that can be installed without installing Uniclaw itself.

Unique to Uniclaw:

- **Public-URL receipts.** Every high-risk action mints a receipt at `uniclaw://receipt/<hash>`. Verifiable cold by any auditor.
- **Constitution engine.** Human-readable rules separate from the model, judging proposals before the policy gate.
- **Capability budget algebra.** Leases carry numeric budgets that compose on delegation and shrink with use.
- **Provenance graph.** Typed edges (`user → model → tool → output`) — explain any decision, time-travel any state.
- **Sleep-stage memory.** Memory consolidates through Light Sleep (hourly cleanup), REM Sleep (daily reflection), Deep Sleep (weekly promotion + integrity walk). *Uniclaw is the first agent runtime that sleeps.*
- **Mobile-sovereign profile.** Android-native, on-device LLM via WGSL/Vulkan, hardware-attested sensor leases.

See [`UNICLAW_PLAN.md`](../UNICLAW_PLAN.md) for the full master plan.

## Workspace

```text
uniclaw/
├── crates/
│   ├── uniclaw-receipt/   # Receipt format types — shared, no_std-friendly
│   └── uniclaw-verify/    # Standalone verifier binary — ≤ 200 LOC, no kernel deps
├── Cargo.toml             # Workspace root
└── …                      # Project hygiene, CI, license files
```

## Quick start

```sh
# Build everything.
cargo build --workspace

# Run tests.
cargo test --workspace

# Run the standalone verifier on a receipt.
cargo run --bin uniclaw-verify -- path/to/receipt.json
```

## Engineering discipline

Uniclaw enforces several rules in CI to avoid the failure modes seen in predecessor projects (god-object kernels, config-format sprawl, plugin-as-trusted, drift on size budgets):

- **Adopt, don't copy.** Read every claw's source; never import it. Patterns are reimplemented in Uniclaw idioms with `// Pattern adapted from <project>/<file> (<license>)` citations.
- **Hard ceilings.** ≤ 5 KLOC per file in `uniclaw-kernel`, ≤ 20 crates through Phase 4, TOML-only config, size CI gate per profile.
- **Two-track development.** `trunk` (boring, shippable) + `lab` (experimental, may fail). `lab` failures must not block `trunk`.
- **Public quarterly demos.** Recorded, tagged, embarrassing if missed.
- **Adapter scarcity.** Only OpenClaw sidecar adapter ships in MVP; additional adapters require ≥ 10 GitHub thumbs of demand.

See [`UNICLAW_PLAN.md`](../UNICLAW_PLAN.md) §24.

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security disclosures: [`SECURITY.md`](SECURITY.md).
