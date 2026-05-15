# Uniclaw

> The model proposes. The kernel decides. **The receipt proves it.**

```text
   ┌──────────────┐    ┌──────────────┐    ┌────────────────────┐
   │  The model   │ →  │ Constitution │ →  │   Tool execution   │
   │   proposes   │    │   + Budget   │    │   (sandboxed)      │
   └──────────────┘    └──────────────┘    └────────────────────┘
                                                    │
                                                    ▼
                              ┌──────────────────────────────────┐
                              │   uniclaw://receipt/<blake3>     │   ← Ed25519-signed
                              │   Verifiable by anyone, cold     │     Chained by BLAKE3
                              └──────────────────────────────────┘
                                                    │
                                                    ▼
                                       Hand it to an auditor.
                                       They verify from any laptop
                                       with a 720 KiB binary.
                                       They never trust your runtime.
```

Every other agent runtime gives you logs.
**Uniclaw gives you receipts** — signed, content-addressed, third-party-verifiable.

🦀+🦞

## Why this matters

Your agent calls a tool. Did it stay inside policy? Who approved it? What credential did it touch? Was the output redacted? Can you prove all of it without showing your database, your machine, or your trust relationships?

Logs say *"this is what we wrote down."*
Receipts say *"this is what happened, signed by us, chained to what came before, and verifiable cold by anyone."*

A receipt is a small JSON object. It carries the action, the policy decision, the rule references, the provenance edges, the input and output content hashes, and an Ed25519 signature over the whole thing. The receipt's content id is BLAKE3 over a canonical encoding. Each receipt links to the previous one's hash, so the chain is tamper-evident. The verifier is ~200 LOC of cryptographic math; it depends on nothing else in this repo.

## What's unique about Uniclaw

- **Public-URL receipts.** Every consequential action mints a receipt at `/receipts/<hash>`. Mount it on any HTTPS endpoint. Auditors fetch it from anywhere.
- **Constitution engine.** Human-readable TOML rules separate from the model. The constitution judges proposals *before* the policy gate, before the tool, before the LLM gets to claim authority.
- **Capability budget algebra.** Leases carry numeric budgets that compose on delegation and shrink with use. A delegated child agent can't spend more authority than its parent leased it.
- **Provenance graph.** Typed edges (`user → model → tool → output`, `secret_used`, `tool_input`, `tool_output`) — explain any decision; query "which receipts touched `secret:<X>`?" structurally.
- **Sleep-stage memory.** Memory consolidates through Light Sleep (hourly cleanup), Deep Sleep (weekly integrity walk), REM Sleep (daily reflection — Phase 4). *Uniclaw is the first agent runtime that sleeps.*
- **Browser verifier.** A self-contained ~8.5 KB HTML page runs Ed25519 verification client-side via `crypto.subtle`. Save it offline; verify any receipt without trusting any server.
- **Mobile-sovereign profile.** Android-native, on-device LLM via WGSL/Vulkan, hardware-attested sensor leases (Phase 5).

## Every claw can use Uniclaw

Uniclaw is **not an assistant.** It's the proof layer your assistant plugs into. Every other claw is good at something Uniclaw deliberately is not: channels, hardware, deployment, autonomy, edge footprint. None of them produce *portable* third-party-verifiable evidence. That's the gap Uniclaw fills.

| Your claw | Uniclaw's job alongside it |
|---|---|
| **OpenClaw** — channels, gateway, skills, companion apps | Sign every Slack/Discord/web action with a receipt URL. Maps channel identity → Uniclaw principals; OpenClaw tool manifests → Uniclaw capabilities. |
| **ZeroClaw** — Rust, hardware, 30+ channels, single-binary | Upgrade local HMAC tool receipts into public Ed25519 evidence. Hardware actions (GPIO/I2C/USB/actuators) emit explicit capability receipts. |
| **OpenFang** — Hands, workflows, capability packages | Anchor each workflow node + branch + retry as receipt-linked actions. Anchor OpenFang's Merkle audit chains in signed checkpoint receipts. |
| **NemoClaw** — sandbox, k3s, OpenShell, NVIDIA | Sign from outside the sandbox. The signing key never sees the workload. Egress + inference-route + secret-injection events become signed receipts. |
| **NanoClaw** — small, containerized, SQLite mailboxes | Add receipt id columns to session DBs. Containers can request actions; only the host can sign. Stay simple. |
| **IronClaw** — Reborn kernel, secret leases, network mediation | Externalize the strong kernel events. Convert one-shot secret leases into `secret_used` receipts, WIT tool calls into `tool_executed` receipts. |
| **PicoClaw** — edge, OpenWrt, RISC-V, Android | Tiny verifier on the device. The gateway mints; the device verifies before executing high-risk commands. Receipt bundles for offline sync. |

Three integration patterns (pick the smallest one that fits):

1. **Embedded kernel library.** Link `uniclaw-kernel` directly. Call `EvaluateProposal`; get back a signed `Allowed` / `Denied` / `Pending` receipt. Submit `RecordToolExecution` after the tool runs. Best for Rust runtimes.
2. **Receipt sidecar.** Run `uniclaw-host` as a local daemon. POST proposals over HTTP/Unix socket; get receipt URLs back. Best for TypeScript, Go, Python, container deployments.
3. **External witness service.** You sign locally; a witness publishes chain checkpoints. Adds *non-omission* evidence on top of the receipts themselves. Future-phase.

The authority rule:

> The model can request authority, but only Uniclaw can mint the evidence that authority was granted and spent.

## Status

**Pre-alpha.** Phase 3 is in progress. Receipt format, kernel, constitution, budgets, approvals, store, sleep passes, public-URL hosting, browser verifier, secret broker, HTTP fetch tool, and WASM runtime (core + Component Model) all ship on `main` today. WASM host imports, container fallback, output sanitization, federated memory, and the mobile-sovereign profile are next.

No production deployments yet. Run it, break it, file issues.

| Phase | Theme | Status |
|---|---|---|
| 0 | Receipt-First Foundation | ✅ shipped |
| 1 | Shippable Core (kernel + constitution + budget + approval + router + store + sleep + explainer) | ✅ shipped |
| 2 | Public Service (host + SQLite store + Deep Sleep + browser HTML verifier) | ✅ shipped |
| 3 | Tools & Secrets (tool foundation, HTTP fetch, secret broker, WASM runtime, Component Model) | 🚧 in progress |
| 4 | Federated Memory (sync, vector index, provenance graph) | ⬜ planned |
| 5 | Mobile-Sovereign | ⬜ planned |
| 6 | Governance (privacy receipts, optional ZK) | ⬜ planned |
| 7 | Interop (MCP bridge, OpenTelemetry, multi-claw adapter kit) | ⬜ planned |

[Full roadmap](docs/03-roadmap.md) · [Per-step deep dives](docs/steps/) · [What is Uniclaw?](docs/01-what-is-uniclaw.md) · [Uniclaw vs OpenClaw](docs/02-uniclaw-vs-openclaw.md)

## Quick start

```bash
git clone https://github.com/BoardClaw-Labs/uniclaw
cd uniclaw

cargo build --workspace
cargo test --workspace          # 336 tests, all passing

# Mint a fresh receipt and verify it with the standalone verifier.
cargo run --release --example mint-sample -p uniclaw-verify > /tmp/receipt.json
cargo run --release --bin uniclaw-verify -- /tmp/receipt.json
```

The `uniclaw-verify` binary is ~720 KiB stripped. **It depends on nothing else in this repo.** You can ship it standalone to anyone who wants to verify a receipt without installing Uniclaw at all. That's the whole point of the architecture: the verifier is the smallest possible trust footprint.

## Workspace

```text
uniclaw/                              16 of 20 crates  ·  ≤ 20 ceiling
├── crates/
│   ├── uniclaw-receipt/              receipt types — no_std-friendly
│   ├── uniclaw-verify/               standalone verifier binary (~720 KiB stripped)
│   ├── uniclaw-kernel/               event handler — signs receipts, advances chain
│   ├── uniclaw-constitution/         TOML-driven policy engine
│   ├── uniclaw-budget/               capability-lease algebra
│   ├── uniclaw-approval/             pending → resolved approval flow
│   ├── uniclaw-router/               channel-aware approval routing
│   ├── uniclaw-store/                receipt log trait + in-memory impl
│   ├── uniclaw-store-sqlite/         WAL-mode SQLite-backed receipt log
│   ├── uniclaw-sleep/                Light Sleep + Deep Sleep passes
│   ├── uniclaw-explain/              receipt → human-readable evidence
│   ├── uniclaw-host/                 axum HTTP server + browser verifier UI
│   ├── uniclaw-tools/                Tool trait + Capability enum + ToolHost
│   ├── uniclaw-tools-http/           sandboxed HTTP fetch tool (cap + SSRF + bounded)
│   ├── uniclaw-secrets/              SecretValue (zeroize-on-drop) + SecretBroker
│   └── uniclaw-tools-wasm/           wasmtime runtime + Component Model layer
├── docs/                             intro · vs-OpenClaw · roadmap · per-step deep-dives
├── RFCS/                             RFC-0001 receipt format spec
└── CHANGELOG.md                      every shipped step, in detail
```

## Engineering discipline

These rules exist to avoid the failure modes seen in predecessor projects (god-object kernels, config-format sprawl, plugin-as-trusted, drift on size budgets):

- **Adopt, don't copy.** Read every claw's source; never import it. Adopted patterns carry `// adapted from <project>/<file>` citations in the relevant `lib.rs`. We've now drawn from IronClaw (WIT Component Model + secret-lease pattern + StoreData shape), OpenFang (capability glob enforcement), OpenClaw (gateway-level deny lists), and ZeroClaw (drop-zeroing discipline). No source borrowed from any.
- **Hard ceilings.** ≤ 5 KLOC per file in `uniclaw-kernel`, ≤ 20 crates through Phase 4, TOML-only config, size CI gate per profile.
- **Two-track development.** `trunk` (boring, shippable) + `lab` (experimental, may fail). `lab` failures must not block `trunk`.
- **Per-step doc.** Every implementation step ships with [`docs/steps/<NN>-<topic>.md`](docs/steps/) explaining why we chose X over Y.
- **Adapter scarcity.** Only one external-claw adapter ships in MVP; additional adapters require ≥ 10 GitHub thumbs of demand. Avoids "every channel" sprawl.

## Non-goals

To stay coherent, Uniclaw deliberately does *not* try to:

- Out-OpenClaw OpenClaw on channels/skills/onboarding.
- Out-PicoClaw PicoClaw on edge footprint (we ship a *tiny verifier* for that world; the full runtime is for hosts and desktops).
- Out-NemoClaw NemoClaw on NVIDIA / OpenShell deployment.
- Compete with IronClaw's broad runtime contracts. We integrate with them.
- Be a chatbot. Uniclaw is the evidence machine your chatbot plugs into.

The win condition is *not* "everyone runs the Uniclaw app." The stronger win condition is *"everyone trusts a Uniclaw-compatible receipt."*

## License

Dual-licensed: Apache-2.0 OR MIT. Pick whichever fits your project.

- [`LICENSE-APACHE`](LICENSE-APACHE)
- [`LICENSE-MIT`](LICENSE-MIT)

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow. Security disclosures go through [`SECURITY.md`](SECURITY.md).

If you're an OpenClaw / ZeroClaw / OpenFang / NemoClaw / NanoClaw / IronClaw / PicoClaw maintainer (or building anything adjacent) and want to talk about an integration, open an issue with the `integration` label.
