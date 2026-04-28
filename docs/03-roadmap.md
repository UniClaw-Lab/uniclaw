# The Uniclaw Roadmap (8 phases, plain English)

> A guided tour through the receipt-first roadmap. Each phase is one focused goal. We finish a phase before moving to the next.

The full plan lives in `UNICLAW_PLAN.md` §28. This page is the friendly summary.

## Why "receipt-first"?

The order matters. Many AI agent projects build the agent first and bolt on logging afterward. Uniclaw goes the other way. The **first thing** we built was the receipt format. **Then** we built the runtime around it. Why?

Because if the receipt format is wrong, every later piece is built on sand. By making receipts come first, every later step has to *fit* the receipt format — which keeps the whole runtime honest.

```mermaid
graph LR
  P0[Phase 0<br>Receipt format] --> P1[Phase 1<br>Shippable Core]
  P1 --> P2[Phase 2<br>Public service]
  P2 --> P3[Phase 3<br>Tools and secrets]
  P3 --> P4[Phase 4<br>Federated memory]
  P4 --> P5[Phase 5<br>Mobile-sovereign]
  P5 --> P6[Phase 6<br>Compliance + redaction]
  P6 --> P7[Phase 7<br>Verified delegation]
  P7 --> P8[Phase 8<br>Hardening + GA]
```

## Phase 0 — Receipt-First Foundation ✅ done

**Goal:** define what a receipt looks like, how to sign it, and how to verify it cold.

**What shipped:**

- `RFCS/0001-receipt-format.md` — the human-readable spec for what a receipt is.
- `uniclaw-receipt` crate — Rust types for receipts, plus crypto sign/verify behind a feature flag.
- `uniclaw-verify` — a tiny standalone binary (~720 KB stripped) that takes a receipt JSON file and reports whether it verifies. Has no internet, no database, no dependencies on anything else.

**Why it matters:** before this phase, "verifiable" was a promise. After this phase, you can hand someone a JSON file and a public key, and they can verify it on an offline laptop.

→ See [steps/00-foundation-receipts.md](steps/00-foundation-receipts.md).

## Phase 1 — Shippable Core ✅ done (you are here, just finished)

**Goal:** build the trusted runtime core that produces receipts honestly.

This is the longest phase because it lays in everything the kernel needs: state machine, rules, budgets, approvals, storage, sleep cleanup. It shipped in 8 steps:

1. **Kernel state machine sketch** — the core that turns proposals into receipts.
2. **Constitution engine** — code-based rules separate from the model.
3. **Capability budgets** — algebraic spending limits.
4. **Receipt explainer** — turn receipts into plain English.
5. **Approval engine** — Pending receipts and operator response.
6. **Channel-aware approval routing** — how the operator gets asked.
7. **Receipt store** — chain-validated, issuer-pinned storage.
8. **Light Sleep cleanup** — the first sleep-stage memory pass.

After Phase 1: the trusted core is **internally** complete. You can wire it up and run it. What it cannot yet do is **show itself** to the outside world.

→ See [steps/01-kernel-state-machine.md](steps/01-kernel-state-machine.md) through [steps/08-light-sleep.md](steps/08-light-sleep.md) for one page per step.

## Phase 2 — Public Service 🚧 in progress

**Goal:** make receipts publicly verifiable through a URL.

**What's shipping:**

- ✅ **`uniclaw-host` crate** — an HTTP server that serves any receipt at `/receipts/<hash>`. Step 9. See [steps/09-public-url-hosting.md](steps/09-public-url-hosting.md).
- 🔜 A real, running instance at `https://uniclaw.dev/receipts/...`.
- 🔜 SQLite-backed receipt log so the server can hold receipts that outlive a process.
- 🔜 REM Sleep (daily reflection) and Deep Sleep (weekly integrity walk) round out the sleep-stage architecture.

**Why it matters:** **this is the wedge made tangible.** Every prior step is infrastructure that you have to read source code to appreciate. Phase 2 is when an auditor on the other side of the world can `curl` a URL and verify a receipt.

## Phase 3 — Tools and Secrets

**Goal:** let the agent actually do things, safely.

**What ships:**

- WASM tool host — run untrusted tools inside a sandbox.
- Container fallback for tools that need a real OS.
- "WASM in container" defense-in-depth for the riskiest tools.
- Secret broker — scoped secrets injected at the host boundary, never in prompts.
- Response-side leak scanner — looks for secret patterns in the model's output and redacts them before they leave the kernel.

**Why it matters:** this is where Uniclaw can finally call HTTP, run code, edit files — but with capability budgets enforced *and* with secrets that the model never sees in plaintext.

## Phase 4 — Federated Memory

**Goal:** memory that syncs across your devices, with provenance preserved.

**What ships:**

- CRDT-based memory sync (laptop ↔ phone ↔ server).
- Long-term memory and identity store.
- Vector index (WGSL-accelerated where possible).
- Provenance graph — typed edges between user → model → tool → output, queryable.

**Why it matters:** the agent is not on one device. Memory has to follow you, and the receipts have to follow the memory.

## Phase 5 — Mobile-Sovereign

**Goal:** Android-native, on-device, hardware-attested.

**What ships:**

- Android operator app (primary surface).
- Mobile-local quantized models (`q4_k_m` ≈ 1–3 B parameters on Snapdragon 8 Gen 3+ / Tensor G3+).
- Hardware attestation for sensor inputs (camera, mic, GPS) using the phone's secure enclave.
- Auto-routing between on-device and cloud models based on battery and connectivity.

**Why it matters:** privacy-first agents *cannot* be cloud-only. This is the wedge no other claw is even targeting.

## Phase 6 — Compliance + Provable Redaction

**Goal:** turn the audit chain into something a regulator will accept.

**What ships:**

- Redaction pipeline where each redactor emits its own proof (homomorphic redaction receipt).
- SOC2 / EU AI Act audit packs auto-generated from the receipt chain.
- Retention policy enforcement (configurable by data class).
- Optional ZK receipts for receipts that need to prove a property *without* revealing the underlying data.

**Why it matters:** "we have logs" is not enough. "Here is a cryptographic proof that section 5 of this document was redacted, and the rest is intact" is what regulated industries actually need.

## Phase 7 — Verified Delegation

**Goal:** safely delegate from one agent to another.

**What ships:**

- Multi-agent runtime where every cross-agent message is a signed receipt.
- Capability lease delegation across agents (your budget cannot be exceeded by anything you delegate to).
- Verified MCP bridge with streaming (fixes IronClaw's gap).
- Compatibility layers for OpenClaw, ZeroClaw, NanoClaw, IronClaw, OpenFang.

**Why it matters:** real-world agentic workflows involve agents calling other agents. Today that's a security disaster. With Uniclaw's budget algebra and signed inter-agent receipts, it stops being one.

## Phase 8 — Hardening + GA

**Goal:** general availability.

**What ships:**

- Formal verification of the kernel's state machine.
- Reproducible builds for the verifier and kernel.
- Threat-model document and red-team bug bounty.
- Stable wire-format guarantees for receipts.
- Versioned receipt format with backwards-compat through Phase 9.

**Why it matters:** at GA, "what runs in production" must be a thing you can audit, formally, top to bottom. This phase gets us there.

## Where we are right now

```
Phase 0 ✅ done
Phase 1 ✅ done
Phase 2 🚧 in progress (step 9 just landed)   ← you are here
Phase 3 ⬜ planned
Phase 4 ⬜ planned
Phase 5 ⬜ planned
Phase 6 ⬜ planned
Phase 7 ⬜ planned
Phase 8 ⬜ planned
```

The repo on GitHub will always have an up-to-date `CHANGELOG.md` showing every shipped step. The master plan (`UNICLAW_PLAN.md`) holds the canonical detailed version of this roadmap.

## How to follow along

- **Read the [step docs](steps/)** — one page per shipped step, in plain English.
- **Watch GitHub** — every step lands as a PR with a verification gate (build + test + clippy + benchmark).
- **Check `CHANGELOG.md`** — always reflects what is on `main`.
