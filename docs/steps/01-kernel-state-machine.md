# Phase 1 Step 1 — The Kernel State Machine

> **Phase:** 1 — Shippable Core
> **PR:** #2
> **Crate introduced:** `uniclaw-kernel`

## What is this step?

This step builds the **trusted runtime core** — the small, central piece of code that owns the chain of receipts. We call it the **kernel**.

Think of it like the engine of a car: every other part of the car connects to the engine, but the engine itself is one focused thing that does one well-understood job.

## Where does this fit in the whole Uniclaw?

The kernel is the **Spine** layer of Uniclaw's architecture (master plan §9 splits Uniclaw into Brain / Spine / Hands / Skin / Sense). Every action the agent takes flows through the kernel:

```
Brain (model)  --proposes-->  Kernel  --produces-->  Receipt
                              ^   |
                              |   |
              Hands (tools)  -+   +->  Stored, verified, served
              Skin  (channels)
              Sense (sensors)
```

The kernel is the **only** thing in the whole runtime that holds the signing key and produces receipts. Everything else feeds it inputs and reads its outputs. This is intentional: by keeping the trust-bearing code in one small place, we can audit it carefully.

## What problem does it solve technically?

Two related problems:

### 1. "Who actually creates the receipts?"

Without a kernel, every subsystem could try to create its own receipts, with their own signing keys, with their own chain. The result would be a forest of mini-chains nobody could correlate. The kernel is the single producer — one signing key, one chain, one canonical history.

### 2. "How does the chain stay correct under concurrent updates?"

Receipts must come out in order, with each `prev_hash` pointing to the previous `leaf_hash`. If two parts of the runtime tried to mint receipts at the same time, the chain would break. The kernel owns a small **state machine** (`KernelState { sequence, prev_hash }`) that advances atomically with each receipt produced. Only one receipt is minted at a time, in order.

## How does it work in plain words?

The kernel exposes a small surface:

```rust
let mut kernel = Kernel::new(signer, clock, constitution);
let outcome = kernel.handle(KernelEvent::evaluate(proposal))?;
//          ↑                                         ↑
//   the signed receipt          the action to consider
//   + a "kind" code
```

Three abstract dependencies, injected:

- **`Signer`** — produces an Ed25519 signature over a receipt body. In tests this is a stub. In production this is a real key-holder (today: an `ed25519-dalek::SigningKey`; tomorrow: an HSM).
- **`Clock`** — produces a timestamp. Injected so tests can be deterministic.
- **`Constitution`** — the rules engine (Phase 1 Step 2). Tells the kernel whether to allow, deny, or require approval.

That's it. No global state. No singletons. No mutex on a static. The kernel is an ordinary Rust struct you construct, hand events to, and read outcomes from.

### What `handle` does, in order

1. Reads the proposal.
2. Asks the Constitution: "what should I do with this action?"
3. If a budget lease was provided, tries to charge the action's cost.
4. Builds a receipt body with the final decision.
5. Computes the leaf hash from the body.
6. Calls the signer to produce the signature.
7. Advances state: `sequence += 1`, `prev_hash = leaf_hash`.
8. Returns the signed receipt + an `OutcomeKind` describing how the decision was reached.

If anything goes wrong in a way that should *not* produce a receipt (e.g., a forged input), the kernel returns a `KernelError` instead — without advancing the chain. This matters: an attacker should not be able to make the kernel mint a receipt just by submitting bad input.

## Why this design choice and not another?

- **Why generic over `Signer`/`Clock`/`Constitution` instead of trait objects?** Zero-cost. Tests use stub types; production uses real ones; both compile to direct calls with no virtual dispatch.
- **Why does the kernel not store a database?** Storage is a separate concern (Step 7's receipt store). The kernel is *only* the trusted minting core.
- **Why does the kernel re-check budgets at approve time?** Because a Pending receipt may sit in the operator's queue for hours. The lease may exhaust in the meantime. Re-checking at approve time catches that case, and the resulting Denied receipt records *why*.
- **Why is `Kernel::handle` synchronous, not async?** The kernel itself does no I/O. The signer might (HSM), but that's the signer's concern. Async leaks would have made the trusted core harder to reason about.

## What you can do with this step today

- Construct a `Kernel` and hand it `Proposal` events.
- Get back signed receipts in a verifiable chain.
- Inspect the `OutcomeKind` to see *why* the decision was reached, even when the receipt's `decision` field alone wouldn't tell you.

```rust
match outcome.kind {
    OutcomeKind::Allowed                          => println!("All good."),
    OutcomeKind::DeniedByConstitution             => println!("A rule blocked it."),
    OutcomeKind::DeniedByBudget(_)                => println!("Out of budget."),
    OutcomeKind::PendingApproval                  => println!("Operator must approve."),
    OutcomeKind::ApprovedAfterPending             => println!("Approved by operator."),
    OutcomeKind::DeniedByOperator                 => println!("Rejected by operator."),
    OutcomeKind::DeniedByBudgetAtApproveTime(_)   => println!("Approved, but no budget left."),
    OutcomeKind::AllowedAsDenied                  => println!("Caller pre-decided Denied."),
    OutcomeKind::LightSleepCompleted{ .. }        => println!("Sleep cleanup pass done."),
}
```

## In summary

Step 1 is the spinal cord. It is small on purpose. It does one job — produce signed, chained receipts honestly — and refuses to do anything else. Every later step plugs into the kernel by giving it inputs (rules, budgets, approvals, sleep reports) and reading its outputs (receipts).
