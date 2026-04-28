# Phase 1 Step 6 — Channel-Aware Approval Routing

> **Phase:** 1 — Shippable Core
> **PR:** #5
> **Crate introduced:** `uniclaw-router`

## What is this step?

This step builds the **delivery layer** for approval prompts. When the kernel mints a Pending receipt, **someone has to ask the operator**. This step decides *how* and *where* the operator gets asked.

In v0, only a CLI router ships. You run it in a terminal; when an action needs approval, the prompt shows up in your terminal; you type `approve` or `deny`. Future routers (Slack, email, mobile push) plug in through the same trait.

## Where does this fit in the whole Uniclaw?

The approval router sits **between** the kernel and the human. It is not part of the kernel itself — the kernel is happy to mint Pending receipts forever; it has no opinion about who answers them. The router takes the Pending receipt, presents it to the operator on whatever channel makes sense, and brings back the answer.

```
Kernel mints Pending receipt
         |
         v
   ApprovalRouter::route(&pending, &original_proposal)
         |
         v   (operator decides)
         v
   ApprovalDecision::Approved or Denied
         |
         v
   Kernel handles ResolveApproval
```

This separation is the same trick we used in Step 5 — keep the kernel stateless and decoupled. The kernel doesn't care if the answer comes from a terminal, Slack, a mobile app, or a web dashboard. It just cares that the answer is authentic.

## What problem does it solve technically?

Three problems:

### 1. "How does the operator actually see the question?"

Without a router, the Pending receipt sits in memory forever. The router is the channel-bridge. It can be as simple as printing to stdout and reading from stdin (the CLI router) or as fancy as an interactive Slack message with buttons (future).

### 2. "How do we keep the trait surface stable across many channels?"

The `ApprovalRouter` trait is intentionally tiny:

```rust
pub trait ApprovalRouter {
    fn route(
        &mut self,
        pending: &Receipt,
        original_proposal: &Proposal,
    ) -> Result<ApprovalDecision, RouterError>;
}
```

Synchronous. Takes `&mut self` so implementations can own buffered IO without interior mutability. Returns a typed error so the orchestrator can distinguish "operator denied" from "channel broken" — these are different things.

### 3. "How do we glue the kernel + router together without the caller writing the loop every time?"

We ship a free function:

```rust
pub fn evaluate_with_routing<S, C, K, R>(
    kernel: &mut Kernel<S, C, K>,
    router: &mut R,
    proposal: Proposal,
) -> Result<KernelOutcome, OrchestrationError>
where ...
```

It does the dance:

1. `kernel.handle(KernelEvent::evaluate(proposal_clone))`.
2. If the outcome is `OutcomeKind::PendingApproval`, call `router.route(&pending_receipt, &original_proposal)`.
3. Submit `KernelEvent::resolve(Approval { ... })` back to the kernel.
4. Return the final receipt (or the original Pending outcome if no approval was needed).

Callers get a one-call API: "evaluate this proposal, doing whatever approval routing is needed, and give me the final receipt."

## How does it work in plain words?

The CLI router (`CliApprovalRouter<R: BufRead, W: Write>`) renders a Pending receipt to a writer and reads a line from a reader:

```
Pending action requires approval:
  Action kind:   shell.exec
  Action target: ls
  Issued at:     2026-04-27T12:00:00Z
  Receipt id:    a1b2c3d4...
Approve this action? [yes/no/abort]:
```

Inputs `yes` / `y` / `approve` map to `ApprovalDecision::Approved`. `no` / `n` / `deny` map to `ApprovalDecision::Denied`. `abort` raises `RouterError::Aborted` so the orchestrator can stop without minting a final receipt.

Generic over `R: BufRead, W: Write` so tests use byte-vector readers/writers — no real terminal needed.

## Why this design choice and not another?

### The "adapter scarcity" rule

We deliberately ship **only one router** in this PR. Slack, email, webhook, and mobile push routers are deferred. The rule (master plan §24.5) is: an additional channel adapter ships only after **≥10 GitHub-thumbs of demand**. We don't want to be the project with 12 half-maintained Slack adapters.

### Why synchronous?

The CLI router needs no async; it blocks on stdin. A future Slack router will likely need async, but we'd rather offer it as a separate trait (or add an async layer on top) than complicate the simple case for the future case.

### Why does the router get the Proposal AND the Receipt?

Because the Pending receipt records the action but not the budget or the provenance edges the caller carried. The Proposal carries all of that. A rich UI can show both: "the agent wanted to do X (action), here's how it got to that decision (provenance), here's how much budget it would use (charge)."

### Why a typed `RouterError`?

The orchestrator must distinguish channel failures from operator denials. `RouterError::Denied` ≠ `RouterError::ChannelBroken`. Audit trails should never collapse the two.

## What you can do with this step today

- Run a kernel with the CLI router in a terminal. Submit shell.exec proposals; get prompted; answer interactively.
- Plug in your own `ApprovalRouter` implementation by implementing one trait method.
- Write tests that drive the router with synthetic stdin/stdout buffers.

```rust
// Pseudocode for a real session
let mut kernel = Kernel::new(my_signer, my_clock, load_constitution());
let mut router = CliApprovalRouter::new(stdin_lock, stdout_lock);

let outcome = evaluate_with_routing(
    &mut kernel,
    &mut router,
    Proposal::with_lease(/* ... */),
)?;

println!("Final outcome: {:?}", outcome.kind);
```

## In summary

Step 6 makes the approval engine actually *reach* the operator. The trait is tiny on purpose. Only the CLI router ships in v0. The orchestrator hides the kernel↔router dance behind one call. Future channels plug in through the same trait — but only when there is real demand, not speculative breadth.
