# Phase 1 Step 3 — Capability Budgets

> **Phase:** 1 — Shippable Core
> **PR:** #3 (bundled with constitution and explainer)
> **Crate introduced:** `uniclaw-budget`

## What is this step?

This step gives the kernel **numerical spending limits** for every action: bytes of network traffic, file writes, LLM tokens, wall-clock milliseconds, and total uses. Once a limit is hit, the kernel **refuses** to allow more.

Budgets are not advisory. They are enforced by the kernel. An action that would exceed the budget gets a Denied receipt, with the budget rule recorded.

## Where does this fit in the whole Uniclaw?

Budgets live alongside the Constitution. After the Constitution decides the action is permitted, the kernel asks: "do you have the budget?" If yes, the action proceeds. If no, the kernel mints a Denied receipt explaining which dimension was exhausted.

```
Constitution says OK?   ->   Budget says OK?   ->   Mint Allowed receipt
        |                          |
       no                         no
        v                          v
   Deny receipt               Deny receipt
   (rule cited)               (budget reason cited)
```

## What problem does it solve technically?

Three problems:

### 1. "How do I cap what an action can use?"

In other agent runtimes, "limits" are usually advisory or middleware-implemented. They can be bypassed if the tool author forgets. In Uniclaw, the kernel itself runs the budget check before producing an Allowed receipt — there is no path that skips it.

### 2. "How do limits compose when one tool delegates to another?"

This is the trickier problem. Suppose Tool A has a 1000-byte network budget. It calls Tool B. How much of A's budget should B get?

If we naively give B "1000 bytes," B might use 1000 bytes *and then return to A*, which then also uses bytes — exceeding the original 1000 limit.

We solve this with **reservation semantics**: when A delegates to B with a 200-byte sub-budget, A's lease is debited 200 bytes upfront. B can use up to 200 bytes. A is left with 800 to use after B returns. The total can never exceed A's parent budget.

This is what we mean by "**capability budget algebra**." Budgets compose like algebra — they always sum correctly.

### 3. "How does the receipt record budget consumption?"

When the kernel charges a lease, it returns the post-charge state alongside the receipt. The caller threads this back into the next call. The audit trail can show: lease X had 1000 bytes; after action Y, lease X had 950 bytes.

## How does it work in plain words?

The five resource dimensions:

```rust
pub struct ResourceUse {
    pub net_bytes:    u64,  // bytes of network IO
    pub file_writes:  u64,  // file system writes
    pub llm_tokens:   u64,  // tokens spent on the model
    pub wall_ms:      u64,  // wall-clock ms
    pub uses:         u64,  // raw call count
}

pub struct Budget {
    pub net_bytes:   u64,
    pub file_writes: u64,
    pub llm_tokens:  u64,
    pub wall_ms:     u64,
    pub max_uses:    u64,
}
```

A `CapabilityLease` ties a budget to a unique `LeaseId` and tracks how much has been consumed:

```rust
pub struct CapabilityLease {
    pub id:       LeaseId,
    pub budget:   Budget,
    pub consumed: ResourceUse,
}

impl CapabilityLease {
    pub fn try_charge(&mut self, charge: &ResourceUse) -> Result<(), BudgetError>;
    pub fn delegate(&mut self, sub_budget: Budget) -> Result<CapabilityLease, BudgetError>;
    pub fn remaining(&self) -> ResourceUse;
}
```

`try_charge` is the basic operation: try to add `charge` to `consumed`. If it would exceed `budget`, return a typed `BudgetError` (one of `NetBytesExhausted`, `FileWritesExhausted`, …). The lease is *not* mutated on error.

`delegate` is the algebra: try to reserve `sub_budget` from this lease, then return a new child lease. The parent's `consumed` is increased by `sub_budget` upfront — that's the reservation. The child lease has its own budget and tracks its own consumption.

### A complete example

```rust
let mut parent = CapabilityLease::new(LeaseId::ZERO, Budget {
    net_bytes: 1000, file_writes: 10, llm_tokens: 0, wall_ms: 0, max_uses: 100,
});

// Tool A delegates 200 bytes of network to Tool B.
let mut child = parent.delegate(Budget {
    net_bytes: 200, file_writes: 0, llm_tokens: 0, wall_ms: 0, max_uses: 10,
}).unwrap();

assert_eq!(parent.remaining().net_bytes, 800);  // reserved upfront
assert_eq!(child.remaining().net_bytes,  200);

child.try_charge(&ResourceUse { net_bytes: 150, .. }).unwrap();
assert_eq!(child.remaining().net_bytes, 50);
// parent's view does NOT see this charge — it already reserved.
assert_eq!(parent.remaining().net_bytes, 800);
```

## Why this design choice and not another?

- **Why five fixed dimensions instead of arbitrary key-value?** Because every dimension has its own semantics for how to charge and what "exhausted" means. A typed struct enforces that all five are considered.
- **Why reservation upfront instead of "settle on return"?** Because tools can crash, hang, or timeout. With reservation, the parent's budget is correctly accounted even if the child never returns.
- **Why typed `BudgetError` and not a string?** Because the kernel records the budget error in the receipt as a virtual rule (`$kernel/budget/net_bytes_exhausted`). The variant name becomes part of the audit trail.
- **Why `try_charge` instead of `charge`?** "Try" makes it explicit that the caller must handle the rejection. There is no panic path.

## What you can do with this step today

- Attach a `CapabilityLease` to a `Proposal` so the kernel enforces budget on each action.
- Delegate sub-budgets to nested calls and have the math just work.
- Inspect the lease state after each action to see how much budget remains.
- Get a Denied receipt with a virtual `$kernel/budget/<dimension>_exhausted` rule when limits are hit, so auditors can see what ran out.

## In summary

Step 3 makes "spending limits" real. The kernel enforces them. Sub-tools cannot exceed their parent's allocation. Every charge produces an audit-recordable receipt. This is one of the things you cannot get from a generic agent runtime; it requires the kernel to own the gate.
