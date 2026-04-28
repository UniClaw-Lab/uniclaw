# Phase 1 Step 5 — The Approval Engine

> **Phase:** 1 — Shippable Core
> **PR:** #4
> **Crate introduced:** `uniclaw-approval`
> **Crates updated:** `uniclaw-kernel`, `uniclaw-constitution` (added `RuleVerdict::RequireApproval`)

## What is this step?

This step makes Uniclaw able to **pause an action and ask a human**. When a Constitution rule says `RequireApproval`, the kernel stops, mints a **Pending** receipt, and waits. When the operator answers (Approved or Denied), the kernel mints the **final** receipt — chained to the Pending one with a provenance edge.

Before this step the kernel could only say *yes* or *no*. After this step it can say *wait*.

## Where does this fit in the whole Uniclaw?

The approval engine is the bridge between the **automatic** and the **human-supervised** parts of the runtime. The Constitution can mark certain actions as needing approval. The kernel writes a Pending receipt. Some routing layer (Step 6) carries the question to the operator. The operator's answer comes back to the kernel as a `KernelEvent::ResolveApproval`.

```
Action       -> Constitution (RequireApproval) -> Kernel mints Pending receipt
                                                                |
                                                                v
                                                       (operator gets asked)
                                                                |
                                                                v
                          (yes/no answer) -> Kernel mints Approved or Denied receipt
                                                                |
                                                                v
                                                  (chained back to Pending)
```

## What problem does it solve technically?

Several problems at once:

### 1. "How do we cleanly handle 'wait for human' inside a kernel that owns a chain?"

Naively, you'd hold pending requests in kernel memory and resume them when the answer arrives. That works on one machine but fails as soon as the kernel restarts, or as soon as you have a multi-process setup. Our solution: **the kernel does not store pending state**. The caller holds the Pending receipt and the original Proposal, and resubmits both when the operator decides. The kernel's job is to verify the resubmission is genuine and to mint the next receipt.

### 2. "How do we prevent an attacker from forging an approval?"

An attacker who can submit `ResolveApproval` events could try to bypass the human. So the kernel runs a four-step **authenticity gate** before honoring the resolution:

1. The Pending receipt's Ed25519 signature must verify under the issuer in the receipt.
2. The issuer must be **this kernel's public key**. A receipt from another kernel cannot be resolved here.
3. The Pending receipt's `decision` must actually be `Pending` — not Allowed, not Approved.
4. The resubmitted Proposal's `action` must match the action recorded in the Pending receipt — same `kind`, same `target`, same `input_hash`.

If any check fails, the kernel returns `KernelError::ResolveApprovalRejected(...)` and **does not advance the chain**. The receipt log will not contain a forged event.

### 3. "How do we record that the approval led to the action?"

We add a **provenance edge** to the final receipt: `from = "receipt:<pending_hash>"`, `to = "decision"`, `kind = "approval_response"`. An auditor can follow the link from the final receipt to the Pending one and see the whole story.

### 4. "What about the budget? When do we charge?"

A naive budget charge at proposal time would be wrong — the action might never run if the operator denies it. So we charge **only at the final decision**, not at Pending time. This adds a subtle case: what if the operator says yes, but the budget has *exhausted* in the meantime (a long queue, parallel actions)? The kernel re-checks the budget at approve time and produces `OutcomeKind::DeniedByBudgetAtApproveTime` if the lease no longer covers the charge.

## How does it work in plain words?

Two new pieces:

### `ApprovalDecision`

The operator's answer:

```rust
pub enum ApprovalDecision {
    Approved,
    Denied,
}
```

Lives in the small `uniclaw-approval` crate. Tiny by design — it should be embeddable from anywhere.

### `KernelEvent::ResolveApproval`

The operator's response carried back to the kernel:

```rust
pub struct Approval {
    pub pending_receipt:  Receipt,
    pub original_proposal: Proposal,
    pub response:         ApprovalDecision,
}

KernelEvent::resolve(approval)  // ergonomic constructor
```

When the kernel handles a `ResolveApproval`, it:

1. Runs the authenticity gate (steps 1–4 above).
2. If the response is `Approved`, re-checks the budget.
3. Mints the final receipt — Approved, Denied, or Denied-by-budget-at-approve-time.
4. Adds the `approval_response` provenance edge to the final receipt's `provenance`.

## Why this design choice and not another?

- **Why not store pending state in the kernel?** Stateless kernel = simple kernel. The caller already needs the Pending receipt to render a UI to the operator; carrying it back adds zero burden.
- **Why a four-step gate and not just "verify signature"?** Because a valid Pending receipt from a *different* kernel is still cryptographically valid — the issuer check stops cross-kernel injection. And a valid Pending receipt with a *different* action substituted is also signature-valid for the original action — the action-match check catches that.
- **Why re-check budget at approve time?** Because the lease may have been spent down on parallel actions. The kernel re-checks; the receipt records `DeniedByBudgetAtApproveTime`; the audit trail tells the whole story.
- **Why a separate `uniclaw-approval` crate for one enum?** So that Slack bots, dashboards, mobile apps, etc. can depend on the enum without pulling in the entire kernel.

## What you can do with this step today

- Author a Constitution rule with `verdict = "RequireApproval"`.
- Submit a Proposal that matches the rule. Get back a Pending receipt.
- Display the receipt to your operator.
- Submit `KernelEvent::resolve(Approval { pending, original, response: Approved })`.
- Get back the final receipt, with a chained provenance edge to the Pending one.
- Forge nothing — every authenticity-gate failure produces a typed error, no chain advance.

## In summary

Step 5 makes Uniclaw able to ask. The kernel does not store the question; the caller holds it. The kernel verifies the answer is real before honoring it. Every approval becomes a receipt with a provable link back to the question. This is what makes "the operator agreed to this action" something an auditor can verify cold, not just take on faith.
