# Phase 1 Step 8 — Light Sleep Cleanup Pass

> **Phase:** 1 — Shippable Core
> **PR:** #7
> **Crate introduced:** `uniclaw-sleep`

## What is this step?

This step introduces **scheduled background cleanup**, the first of three "sleep stages" Uniclaw will use to keep itself tidy.

Light Sleep runs every hour (in production). It walks through registered cleanup tasks — drop expired session state, reap timed-out capability leases, normalize JSON, vacuum storage — and writes one signed receipt for the whole pass.

The pass is **best-effort** and **idempotent**. A cleaner that fails does not stop the others. The receipt records what happened.

## Where does this fit in the whole Uniclaw?

Sleep-stage memory (master plan §16.3) is the project's "brand moment" — *Uniclaw is the first agent runtime that sleeps.* Three stages are planned:

| Stage | Frequency | Purpose |
|---|---|---|
| **Light Sleep** | hourly | cleanup (this step) |
| **REM Sleep** | daily | reflection (future) |
| **Deep Sleep** | weekly | promotion + integrity walk (future) |

Each stage produces its own receipt. The receipt is the proof that the schedule fired and what it did.

```
hourly:    [ Light Sleep cleanup pass ]   --> receipt: $kernel/sleep/light
daily:     [ REM Sleep reflection     ]   --> receipt: $kernel/sleep/rem    (future)
weekly:    [ Deep Sleep integrity walk ]  --> receipt: $kernel/sleep/deep   (future)
```

## What problem does it solve technically?

Three problems:

### 1. "How do subsystems register cleanup work without coupling?"

The new `Cleanable` trait:

```rust
pub trait Cleanable {
    fn name(&self) -> &str;
    fn clean(&mut self) -> Result<CleanupReport, CleanupError>;
}
```

Any subsystem can implement it. A session store, a budget lease tracker, a graph store — each implements `Cleanable` with a stable name. Light Sleep doesn't know what these subsystems do internally; it just calls `clean()` on each and aggregates the results.

The orchestrator function:

```rust
pub fn run_light_sleep(cleaners: &mut [&mut dyn Cleanable]) -> LightSleepReport;
```

is a thin loop: walk the slice, call each, collect outcomes. Failures are recorded, not propagated.

### 2. "What does a *good* receipt for an empty cleanup pass look like?"

In v0, no subsystem has yet registered as a cleaner — there's nothing in production for Light Sleep to clean. So the typical pass right now has *zero* cleaners. Should we skip the receipt then?

**No.** The receipt itself is the proof that the schedule fired on time. A long quiet period in the audit chain with no `$kernel/sleep/light` receipts would mean *something is wrong*. So we always mint a receipt, even for an empty pass:

```
Action kind:   $kernel/sleep/light
Action target: cleaners=0 rows=0 bytes=0 failed=0
Decision:      Allowed
Provenance:    [] (no cleaners registered)
```

As subsystems start registering Cleanable impls, this receipt will accumulate provenance edges and rows-affected counts.

### 3. "How does the receipt link back to specific cleaners?"

Each cleaner pass becomes one provenance edge:

| Outcome | `from` | `to` | `kind` |
|---|---|---|---|
| Success | `cleaner:store/sessions` | `rows=12 bytes=4096` | `light_sleep_pass` |
| Failure | `cleaner:budget/leases` | `error: storage offline` | `light_sleep_failure` |

An auditor reading the receipt can attribute every row deleted and every byte reclaimed to a specific subsystem, and see at a glance if any subsystem failed.

## How does it work in plain words?

A scheduled run:

```rust
// Some scheduler decides it is time for an hourly pass.
let mut session_cleaner = SessionCleaner::new(&db);
let mut lease_cleaner   = LeaseCleaner::new(&leases);

// Each subsystem does its work; the orchestrator collects outcomes.
let report: LightSleepReport = run_light_sleep(&mut [
    &mut session_cleaner,
    &mut lease_cleaner,
]);

// The kernel turns the report into a signed audit receipt.
let outcome = kernel.handle(KernelEvent::run_light_sleep(report))?;

// outcome.kind == OutcomeKind::LightSleepCompleted { failed_cleaners: 0 }
```

The kernel's part is small: take the report, build an action, build provenance edges from each `CleanerPass`, mint a receipt with `decision = Allowed`, `kind = "$kernel/sleep/light"`. No new chain machinery; it reuses the same `mint` path the rest of the kernel uses.

A failing cleaner does not abort the pass. The pass continues. The failure appears as a `light_sleep_failure` provenance edge, with the cleaner's error message in the `to` field. The outcome surfaces `failed_cleaners` as a count for the caller to react to (alerts, etc.).

## Why this design choice and not another?

- **Why mint a receipt for an empty pass?** Because a *missing* receipt would be the alarming case. The receipt is the heartbeat.
- **Why best-effort instead of all-or-nothing?** Because Light Sleep runs on the same machine as the kernel. One subsystem failing should never halt the whole runtime.
- **Why the kernel signs, not the sleep crate?** Same trust principle as everywhere else: the kernel owns the signing key. Light Sleep gives the kernel a *report* and the kernel decides if it merits a receipt. (Today: always yes.)
- **Why a slice of `&mut dyn Cleanable` instead of a registry?** Because the scheduler that *runs* Light Sleep is the right place to know which cleaners to invoke — different deployments will register different cleaners. No global registry; the caller passes them in.

## What you can do with this step today

- Implement `Cleanable` for any subsystem you write.
- Call `run_light_sleep` against your cleaners on a schedule.
- Hand the resulting `LightSleepReport` to the kernel as a `KernelEvent::RunLightSleep`.
- Observe the audit receipt that appears in the chain.

## Performance baseline

On x86_64 Linux:

- 0 cleaners: **32.65 µs/call** (just sign + leaf-hash; in line with the kernel baseline)
- 3 cleaners: **40.09 µs/call**
- 10 cleaners: **46.04 µs/call** (~1.3 µs/cleaner of String allocation overhead)

A pass with 1000 cleaners would take roughly 1.5 ms. Light Sleep is comfortably background work.

## In summary

Step 8 starts the sleep-stage architecture, with the simplest of the three (cleanup) shipping first. The receipt-for-an-empty-pass design is what lets us ship this *now*, before any cleanup-needing subsystems exist — the schedule firing is itself the audit-worthy event. As later steps add session stores, lease GC, and graph cleanup, they slot in by implementing `Cleanable`, and the same Light Sleep receipt grows real meaning.
