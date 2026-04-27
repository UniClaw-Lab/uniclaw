//! Sleep stages for Uniclaw — Light, REM, and Deep Sleep.
//!
//! Master plan §16.3 introduces *sleep-as-architecture*: the runtime
//! schedules background passes that consolidate state. Three stages are
//! planned:
//!
//! - **Light Sleep** (hourly): cleanup. Drops expired session state, reaps
//!   TTL'd capability leases, collapses duplicate provenance edges,
//!   normalizes JSON, dedupes artifact blobs, vacuums the storage backend.
//!   Idempotent and cheap. No model. Pure SQL/Rust. (§16.3.1)
//! - **REM Sleep** (daily): reflection. Re-embeds memories, detects
//!   duplicate facts, generates pattern summaries, restructures the
//!   provenance graph. Optionally model-assisted. (§16.3.2)
//! - **Deep Sleep** (weekly): promotion + integrity walk. Promotes
//!   frequently-recalled facts, archives cold data, walks the Merkle audit
//!   chain end-to-end. (§16.3.3)
//!
//! ## Current shape — Light Sleep only
//!
//! This crate currently ships only the Light Sleep architecture: a
//! [`Cleanable`] trait, per-cleaner [`CleanupReport`], and the
//! [`LightSleepReport`] aggregate that [`run_light_sleep`] produces. REM
//! and Deep Sleep arrive in follow-up steps once their backing subsystems
//! (provenance graph, federated memory CRDT) land.
//!
//! ## Why a receipt for an empty pass
//!
//! In v0 there is no persistent session state, no `SQLite`, and no provenance
//! graph — so a Light Sleep pass with **zero registered cleaners** is the
//! norm. The pass is still meaningful: the kernel mints a Light Sleep
//! receipt that proves the scheduled pass ran on time. Once cleanup
//! subsystems start registering, the same receipt records what they did.
//!
//! ## Where this fits
//!
//! `uniclaw-sleep` is the **Spine** layer's background-task surface
//! (master plan §9). The kernel consumes the [`LightSleepReport`] this
//! crate produces and turns it into a signed audit receipt — see
//! `uniclaw-kernel`'s `KernelEvent::RunLightSleep`.
//!
//! ## Adopt-don't-copy
//!
//! Sleep-stage memory is net-new in this shape. No source borrowed from
//! any of the nine reference claw runtimes — none of them have it. The
//! cleanup-pass *idea* generalizes long-known background-GC patterns from
//! database engines (`PostgreSQL`'s autovacuum, `SQLite`'s incremental
//! VACUUM); we mirror that *idea*, not their code.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// A subsystem that participates in Light Sleep.
///
/// Implementations are expected to be **idempotent and cheap** (master
/// plan §16.3.1). A cleaner may legitimately do nothing — for example, a
/// session store with no expired rows returns
/// `CleanupReport::EMPTY`. Cleaners must not perform model calls or
/// network I/O.
///
/// The trait takes `&mut self` so the cleaner can freely mutate its own
/// internal state, but it must not require coordination across cleaners —
/// `run_light_sleep` invokes them sequentially in the order given.
pub trait Cleanable {
    /// Stable identifier for this cleaner. Used in the Light Sleep
    /// receipt's provenance edges (`cleaner:<name>`) so an audit reader
    /// can attribute rows-affected counts to specific subsystems.
    ///
    /// Must be stable across runs and unique per subsystem. Suggested
    /// format: `<crate>/<unit>` (e.g. `"store/sessions"`,
    /// `"budget/leases"`).
    fn name(&self) -> &str;

    /// Run one cleanup pass. Returns what was cleaned, or an error if the
    /// pass could not run. A cleaner returning `Err` does **not** abort
    /// the overall Light Sleep pass — `run_light_sleep` records the
    /// failure in the report and moves on.
    ///
    /// # Errors
    ///
    /// Implementation-defined. Convert your concrete error to
    /// [`CleanupError`] via its `String` message.
    fn clean(&mut self) -> Result<CleanupReport, CleanupError>;
}

/// What a single cleaner did during one Light Sleep pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Number of rows / records / entries affected (deleted, collapsed,
    /// or normalized — implementation-defined).
    pub rows_affected: u64,
    /// Approximate bytes reclaimed by the pass.
    pub bytes_reclaimed: u64,
}

impl CleanupReport {
    /// A no-op pass — cleaner ran but found nothing to do.
    pub const EMPTY: Self = Self {
        rows_affected: 0,
        bytes_reclaimed: 0,
    };
}

/// Why a cleaner could not complete its pass.
///
/// Carries a human-readable message rather than a typed enum because each
/// cleaner has its own failure modes; the orchestrator only needs enough
/// information to record the failure in the audit receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupError {
    /// Short human-readable reason. Goes into the Light Sleep receipt
    /// provenance edge for the failed cleaner.
    pub message: String,
}

impl CleanupError {
    /// Construct a new error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for CleanupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for CleanupError {}

/// Aggregated outcome of one Light Sleep pass — one entry per registered
/// cleaner, in the order they ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightSleepReport {
    /// One [`CleanerPass`] per registered cleaner, in invocation order.
    pub passes: Vec<CleanerPass>,
}

/// One cleaner's contribution to a Light Sleep report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanerPass {
    /// Cleaner identifier (`Cleanable::name`).
    pub name: String,
    /// Either the cleaner's [`CleanupReport`] or the error message it
    /// returned. Failures are recorded, not propagated.
    pub outcome: Result<CleanupReport, CleanupError>,
}

impl LightSleepReport {
    /// An empty report — the pass ran but no cleaners were registered.
    /// Receiving such a report is the normal state in v0.
    #[must_use]
    pub fn empty() -> Self {
        Self { passes: Vec::new() }
    }

    /// Number of cleaners that participated in this pass.
    #[must_use]
    pub fn cleaner_count(&self) -> usize {
        self.passes.len()
    }

    /// Total `rows_affected` across all successful cleaners.
    #[must_use]
    pub fn total_rows_affected(&self) -> u64 {
        self.passes
            .iter()
            .filter_map(|p| p.outcome.as_ref().ok())
            .map(|r| r.rows_affected)
            .sum()
    }

    /// Total `bytes_reclaimed` across all successful cleaners.
    #[must_use]
    pub fn total_bytes_reclaimed(&self) -> u64 {
        self.passes
            .iter()
            .filter_map(|p| p.outcome.as_ref().ok())
            .map(|r| r.bytes_reclaimed)
            .sum()
    }

    /// Number of cleaners whose pass failed.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.passes.iter().filter(|p| p.outcome.is_err()).count()
    }

    /// True when every registered cleaner returned `Ok`. Vacuously true
    /// when there are no cleaners.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed_count() == 0
    }
}

/// Run one Light Sleep pass over `cleaners` in order, collecting each
/// cleaner's outcome into a [`LightSleepReport`].
///
/// A failing cleaner is **recorded**, not propagated — Light Sleep is a
/// best-effort background pass. The kernel mints a single receipt for the
/// whole pass; the per-cleaner outcomes appear as provenance edges so an
/// auditor can see which subsystems failed and why.
pub fn run_light_sleep(cleaners: &mut [&mut dyn Cleanable]) -> LightSleepReport {
    let mut passes = Vec::with_capacity(cleaners.len());
    for cleaner in cleaners {
        let name = String::from(cleaner.name());
        let outcome = cleaner.clean();
        passes.push(CleanerPass { name, outcome });
    }
    LightSleepReport { passes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// In-memory cleaner that always succeeds with the configured report.
    struct StubCleaner {
        name: String,
        report: CleanupReport,
        calls: u32,
    }

    impl StubCleaner {
        fn new(name: &str, rows: u64, bytes: u64) -> Self {
            Self {
                name: name.to_string(),
                report: CleanupReport {
                    rows_affected: rows,
                    bytes_reclaimed: bytes,
                },
                calls: 0,
            }
        }
    }

    impl Cleanable for StubCleaner {
        fn name(&self) -> &str {
            &self.name
        }
        fn clean(&mut self) -> Result<CleanupReport, CleanupError> {
            self.calls += 1;
            Ok(self.report)
        }
    }

    /// Cleaner that always returns an error.
    struct FailingCleaner {
        name: String,
        message: String,
    }

    impl Cleanable for FailingCleaner {
        fn name(&self) -> &str {
            &self.name
        }
        fn clean(&mut self) -> Result<CleanupReport, CleanupError> {
            Err(CleanupError::new(self.message.clone()))
        }
    }

    #[test]
    fn empty_pass_produces_empty_report() {
        let report = run_light_sleep(&mut []);
        assert_eq!(report.cleaner_count(), 0);
        assert_eq!(report.total_rows_affected(), 0);
        assert_eq!(report.total_bytes_reclaimed(), 0);
        assert_eq!(report.failed_count(), 0);
        assert!(report.all_succeeded(), "vacuously true with no cleaners");
    }

    #[test]
    fn successful_cleaners_aggregate_totals() {
        let mut a = StubCleaner::new("store/sessions", 5, 100);
        let mut b = StubCleaner::new("budget/leases", 3, 50);
        let mut c = StubCleaner::new("graph/edges", 7, 250);
        let report = run_light_sleep(&mut [&mut a, &mut b, &mut c]);

        assert_eq!(report.cleaner_count(), 3);
        assert_eq!(report.total_rows_affected(), 15);
        assert_eq!(report.total_bytes_reclaimed(), 400);
        assert_eq!(report.failed_count(), 0);
        assert!(report.all_succeeded());

        // Order is preserved.
        assert_eq!(report.passes[0].name, "store/sessions");
        assert_eq!(report.passes[1].name, "budget/leases");
        assert_eq!(report.passes[2].name, "graph/edges");

        // Each cleaner ran exactly once.
        assert_eq!(a.calls, 1);
        assert_eq!(b.calls, 1);
        assert_eq!(c.calls, 1);
    }

    #[test]
    fn failing_cleaner_is_recorded_and_does_not_abort_others() {
        let mut a = StubCleaner::new("store/sessions", 5, 100);
        let mut b = FailingCleaner {
            name: "graph/edges".to_string(),
            message: "lock contention".to_string(),
        };
        let mut c = StubCleaner::new("budget/leases", 3, 50);
        let report = run_light_sleep(&mut [&mut a, &mut b, &mut c]);

        assert_eq!(report.cleaner_count(), 3);
        assert_eq!(report.failed_count(), 1);
        assert!(!report.all_succeeded());

        // Successful cleaners' totals do not include the failure.
        assert_eq!(report.total_rows_affected(), 8);
        assert_eq!(report.total_bytes_reclaimed(), 150);

        // The failure is preserved with its message.
        let failure = report.passes[1].outcome.as_ref().unwrap_err();
        assert_eq!(failure.message, "lock contention");

        // The cleaner *after* the failure still ran.
        assert_eq!(c.calls, 1);
    }

    #[test]
    fn idempotent_repeat_is_safe() {
        // Light Sleep is idempotent; running it twice in a row over the
        // same stub cleaners is well-defined.
        let mut a = StubCleaner::new("store/sessions", 5, 100);
        let r1 = run_light_sleep(&mut [&mut a]);
        let r2 = run_light_sleep(&mut [&mut a]);
        assert_eq!(r1.passes[0].outcome, r2.passes[0].outcome);
        assert_eq!(a.calls, 2);
    }
}
