//! [`WasmConfig`] — runtime knobs for [`crate::WasmTool`].
//!
//! Every field is a *bound*, not a target. The runtime never tries
//! to use the full budget; the guest runs to completion and the
//! bounds only fire on misbehaviour.

use core::time::Duration;

/// Resource limits applied to every [`crate::WasmTool::call`]
/// invocation.
///
/// All four bounds are independent — a guest must satisfy *all* of
/// them. The first one tripped halts execution and surfaces as a
/// [`uniclaw_tools::ToolError`].
///
/// Defaults aim at short, deterministic computations (parsing,
/// hashing, token counting). For heavier workloads, construct a
/// custom config rather than relying on defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmConfig {
    /// CPU bound, expressed in wasmtime fuel units. Each guest
    /// instruction consumes fuel deterministically; on exhaustion
    /// the call traps and the host returns
    /// [`uniclaw_tools::ToolError::Failed`].
    ///
    /// Default: `100_000_000` (~100 ms of compute on most hardware
    /// for tight integer loops; varies by instruction mix).
    pub fuel: u64,

    /// Hard cap on guest linear memory in bytes. The runtime's
    /// [`wasmtime::ResourceLimiter`] refuses `memory.grow` past
    /// this size; the guest sees `-1` as the result and (typically)
    /// traps shortly after.
    ///
    /// Default: 16 MiB. Picked because it's larger than realistic
    /// JSON/string workloads and small enough that an OOM tool
    /// can't take down the host.
    pub max_memory_bytes: usize,

    /// Wall-clock timeout. After this elapses, the next epoch tick
    /// makes the deadline-passed check trap; the host returns
    /// [`uniclaw_tools::ToolError::Timeout`]. Wall-clock (not
    /// CPU-time) so a guest can't burn the fuel budget at one
    /// instruction every 10 ms.
    ///
    /// Default: 5 seconds.
    pub timeout: Duration,

    /// How often the engine's epoch counter is incremented by the
    /// background ticker thread. Smaller = tighter timeout
    /// resolution, more wakeups; larger = looser resolution,
    /// fewer wakeups.
    ///
    /// `timeout / epoch_tick` is the deadline value passed to
    /// [`wasmtime::Store::set_epoch_deadline`].
    ///
    /// Default: 100 ms — yields ~50 ticks for a 5-second timeout,
    /// which is plenty of resolution for human-perceptible bounds.
    pub epoch_tick: Duration,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            fuel: 100_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            timeout: Duration::from_secs(5),
            epoch_tick: Duration::from_millis(100),
        }
    }
}

impl WasmConfig {
    /// Compute the epoch deadline (number of ticks) implied by
    /// `timeout / epoch_tick`. Always at least 1 — a zero deadline
    /// would trap before any guest instruction ran.
    pub(crate) fn epoch_deadline(&self) -> u64 {
        let ticks = self.timeout.as_nanos() / self.epoch_tick.as_nanos().max(1);
        u64::try_from(ticks).unwrap_or(u64::MAX).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_finite_and_nonzero() {
        let c = WasmConfig::default();
        assert!(c.fuel > 0);
        assert!(c.max_memory_bytes > 0);
        assert!(c.timeout > Duration::ZERO);
        assert!(c.epoch_tick > Duration::ZERO);
    }

    #[test]
    fn epoch_deadline_floor_is_one() {
        // Even if timeout < epoch_tick, the deadline must be >= 1
        // (a zero deadline traps before any instruction).
        let c = WasmConfig {
            timeout: Duration::from_millis(10),
            epoch_tick: Duration::from_millis(100),
            ..WasmConfig::default()
        };
        assert_eq!(c.epoch_deadline(), 1);
    }

    #[test]
    fn epoch_deadline_for_default_config() {
        // 5s / 100ms = 50 ticks.
        let c = WasmConfig::default();
        assert_eq!(c.epoch_deadline(), 50);
    }

    #[test]
    fn epoch_deadline_handles_overflow() {
        // Pathological: huge timeout, tiny tick. The cast to u64
        // saturates rather than panicking.
        let c = WasmConfig {
            timeout: Duration::from_secs(u64::MAX / 2),
            epoch_tick: Duration::from_nanos(1),
            ..WasmConfig::default()
        };
        // Just check it didn't panic and returned something
        // representable.
        let _ = c.epoch_deadline();
    }
}
