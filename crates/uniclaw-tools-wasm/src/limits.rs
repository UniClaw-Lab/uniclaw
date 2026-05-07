//! [`StoreData`] — the per-call store state.
//!
//! Combines:
//! - The memory cap (enforced via [`wasmtime::ResourceLimiter`]'s
//!   `memory_growing` callback) — refuses guest memory growth past
//!   the configured ceiling.
//! - A WASI context — exists so a Rust→WASM Component built against
//!   `wasm32-wasip2` can satisfy its automatic WASI imports without
//!   the host actually granting any real capability. The ctx is
//!   constructed empty (no preopens, no env, no stdio passthrough);
//!   guests still can't reach a real syscall in 16b because every
//!   capability they'd need would have been opted-in via
//!   `WasiCtxBuilder` and we never call those builders.
//!
//! For core wasm calls (16a path), the WASI fields are present but
//! unused — they cost a `ResourceTable::new()` per store and that's
//! it. Splitting into two store-data types per kind would cost more
//! in code complexity than the saving is worth.

use wasmtime::ResourceLimiter;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

// `WasiCtx` doesn't impl `Debug` so we hand-roll one. The internals
// of the WASI context aren't useful in diagnostic output anyway.
pub(crate) struct StoreData {
    pub(crate) max_memory_bytes: usize,
    wasi: WasiCtx,
    table: ResourceTable,
}

impl core::fmt::Debug for StoreData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreData")
            .field("max_memory_bytes", &self.max_memory_bytes)
            .finish_non_exhaustive()
    }
}

impl StoreData {
    pub(crate) fn new(max_memory_bytes: usize) -> Self {
        // Empty WASI context: no preopened directories, no env vars,
        // no stdio. The Component sees imports it can call but those
        // calls would surface as errors / no-ops because no capability
        // was granted. Step 16c replaces this with capability-checked
        // Uniclaw imports.
        Self {
            max_memory_bytes,
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
        }
    }
}

impl ResourceLimiter for StoreData {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // `desired` is the new total size in bytes (not the delta).
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Tables hold function references; v0 doesn't constrain them
        // separately.
        Ok(true)
    }
}

impl WasiView for StoreData {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
