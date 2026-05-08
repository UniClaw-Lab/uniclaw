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
//!   guests still can't reach a real syscall in 16b/16c because
//!   every WASI capability they'd need would have been opted in via
//!   `WasiCtxBuilder` and we never call those builders.
//! - An optional [`crate::host::HostState`] — present for tools
//!   constructed with `WasmTool::from_component_bytes_with_host`,
//!   absent for 16a/16b paths. Carries the [`uniclaw_tools_http::HttpFetchTool`]
//!   reference, the secret broker, and the per-call accumulators
//!   (`secrets_used`, log entries, `http-fetch` counts).
//!
//! For 16a/16b paths, the WASI fields are present but unused, and
//! `host` is `None`. Splitting into two store-data types per kind
//! would cost more in code complexity than the saving is worth.

use wasmtime::ResourceLimiter;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::host::HostState;

// `WasiCtx` doesn't impl `Debug` so we hand-roll one. The internals
// of the WASI context aren't useful in diagnostic output anyway.
pub(crate) struct StoreData {
    pub(crate) max_memory_bytes: usize,
    wasi: WasiCtx,
    table: ResourceTable,
    host: Option<HostState>,
}

impl core::fmt::Debug for StoreData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreData")
            .field("max_memory_bytes", &self.max_memory_bytes)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl StoreData {
    /// Build a store-data with no host imports configured. Used
    /// by the 16a core-wasm path and the 16b Component path.
    pub(crate) fn new(max_memory_bytes: usize) -> Self {
        Self {
            max_memory_bytes,
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            host: None,
        }
    }

    /// Build a store-data with host imports configured. Used by
    /// the 16c Component-with-host path. The `HostState` carries
    /// the `Arc<HttpFetchTool>` + `Arc<dyn SecretBroker>` plus
    /// per-call accumulators.
    pub(crate) fn with_host(max_memory_bytes: usize, host: HostState) -> Self {
        Self {
            max_memory_bytes,
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            host: Some(host),
        }
    }

    /// Read-only view of the host state. `None` for 16a/16b paths.
    pub(crate) fn host_state(&self) -> Option<&HostState> {
        self.host.as_ref()
    }

    /// Mutable view of the host state. The bindgen-generated
    /// `host::Host for StoreData` impl uses this to delegate.
    pub(crate) fn host_mut(&mut self) -> Option<&mut HostState> {
        self.host.as_mut()
    }
}

impl ResourceLimiter for StoreData {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
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
