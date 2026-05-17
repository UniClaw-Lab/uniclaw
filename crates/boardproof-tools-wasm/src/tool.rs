//! [`WasmTool`] — the public façade.
//!
//! Wraps either a core [`wasmtime::Module`] (for the v0 packed-i64
//! ABI from step 16a) or a [`wasmtime::component::Component`] (for
//! the typed Component Model surface added in step 16b). Both share
//! the same engine config, the same per-call resource limits, and
//! the same `Tool` trait implementation. Internal dispatch picks
//! the right call path based on the `WasmKind` the constructor
//! recorded.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{Engine, Linker, Module, Store, Trap};

use boardproof_receipt::Digest;
use boardproof_tools::{
    ApprovalPolicy, Tool, ToolCall, ToolError, ToolManifest, ToolMetadata, ToolOutput,
};

use boardproof_secrets::SecretBroker;
use boardproof_tools_http::HttpFetchTool;

use crate::bindings;
use crate::config::WasmConfig;
use crate::error::BuildError;
use crate::host::HostState;
use crate::limits::StoreData;

/// What kind of wasm artifact a [`WasmTool`] is wrapping.
///
/// - [`WasmKind::Core`] — 16a's packed-i64 ABI. Built via
///   [`WasmTool::from_wat`] / [`WasmTool::from_module_bytes`].
/// - [`WasmKind::Component`] — 16b's typed `tool` world.
///   Built via [`WasmTool::from_component_bytes`]. Exports only;
///   no host imports.
/// - [`WasmKind::ComponentWithHost`] — 16c's typed
///   `tool-with-host` world. Built via
///   [`WasmTool::from_component_bytes_with_host`]. The guest
///   imports `host` (capability-mediated http-fetch, broker-
///   backed secret-exists, log-message, now-millis) plus exports
///   `tool-api`. The constructor wires an `Arc<HttpFetchTool>` +
///   `Arc<dyn SecretBroker>` that satisfy the imports.
///
/// The three kinds use different bindgen output, different
/// linkers, and different calling conventions, so they're
/// modeled as separate variants rather than dynamically
/// dispatched.
enum WasmKind {
    Core(Module),
    Component(Component),
    ComponentWithHost {
        component: Component,
        http: Arc<HttpFetchTool>,
        broker: Arc<dyn SecretBroker>,
    },
}

/// A [`Tool`] backed by a sandboxed WebAssembly module.
///
/// Three constructors:
///
/// - [`WasmTool::from_wat`] — text form, used by tests and small
///   fixtures. Produces a [`WasmKind::Core`] tool using the 16a ABI.
/// - [`WasmTool::from_module_bytes`] — core wasm bytes. Same ABI.
/// - [`WasmTool::from_component_bytes`] — Component Model bytes
///   conforming to `wit/tool.wit`. Uses the typed
///   `tool-api.call(list<u8>) -> result<list<u8>, string>` surface.
///
/// Each call gets a fresh [`Store`] with the configured fuel,
/// memory limit, and epoch deadline applied. The engine and the
/// compiled module/component are shared across calls; only the
/// per-call state is fresh.
pub struct WasmTool {
    manifest: ToolManifest,
    config: WasmConfig,
    engine: Engine,
    kind: WasmKind,
    /// Background thread that increments the engine's epoch counter
    /// every `config.epoch_tick`. Driving `epoch_interruption` is
    /// what makes the wall-clock timeout fire.
    _ticker: Arc<EpochTicker>,
}

impl core::fmt::Debug for WasmTool {
    // Custom Debug because Engine + Module + Component don't impl Debug.
    // The `_ticker` field is deliberately omitted — its only state is a
    // stop-flag that's not meaningful to print.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind_label = match &self.kind {
            WasmKind::Core(_) => "core",
            WasmKind::Component(_) => "component",
            WasmKind::ComponentWithHost { .. } => "component-with-host",
        };
        f.debug_struct("WasmTool")
            .field("manifest", &self.manifest)
            .field("config", &self.config)
            .field("engine", &"<wasmtime::Engine>")
            .field("kind", &kind_label)
            .finish_non_exhaustive()
    }
}

impl WasmTool {
    /// Compile a tool from WebAssembly text (core wasm only).
    ///
    /// # Errors
    /// Returns [`BuildError::InvalidWat`] if the text fails to parse,
    /// [`BuildError::InvalidWasm`] if the resulting binary fails
    /// wasmtime validation, [`BuildError::EngineSetup`] if engine
    /// construction fails on this platform.
    pub fn from_wat(
        wat: &str,
        manifest: ToolManifest,
        config: WasmConfig,
    ) -> Result<Self, BuildError> {
        let bytes = wat::parse_str(wat).map_err(|e| BuildError::InvalidWat(e.to_string()))?;
        Self::from_module_bytes(&bytes, manifest, config)
    }

    /// Compile a tool from a core wasm module's binary form.
    ///
    /// # Errors
    /// See [`BuildError`].
    pub fn from_module_bytes(
        bytes: &[u8],
        manifest: ToolManifest,
        config: WasmConfig,
    ) -> Result<Self, BuildError> {
        let engine = build_engine()?;

        let module = Module::from_binary(&engine, bytes)
            .map_err(|e| BuildError::InvalidWasm(e.to_string()))?;

        // Validate the v0 core-wasm ABI by name.
        Self::check_required_core_exports(&module)?;

        let ticker = Arc::new(EpochTicker::start(&engine, config.epoch_tick));

        Ok(Self {
            manifest,
            config,
            engine,
            kind: WasmKind::Core(module),
            _ticker: ticker,
        })
    }

    /// Compile a tool from Component Model bytes conforming to
    /// `wit/tool.wit`. The component's `tool-api.call` export is
    /// driven by [`Tool::call`] on each invocation.
    ///
    /// # Errors
    /// [`BuildError::InvalidWasm`] if the bytes fail to parse as a
    /// valid Component, [`BuildError::EngineSetup`] if engine
    /// construction fails.
    ///
    /// Mismatched-world errors (component exports the wrong
    /// interface) currently surface at first call rather than at
    /// construction; wasmtime's `Component::new` accepts any
    /// valid Component bytes regardless of which world they
    /// implement, and the type check happens during
    /// [`bindings::Tool::instantiate`].
    pub fn from_component_bytes(
        bytes: &[u8],
        manifest: ToolManifest,
        config: WasmConfig,
    ) -> Result<Self, BuildError> {
        let engine = build_engine()?;

        let component =
            Component::new(&engine, bytes).map_err(|e| BuildError::InvalidWasm(e.to_string()))?;

        let ticker = Arc::new(EpochTicker::start(&engine, config.epoch_tick));

        Ok(Self {
            manifest,
            config,
            engine,
            kind: WasmKind::Component(component),
            _ticker: ticker,
        })
    }

    /// Compile a tool from Component Model bytes that conform to
    /// the `tool-with-host` world (16c). The component imports
    /// `host` (capability-mediated http-fetch, broker-backed
    /// secret-exists, log-message, now-millis) and exports
    /// `tool-api`.
    ///
    /// `http` is the [`HttpFetchTool`] instance backing the
    /// guest's `http-fetch` import. The guest's calls go through
    /// *this exact* tool — same allowlist, same SSRF gate, same
    /// bounded read. Whatever capability allowlist `http` was
    /// built with is the allowlist the guest sees.
    ///
    /// `broker` backs the guest's `secret-exists` import. The
    /// broker is also the one `http` uses for `bearer-header`
    /// auth injection — typically the operator constructs both
    /// with the same broker; we don't try to enforce that
    /// (there's no way to ask `HttpFetchTool` for its broker
    /// reference in v0).
    ///
    /// # Errors
    /// See [`BuildError`].
    pub fn from_component_bytes_with_host(
        bytes: &[u8],
        manifest: ToolManifest,
        config: WasmConfig,
        http: Arc<HttpFetchTool>,
        broker: Arc<dyn SecretBroker>,
    ) -> Result<Self, BuildError> {
        let engine = build_engine()?;

        let component =
            Component::new(&engine, bytes).map_err(|e| BuildError::InvalidWasm(e.to_string()))?;

        let ticker = Arc::new(EpochTicker::start(&engine, config.epoch_tick));

        Ok(Self {
            manifest,
            config,
            engine,
            kind: WasmKind::ComponentWithHost {
                component,
                http,
                broker,
            },
            _ticker: ticker,
        })
    }

    fn check_required_core_exports(module: &Module) -> Result<(), BuildError> {
        let mut have_memory = false;
        let mut have_alloc = false;
        let mut have_call = false;
        for ext in module.exports() {
            match ext.name() {
                "memory" => have_memory = true,
                "alloc" => have_alloc = true,
                "call" => have_call = true,
                _ => {}
            }
        }
        if !have_memory {
            return Err(BuildError::MissingExport {
                name: "memory".into(),
                detail: "the guest must export its linear memory as 'memory'".into(),
            });
        }
        if !have_alloc {
            return Err(BuildError::MissingExport {
                name: "alloc".into(),
                detail: "expected 'alloc(size: i32) -> i32' export".into(),
            });
        }
        if !have_call {
            return Err(BuildError::MissingExport {
                name: "call".into(),
                detail: "expected 'call(input_ptr: i32, input_len: i32) -> i64' export".into(),
            });
        }
        Ok(())
    }

    /// Read-only view of the runtime config.
    pub fn config(&self) -> &WasmConfig {
        &self.config
    }
}

/// Build the engine config used by every [`WasmTool`]. Three
/// runtime bounds wired in at engine level: fuel, epoch, Component
/// Model on. Memory cap is enforced per-store (different per call)
/// via [`MemoryLimiter`].
fn build_engine() -> Result<Engine, BuildError> {
    let mut wasm_config = wasmtime::Config::new();
    wasm_config.consume_fuel(true);
    wasm_config.epoch_interruption(true);
    // Component Model has been on by default in wasmtime ≥ 25, but
    // we set it explicitly so a future default change can't silently
    // disable our Component path.
    wasm_config.wasm_component_model(true);
    Engine::new(&wasm_config).map_err(|e| BuildError::EngineSetup(e.to_string()))
}

impl Tool for WasmTool {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    fn call(&self, tool_call: &ToolCall) -> Result<ToolOutput, ToolError> {
        match &self.kind {
            WasmKind::Core(module) => self.call_core(module, tool_call),
            WasmKind::Component(component) => self.call_component(component, tool_call),
            WasmKind::ComponentWithHost {
                component,
                http,
                broker,
            } => self.call_component_with_host(component, http, broker, tool_call),
        }
    }

    fn approval_policy(&self, _call: &ToolCall) -> ApprovalPolicy {
        self.manifest.default_approval
    }
}

impl WasmTool {
    /// Per-call store factory. Builds a fresh [`StoreData`] (memory
    /// cap + empty WASI context, no host) and applies the fuel +
    /// epoch deadline. Used by `call_core` and `call_component`.
    fn fresh_store(&self) -> Result<Store<StoreData>, ToolError> {
        self.fresh_store_with(StoreData::new(self.config.max_memory_bytes))
    }

    /// Per-call store factory with host imports configured. Used
    /// by `call_component_with_host`. The `HostState` carries the
    /// `Arc<HttpFetchTool>` + `Arc<dyn SecretBroker>` plus the
    /// per-call accumulators.
    fn fresh_store_with_host(&self, host_state: HostState) -> Result<Store<StoreData>, ToolError> {
        self.fresh_store_with(StoreData::with_host(
            self.config.max_memory_bytes,
            host_state,
        ))
    }

    fn fresh_store_with(&self, data: StoreData) -> Result<Store<StoreData>, ToolError> {
        let mut store = Store::new(&self.engine, data);
        store.limiter(|s| s);
        store
            .set_fuel(self.config.fuel)
            .map_err(|e| ToolError::Failed(format!("set_fuel: {e}")))?;
        store.set_epoch_deadline(self.config.epoch_deadline());
        Ok(store)
    }

    /// 16a core-wasm call path. Allocates input via the guest's
    /// `alloc`, writes input bytes, calls `call`, unpacks the
    /// returned i64, reads output bytes back.
    fn call_core(&self, module: &Module, tool_call: &ToolCall) -> Result<ToolOutput, ToolError> {
        let mut store = self.fresh_store()?;

        // No host imports in v0 — empty linker. Step 16c will populate
        // this with capability-checked syscalls + secret broker bridges.
        let linker = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| map_wasm_error(&e))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| ToolError::Failed("module missing 'memory' export".into()))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| {
                ToolError::Failed(format!("alloc export wrong shape (want i32 -> i32): {e}"))
            })?;

        let call_fn = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "call")
            .map_err(|e| {
                ToolError::Failed(format!(
                    "call export wrong shape (want (i32, i32) -> i64): {e}"
                ))
            })?;

        let input_len = i32::try_from(tool_call.input.len()).map_err(|_| {
            ToolError::Failed(format!(
                "input length {} exceeds i32::MAX (wasm32 limit)",
                tool_call.input.len()
            ))
        })?;

        let input_ptr = alloc
            .call(&mut store, input_len)
            .map_err(|e| map_wasm_error(&e))?;
        if input_ptr < 0 {
            return Err(ToolError::Failed(
                "guest 'alloc' returned a negative pointer".into(),
            ));
        }

        let input_offset = usize::try_from(input_ptr).map_err(|_| {
            ToolError::Failed("guest 'alloc' returned a non-representable pointer".into())
        })?;
        memory
            .write(&mut store, input_offset, &tool_call.input)
            .map_err(|e| ToolError::Failed(format!("write input to guest memory: {e}")))?;

        let packed = call_fn
            .call(&mut store, (input_ptr, input_len))
            .map_err(|e| map_wasm_error(&e))?;

        // Unpack high 32 = ptr, low 32 = len. Cast through u64 to
        // keep the bit pattern; sign-extension would corrupt high
        // bytes for valid 31-bit pointers.
        #[allow(clippy::cast_sign_loss)]
        let packed_u = packed as u64;
        let out_ptr_u32 = (packed_u >> 32) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let out_len_u32 = (packed_u & 0xFFFF_FFFF) as u32;
        let out_ptr = usize::try_from(out_ptr_u32).expect("u32 fits in usize on supported targets");
        let out_len = usize::try_from(out_len_u32).expect("u32 fits in usize on supported targets");

        let out_end = out_ptr.checked_add(out_len).ok_or_else(|| {
            ToolError::Failed(format!(
                "output range overflow: ptr={out_ptr} len={out_len}"
            ))
        })?;

        let mem_data = memory.data(&store);
        let bytes = mem_data
            .get(out_ptr..out_end)
            .ok_or_else(|| {
                ToolError::Failed(format!(
                    "output range [{out_ptr}..{out_end}) outside guest memory ({} bytes)",
                    mem_data.len()
                ))
            })?
            .to_vec();

        let output_hash = Digest(*blake3::hash(&bytes).as_bytes());
        Ok(ToolOutput {
            bytes,
            output_hash,
            metadata: ToolMetadata::default(),
        })
    }

    /// 16b Component Model call path. Drives the bindgen-generated
    /// `tool-api.call(list<u8>) -> result<list<u8>, string>` surface.
    /// The canonical ABI handles host↔guest memory transfer for us;
    /// no `alloc` / `memory` / packed-i64 plumbing needed.
    fn call_component(
        &self,
        component: &Component,
        tool_call: &ToolCall,
    ) -> Result<ToolOutput, ToolError> {
        let mut store = self.fresh_store()?;

        // Linker stub: the v0 `tool` world imports nothing of OURS,
        // but a Rust→WASM Component built against `wasm32-wasip2`
        // automatically picks up WASI imports from std (whether the
        // program touches them or not). We add WASI's empty linker
        // shim so the imports exist — guests still can't reach any
        // real syscall in 16b because we never construct a WASI
        // context with permissions. Step 16c will replace this with
        // capability-checked BoardProof-specific imports.
        let mut linker = ComponentLinker::<StoreData>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|e| ToolError::Failed(format!("add WASI to linker: {e}")))?;

        let instance = bindings::tool::Tool::instantiate(&mut store, component, &linker)
            .map_err(|e| map_wasm_error(&e))?;

        let result = instance
            .boardproof_tool_tool_api()
            .call_call(&mut store, &tool_call.input)
            .map_err(|e| map_wasm_error(&e))?;

        // The Component Model `result<list<u8>, string>` becomes a
        // Rust `Result<Vec<u8>, String>`. The Err arm is a guest-
        // chosen error message — surface it as `ToolError::Failed`
        // with the message preserved (callers may pattern-match on it).
        let bytes = result.map_err(|msg| ToolError::Failed(format!("guest: {msg}")))?;

        let output_hash = Digest(*blake3::hash(&bytes).as_bytes());
        Ok(ToolOutput {
            bytes,
            output_hash,
            metadata: ToolMetadata::default(),
        })
    }

    /// 16c Component-with-host call path. Drives the same
    /// `tool-api.call(...)` export as 16b's `call_component`,
    /// but the Component is allowed to *import* `host` and the
    /// linker wires those imports to [`HostState`]'s
    /// implementations. After the call returns, the per-call
    /// `secrets_used` accumulator is harvested into
    /// [`ToolOutput::metadata`] so the kernel can mint
    /// `secret_used` provenance edges.
    fn call_component_with_host(
        &self,
        component: &Component,
        http: &Arc<HttpFetchTool>,
        broker: &Arc<dyn SecretBroker>,
        tool_call: &ToolCall,
    ) -> Result<ToolOutput, ToolError> {
        let host_state = HostState::new(Arc::clone(http), Arc::clone(broker));
        let mut store = self.fresh_store_with_host(host_state)?;

        // The 16c linker provides BOTH WASI (for std-using
        // Components, same as 16b) AND the BoardProof host imports.
        let mut linker = ComponentLinker::<StoreData>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|e| ToolError::Failed(format!("add WASI to linker: {e}")))?;
        bindings::with_host::ToolWithHost::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            |state: &mut StoreData| state,
        )
        .map_err(|e| ToolError::Failed(format!("add host imports to linker: {e}")))?;

        let instance =
            bindings::with_host::ToolWithHost::instantiate(&mut store, component, &linker)
                .map_err(|e| map_wasm_error(&e))?;

        let result = instance
            .boardproof_tool_tool_api()
            .call_call(&mut store, &tool_call.input)
            .map_err(|e| map_wasm_error(&e))?;

        // Harvest the host-side accumulators BEFORE consuming the
        // store. `secrets_used` is the deduplicated union of
        // every secret reference name the guest's host calls
        // touched.
        let secrets_used = store
            .data()
            .host_state()
            .map(HostState::secrets_used)
            .unwrap_or_default();

        let bytes = result.map_err(|msg| ToolError::Failed(format!("guest: {msg}")))?;
        let output_hash = Digest(*blake3::hash(&bytes).as_bytes());

        Ok(ToolOutput {
            bytes,
            output_hash,
            metadata: ToolMetadata { secrets_used },
        })
    }
}

/// Translate a wasmtime error into [`ToolError`].
///
/// - [`Trap::OutOfFuel`] → `Failed("fuel exhausted")`. Deterministic
///   CPU bound fired.
/// - [`Trap::Interrupt`] → `Timeout`. Wall-clock bound fired (epoch
///   deadline reached). Maps to [`ToolError::Timeout`] because
///   that's exactly what it is — the trait surface from step 13.
/// - Other traps (memory OOB, unreachable, division by zero, etc.)
///   → `Failed("wasm trap: <variant>")`.
/// - Non-trap errors (engine internals, instantiation failures) →
///   `Failed("wasm: <message>")`.
fn map_wasm_error(err: &wasmtime::Error) -> ToolError {
    if let Some(trap) = err.downcast_ref::<Trap>() {
        match trap {
            Trap::OutOfFuel => ToolError::Failed("fuel exhausted".into()),
            Trap::Interrupt => ToolError::Timeout,
            other => ToolError::Failed(format!("wasm trap: {other}")),
        }
    } else {
        ToolError::Failed(format!("wasm: {err}"))
    }
}

/// Background thread that drives [`Engine::increment_epoch`]. See
/// 16a for the rationale (per-tool, detached, exits via stop-flag
/// poll on next sleep wake-up).
struct EpochTicker {
    stop: Arc<AtomicBool>,
}

impl EpochTicker {
    fn start(engine: &Engine, tick: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let engine_clone = engine.clone();
        thread::spawn(move || {
            while !stop_for_thread.load(Ordering::Acquire) {
                thread::sleep(tick);
                engine_clone.increment_epoch();
            }
        });
        Self { stop }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_wasm_error_translates_traps() {
        let e = wasmtime::Error::msg("boom");
        let translated = map_wasm_error(&e);
        match translated {
            ToolError::Failed(msg) => assert!(msg.contains("boom")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
