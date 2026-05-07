//! [`WasmTool`] — the public façade.
//!
//! Wraps a compiled [`wasmtime::Module`] plus a shared [`Engine`]
//! and applies per-call resource limits via [`crate::limits::MemoryLimiter`]
//! and [`wasmtime::Store`]'s fuel + epoch deadline machinery.
//!
//! See the crate-level docs for the v0 guest ABI.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use wasmtime::{Engine, Linker, Module, Store, Trap};

use uniclaw_receipt::Digest;
use uniclaw_tools::{
    ApprovalPolicy, Tool, ToolCall, ToolError, ToolManifest, ToolMetadata, ToolOutput,
};

use crate::config::WasmConfig;
use crate::error::BuildError;
use crate::limits::MemoryLimiter;

/// A [`Tool`] backed by a sandboxed WebAssembly module.
///
/// Construct via [`WasmTool::from_wat`] (text form, used by tests
/// and small fixtures) or [`WasmTool::from_module_bytes`] (binary,
/// used in production).
///
/// Each call gets a fresh [`Store`] with the configured fuel,
/// memory limit, and epoch deadline applied. The engine and the
/// compiled module are shared across calls; only the per-call
/// state is fresh.
pub struct WasmTool {
    manifest: ToolManifest,
    config: WasmConfig,
    engine: Engine,
    module: Module,
    /// Background thread that increments the engine's epoch counter
    /// every `config.epoch_tick`. Driving `epoch_interruption` is
    /// what makes the wall-clock timeout fire. Carried as `Arc` so
    /// `WasmTool: Send + Sync` and so cloning the tool (a future
    /// extension) doesn't spawn a second ticker.
    _ticker: Arc<EpochTicker>,
}

impl core::fmt::Debug for WasmTool {
    // Custom Debug because Engine + Module don't impl Debug.
    // The `_ticker` field is deliberately omitted — its only
    // state is a stop-flag that's not meaningful to print.
    // `finish_non_exhaustive` signals the omission to the reader.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WasmTool")
            .field("manifest", &self.manifest)
            .field("config", &self.config)
            .field("engine", &"<wasmtime::Engine>")
            .field("module", &"<wasmtime::Module>")
            .finish_non_exhaustive()
    }
}

impl WasmTool {
    /// Compile a tool from WebAssembly text.
    ///
    /// # Errors
    /// Returns [`BuildError::InvalidWat`] if the text fails to
    /// parse, [`BuildError::InvalidWasm`] if the resulting binary
    /// fails wasmtime validation, [`BuildError::EngineSetup`] if
    /// engine construction fails on this platform.
    pub fn from_wat(
        wat: &str,
        manifest: ToolManifest,
        config: WasmConfig,
    ) -> Result<Self, BuildError> {
        let bytes = wat::parse_str(wat).map_err(|e| BuildError::InvalidWat(e.to_string()))?;
        Self::from_module_bytes(&bytes, manifest, config)
    }

    /// Compile a tool from a wasm module's binary form.
    ///
    /// # Errors
    /// See [`BuildError`].
    pub fn from_module_bytes(
        bytes: &[u8],
        manifest: ToolManifest,
        config: WasmConfig,
    ) -> Result<Self, BuildError> {
        // Engine config: the three runtime bounds wired in at engine
        // level (fuel + epoch). Memory cap is enforced per-store via
        // the ResourceLimiter, since it's also a per-call setting.
        let mut wasm_config = wasmtime::Config::new();
        wasm_config.consume_fuel(true);
        wasm_config.epoch_interruption(true);
        let engine =
            Engine::new(&wasm_config).map_err(|e| BuildError::EngineSetup(e.to_string()))?;

        let module = Module::from_binary(&engine, bytes)
            .map_err(|e| BuildError::InvalidWasm(e.to_string()))?;

        // Validate the v0 ABI by name. Signature checks happen at
        // call time when wasmtime resolves the typed export — that's
        // where the most accurate error message comes from. Here we
        // only catch obvious "no such export" cases up-front so a
        // misshaped module fails at construction, not on first call.
        Self::check_required_exports(&module)?;

        let ticker = Arc::new(EpochTicker::start(&engine, config.epoch_tick));

        Ok(Self {
            manifest,
            config,
            engine,
            module,
            _ticker: ticker,
        })
    }

    fn check_required_exports(module: &Module) -> Result<(), BuildError> {
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

impl Tool for WasmTool {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    fn call(&self, tool_call: &ToolCall) -> Result<ToolOutput, ToolError> {
        // Per-call store with the resource limits applied. Each call
        // gets a fresh memory + fresh fuel + fresh epoch deadline —
        // no state leaks between calls.
        let limiter = MemoryLimiter {
            max_memory_bytes: self.config.max_memory_bytes,
        };
        let mut store = Store::new(&self.engine, limiter);
        store.limiter(|s| s);
        store
            .set_fuel(self.config.fuel)
            .map_err(|e| ToolError::Failed(format!("set_fuel: {e}")))?;
        store.set_epoch_deadline(self.config.epoch_deadline());

        // No host imports in v0 — empty linker. Step 16c will
        // populate this with capability-checked syscalls + secret
        // broker bridges.
        let linker = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, &self.module)
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

        // Convert the input length to i32. Inputs > 2 GiB can't be
        // expressed in the guest's pointer type anyway; this is a
        // hard limit independent of `max_memory_bytes`.
        let input_len = i32::try_from(tool_call.input.len()).map_err(|_| {
            ToolError::Failed(format!(
                "input length {} exceeds i32::MAX (wasm32 limit)",
                tool_call.input.len()
            ))
        })?;

        // Ask the guest to allocate space, write the input, run.
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

        // Unpack high 32 = ptr, low 32 = len.
        // Cast through u64 to keep the bit pattern; sign-extension
        // would corrupt high bytes for valid 31-bit pointers.
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

    fn approval_policy(&self, _call: &ToolCall) -> ApprovalPolicy {
        self.manifest.default_approval
    }
}

/// Translate a wasmtime error into [`ToolError`].
///
/// The two we care to distinguish:
/// - [`Trap::OutOfFuel`] → `Failed("fuel exhausted")`. Deterministic
///   CPU bound fired.
/// - [`Trap::Interrupt`] → `Timeout`. Wall-clock bound fired (epoch
///   deadline reached). Maps to [`ToolError::Timeout`] because that's
///   exactly what it is — the trait surface from step 13.
///
/// Anything else (memory out-of-bounds, unreachable, division by
/// zero, bad indirect call, etc.) → `Failed("wasm trap: <variant>")`.
/// Non-trap errors (engine internals, instantiation failures) →
/// `Failed("wasm: <message>")`.
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

/// Background thread that drives [`Engine::increment_epoch`].
///
/// Owning a `Engine` (cheap clone — internal Arc) inside the thread
/// keeps it alive at least until the thread exits. The `stop`
/// flag is the way the parent tells the thread to terminate; the
/// thread also exits if its sleep wakes up to `stop=true`.
///
/// Thread is detached (no `join` on Drop) — joining would block
/// the dropping thread for up to one tick. Since the thread holds
/// no resources beyond a clone of the Engine and a reference to
/// `stop`, leaking it for a tick is harmless.
struct EpochTicker {
    stop: Arc<AtomicBool>,
}

impl EpochTicker {
    fn start(engine: &Engine, tick: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let engine_clone = engine.clone();
        thread::spawn(move || {
            // Loop until told to stop. Sleep granularity = tick.
            // We don't try to do high-precision timing; epoch
            // interruption only needs "fires within roughly one
            // tick of the deadline."
            while !stop_for_thread.load(Ordering::Acquire) {
                thread::sleep(tick);
                engine_clone.increment_epoch();
            }
            // engine_clone drops here, releasing this thread's
            // contribution to the engine's refcount.
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
    // Most behavior is exercised in tests/runtime.rs (integration
    // tests with .wat fixtures). The unit tests here only cover
    // helpers that don't need a compiled module.
    use super::*;

    #[test]
    fn map_wasm_error_translates_traps() {
        // We can't easily fabricate every Trap variant from outside
        // wasmtime, so we just check the catch-all path doesn't
        // panic and produces something useful.
        let e = wasmtime::Error::msg("boom");
        let translated = map_wasm_error(&e);
        match translated {
            ToolError::Failed(msg) => assert!(msg.contains("boom")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
