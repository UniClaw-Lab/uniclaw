//! WebAssembly tool runtime for BoardProof — the sandboxed substrate
//! every untrusted tool will eventually run on.
//!
//! Phase 3 step 4 / step 16a (master plan §28). Ships the **runtime
//! skeleton**: `WasmTool` wraps a [`wasmtime`] module, applies
//! deterministic CPU + memory + wall-clock bounds, and implements the
//! [`boardproof_tools::Tool`] trait already proven by `HttpFetchTool`
//! (step 14) and the secret broker (step 15). Step 16b layers the
//! Component Model on top via WIT + `bindgen!`; this step uses **core
//! wasm only** so the runtime infrastructure (fuel, memory, epoch) can
//! be validated without Component Model bindgen edge cases blocking
//! diagnosis.
//!
//! ## What's here
//!
//! - [`WasmTool`] — the public façade. Constructed from a wasm module
//!   (text via [`WasmTool::from_wat`] or bytes via
//!   [`WasmTool::from_module_bytes`]) plus a [`ToolManifest`].
//!   Implements [`boardproof_tools::Tool`] and runs the guest under
//!   per-call resource limits.
//! - [`WasmConfig`] — knobs: fuel budget (CPU bound), max memory
//!   bytes (heap bound), wall-clock timeout (epoch deadline),
//!   epoch tick granularity. Sensible defaults aim for short
//!   computation; real deployments tune these per tool.
//! - [`BuildError`] — module compilation failures (invalid wasm,
//!   missing required exports). Distinct from runtime
//!   [`boardproof_tools::ToolError`] so callers can tell "this module
//!   never loaded" from "this call failed."
//!
//! ## Required guest ABI (v0)
//!
//! Core wasm with the following exports:
//!
//! - `memory: memory` — the guest's linear memory.
//! - `alloc(size: i32) -> i32` — host calls this to reserve space
//!   for the input bytes; returns a pointer into linear memory.
//! - `call(input_ptr: i32, input_len: i32) -> i64` — the entry
//!   point. Returns a packed `(output_ptr << 32) | output_len`.
//!   On error the guest may trap (`unreachable`); the host catches
//!   the trap and returns [`boardproof_tools::ToolError::Failed`].
//!
//! No host imports in v0. The guest is a pure compute black box:
//! no I/O, no clock, no randomness. Capability-mediated host
//! imports land in step 16c, after Component Model (16b) settles.
//!
//! ## Sandbox guarantees (v0)
//!
//! - **CPU bound** via [`wasmtime::Config::consume_fuel`] +
//!   [`wasmtime::Store::set_fuel`]. Each instruction consumes fuel;
//!   the call traps on exhaustion. Fuel is deterministic — same
//!   input, same fuel cost — so the bound is reproducible across
//!   runs.
//! - **Memory bound** via a [`wasmtime::ResourceLimiter`]
//!   implementation that refuses `memory.grow` past
//!   [`WasmConfig::max_memory_bytes`].
//! - **Wall-clock bound** via [`wasmtime::Config::epoch_interruption`]
//!   plus [`wasmtime::Store::set_epoch_deadline`], driven by a
//!   background ticker thread that calls
//!   [`wasmtime::Engine::increment_epoch`] every
//!   [`WasmConfig::epoch_tick`]. Wall-clock-bounded so an attacker
//!   can't "spend" the fuel budget arbitrarily slowly (epoch fires
//!   on real time, not instructions).
//!
//! All three are independent — a malicious or buggy guest needs to
//! satisfy *all* of them (fast enough, small enough, finite enough)
//! to escape. The first one that trips wins.
//!
//! ## What's *not* here (deliberate)
//!
//! - **No host imports** — the guest cannot do I/O, fetch secrets,
//!   touch files, or open sockets. v0 is pure compute. (Capability
//!   enforcement and broker access are wired in a future step;
//!   they reuse this crate's runtime, no breaking changes.)
//! - **No Component Model** — step 16b layers
//!   [`wasmtime::component`] on top of this skeleton. Doing them
//!   together would conflate "does the runtime work" with "does
//!   bindgen produce the right glue."
//! - **No persistent compilation cache** — every constructor
//!   compiles the module from scratch. Acceptable for short
//!   computations; future tuning if cold-start dominates.
//! - **No streaming I/O / async invocation.** [`Tool::call`] is
//!   sync (decided at step 13).
//!
//! ## Adopt-don't-copy
//!
//! - **`IronClaw`'s WIT Component Model + wasmtime substrate** —
//!   this crate is the substrate; the Component Model layer arrives
//!   in step 16b. `IronClaw`'s resource-limiter pattern (fuel +
//!   memory + epoch combined) is the same triad we adopt here.
//!   No source borrowed.
//! - **`wasmtime`'s safe API** — we use `Engine`, `Module`, `Store`,
//!   `Linker`, `Instance`, `TypedFunc`, and the `ResourceLimiter`
//!   trait directly. wasmtime's safe surface is enough; we don't
//!   reach for any `unsafe` (workspace policy enforces it).
//!
//! No source borrowed from any reference claw.

#![forbid(unsafe_code)]

mod bindings;
mod config;
mod error;
mod host;
mod limits;
mod tool;

pub use config::WasmConfig;
pub use error::BuildError;
pub use host::{HostState, LogRecord, MAX_LOG_ENTRIES, MAX_LOG_MESSAGE_BYTES};
pub use tool::WasmTool;

// Re-export the trait so callers don't need a separate `use boardproof_tools::Tool`.
pub use boardproof_tools::{Tool, ToolCall, ToolError, ToolManifest, ToolMetadata, ToolOutput};
