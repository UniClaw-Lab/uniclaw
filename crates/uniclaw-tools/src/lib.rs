//! Tool execution architecture for Uniclaw.
//!
//! This crate is the **foundation** of Phase 3 (master plan §28). It
//! defines what a "tool" is, what capabilities it can declare, and how
//! the kernel records that one ran. **It does not ship a runtime.** The
//! actual execution backends (WASM via `wasmtime`+WIT, container, MCP
//! bridge) arrive in follow-up steps; this crate just gives them all a
//! shared trait surface to implement.
//!
//! ## What's here
//!
//! - [`Capability`] — a typed, glob-aware declaration of what a tool
//!   can read/write/connect-to. Seven variants: `NetConnect`,
//!   `FileRead`, `FileWrite`, `ShellExec`, `EnvRead`, `LlmQuery`,
//!   `SecretRead`.
//! - [`GlobPattern`] — the tiny matcher that powers capability scoping.
//!   Supports `*`, `prefix*`, `*suffix`, `*middle*`, and any combination
//!   of those. No regex; no backtracking pathologies; ~30 LOC, `no_std`.
//! - [`Tool`] — the trait every backend implements: `name`, `manifest`,
//!   `approval_policy`, `call`.
//! - [`ToolManifest`] — a tool's self-declaration: the `action.kind`
//!   prefix it owns, the capabilities it claims, the default approval
//!   policy.
//! - [`ApprovalPolicy`] — `Never` / `Discretionary` / `Always`. Tools
//!   that need per-call decisions return `Discretionary` from
//!   `Tool::approval_policy(&call)`.
//! - [`ToolCall`] / [`ToolOutput`] / [`ToolError`] — the execution
//!   shape. Both call and output carry a BLAKE3 `input_hash` /
//!   `output_hash` so the kernel can record them in the receipt without
//!   re-hashing.
//! - [`ToolHost`] — the registry that maps tool name → `Box<dyn Tool>`.
//!   Synchronous `call(&ToolCall)` interface; async runtimes wrap this
//!   in their own scheduling.
//! - [`NoopTool`] — a built-in identity tool (input == output, no
//!   capabilities). Useful for tests and as an empty-deployment
//!   placeholder.
//!
//! ## What's *not* here (deliberate)
//!
//! - **No WASM runtime.** That lives in `uniclaw-tools-wasm` (next
//!   step). This crate stays no_std-friendly for embedded reuse.
//! - **No HTTP / file / shell tool implementations.** Those land
//!   alongside the WASM runtime once we have a real sandbox.
//! - **No async.** `Tool::call` is sync; runtimes that need async
//!   (e.g. an MCP-bridge tool) wrap a sync `Tool` impl around their
//!   async machinery.
//! - **No signature verification on manifests.** Adopted as a future
//!   step (`ZeroClaw`-style Ed25519 signed manifests; we'll do it
//!   default-on, not default-off).
//!
//! ## Where this fits
//!
//! Master plan §28 Phase 3. This is the **trait foundation** that
//! every later tool-related step plugs into.
//!
//! ```text
//!  Caller
//!    │
//!    ▼
//!  Kernel  ── EvaluateProposal ──→ "tool.<name>" action approved
//!    ▲                                       │
//!    │                                       ▼
//!    │                                ToolHost::call(&ToolCall)
//!    │                                       │
//!    │                                       ▼
//!    │                                  Tool::call(&ToolCall)
//!    │                                       │
//!    │                                       ▼
//!    │                                  Result<ToolOutput, ToolError>
//!    │                                       │
//!    └── KernelEvent::RecordToolExecution ◀──┘
//!         (kernel mints follow-on receipt with
//!          input_hash + output_hash + provenance)
//! ```
//!
//! ## Adopt-don't-copy
//!
//! - **`OpenFang`'s `Capability` enum with glob matching** — adopted in
//!   spirit. Uniclaw's enum is leaner (7 variants, no MemoryRead/Write
//!   yet — those land when the memory subsystem does in Phase 4) and
//!   uses a tiny custom matcher instead of pulling a glob crate.
//!   `OpenFang`'s `validate_capability_inheritance()` (child caps ⊆
//!   parent caps) is on the future list; v0 enforces at execution time
//!   only.
//! - **`IronClaw`'s two-phase approval** (`requires_approval(&params)`
//!   enum + post-execution `ActionRecord`) — adopted as
//!   `ApprovalPolicy { Never, Discretionary, Always }` on the trait
//!   plus `KernelEvent::RecordToolExecution` after the fact.
//! - **`IronClaw`'s `WIT` Component Model** — *not* adopted at this layer.
//!   Step 14 will use `wasmtime::component::bindgen!` with a
//!   `wit/tool.wit` interface, but that integration sits behind a
//!   `WasmTool` adapter that implements this crate's `Tool` trait. The
//!   trait surface stays backend-agnostic.
//! - **`OpenClaw`'s gateway-level deny list** — adopted as Constitution
//!   rules (already supported). High-risk tool kinds get a Constitution
//!   `Deny` rule; that's where they belong, not in trait code.
//! - **`ZeroClaw`'s signed manifests** — on the future list, with
//!   default-on signature verification (the opposite of `ZeroClaw`'s
//!   default-off).
//!
//! No source borrowed from any of the four reference claws.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod capability;
mod host;
mod noop;
mod tool;

pub use capability::{Capability, GlobPattern};
pub use host::ToolHost;
pub use noop::NoopTool;
pub use tool::{ApprovalPolicy, Tool, ToolCall, ToolError, ToolManifest, ToolOutput};
