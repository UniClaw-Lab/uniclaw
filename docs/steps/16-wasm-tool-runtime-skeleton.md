# Phase 3 Step 4 — WASM Tool Runtime skeleton (16a)

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crate introduced:** `boardproof-tools-wasm`
> **Crates touched:** none (additive)

## What is this step?

This step ships **the substrate every untrusted tool will eventually run on**: a sandboxed WebAssembly runtime that wraps a wasmtime module behind the same `Tool` trait already proven by `HttpFetchTool` (step 14) and the secret broker (step 15). The runtime applies three independent bounds on every call — fuel (CPU), memory cap (heap), epoch deadline (wall-clock) — and surfaces failures as the same `ToolError` variants the kernel already knows how to record.

Step 16 was always going to be the biggest jump in Phase 3 (wasmtime brings ~70 transitive deps and the Component Model has rough edges), so we deliberately **split it into two PRs**:

- **16a (this PR)** — the runtime skeleton itself, validated against core wasm via `.wat`-text fixtures. No host imports. No Component Model. The point is to prove fuel + memory + epoch enforcement work in isolation, before any layer above adds its own ways to fail.
- **16b (next)** — the WIT Component Model layer: `bindgen!` host glue, a real Rust→WASM Component test fixture (built ahead of time, bytes committed to the repo with the source alongside).

This split means a failure during 16b localises to "the bindgen layer" rather than "is the runtime broken or is bindgen broken." It also keeps each PR's review surface comparable to step 14/15 — much easier to audit.

## Where does this fit in the whole BoardProof?

Phase 3's Hands layer is now four layers deep:

```
                  Caller
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      Kernel              ToolHost
                              │
        ┌─────────────────────┼──────────────────────┐
        ▼                     ▼                      ▼
   HttpFetchTool          NoopTool              WasmTool ◀── (this step)
   (real I/O,             (identity,            (sandboxed,
    capability +           tests + empty         wasmtime +
    SSRF + secrets)        deployments)          fuel + memory
                                                 + epoch limits)
        │                     │                      │
        └───────────── Tool trait surface ───────────┘
                              │
                              ▼
                  RecordToolExecution
                  (kernel mints execution
                   receipt with input + output
                   hashes in provenance;
                   secret_used edges if the
                   tool consumed credentials)
```

`WasmTool` is the **third** real implementation of `Tool`. Each one validates a different aspect of the trait surface:

- `NoopTool` — basic registration + execution path.
- `HttpFetchTool` — capability enforcement + secret broker integration against real I/O.
- `WasmTool` — sandbox + resource limits against arbitrary guest code.

Once Component Model lands in 16b, the same `Tool` trait wraps any Rust code compiled to wasm.

## What problem does it solve technically?

Three problems.

### 1. "How do I run untrusted code without giving it the host?"

WebAssembly's sandbox + wasmtime's resource governor. The guest sees only its own linear memory; no syscalls, no host data structures, no shared globals. Every call gets a fresh `Store`, so state cannot leak between calls.

### 2. "How do I prevent the guest from spinning forever or eating all the memory?"

Three independent bounds, all enforced by wasmtime:

| Bound | Mechanism | Default | What trips it |
|---|---|---|---|
| CPU | `Config::consume_fuel(true)` + `Store::set_fuel(N)` | 100 M fuel | Tight loops, lots of arithmetic |
| Memory | `Store::limiter(...)` with a custom `ResourceLimiter` | 16 MiB | `memory.grow` past the cap |
| Wall-clock | `Config::epoch_interruption(true)` + `Store::set_epoch_deadline(N)` + a background ticker thread | 5 s | Anything that takes too long in real time |

These are **independent**. A guest that satisfies fuel by burning slowly still trips epoch (wall-clock); a guest that uses tiny memory but loops forever trips fuel; a memory hog trips the limiter. The first one to fire wins.

The `ToolError` mapping is structural:

| wasmtime trap | `ToolError` |
|---|---|
| `Trap::OutOfFuel` | `Failed("fuel exhausted")` |
| `Trap::Interrupt` (epoch deadline) | `Timeout` |
| Memory limiter denial → guest traps later | `Failed(...)` |
| Other traps (unreachable, OOB, etc.) | `Failed("wasm trap: ...")` |

`Timeout` matters specifically: the trait surface from step 13 has a `ToolError::Timeout` variant, and the wall-clock bound is exactly what it's for.

### 3. "How do I keep the runtime simple enough to actually trust?"

By **not** doing any of the things that complicate WASM runtimes:

- No host imports. The guest is pure compute. (16c will add capability-mediated host imports.)
- No Component Model. (16b will layer it on.)
- No persistent compilation cache. Every constructor compiles fresh.
- No async. `Tool::call` is sync (decided at step 13).
- No streaming I/O.

The result is a ~700-LOC crate (manifest validation + resource limits + per-call instantiation) that can be reviewed end-to-end. Future complexity sits behind this surface.

## How does it work in plain words?

```rust
use boardproof_tools_wasm::{WasmConfig, WasmTool};
use boardproof_tools::{ApprovalPolicy, Capability, GlobPattern, Tool, ToolManifest};

// 1. Build a tool from .wat text (or .wasm bytes via from_module_bytes).
let manifest = ToolManifest {
    name: "echo".into(),
    description: "returns input verbatim".into(),
    action_kind: "tool.echo".into(),
    declared_capabilities: vec![],
    default_approval: ApprovalPolicy::Never,
};
let tool = WasmTool::from_wat(ECHO_WAT, manifest, WasmConfig::default())?;

// 2. Submit a ToolCall — same interface every Tool uses.
let out = tool.call(&call)?;

// 3. The kernel records the execution receipt with input + output
//    hashes; same flow as HttpFetchTool's RecordToolExecution.
```

The v0 guest ABI:

```text
;; Required exports.
(memory (export "memory") ...)            ;; the guest's linear memory
(func (export "alloc") (param i32) (result i32))
(func (export "call") (param i32 i32) (result i64))

;; Calling convention:
;;   1. Host calls alloc(input_len) → input_ptr.
;;   2. Host writes input bytes at input_ptr.
;;   3. Host calls call(input_ptr, input_len) → packed (i64).
;;   4. Host unpacks: out_ptr = high32, out_len = low32.
;;   5. Host reads out_len bytes at out_ptr from guest memory.
```

Errors from the guest are signalled via wasm traps (`unreachable`, OOB, etc.). The host catches the trap and returns `ToolError::Failed`.

## Why this design choice and not another?

- **Why core wasm in 16a, Component Model in 16b?** Component Model bindgen has rough edges. Validating the runtime infrastructure against core wasm first makes 16b's failures localisable to "is bindgen producing the right glue" rather than mixed up with "is the runtime working." Same logic as step 14 (HTTP first, secrets next, WASM after both) one level up.
- **Why per-call instantiation, not InstancePre?** wasmtime's `InstancePre` lets you pre-link host imports at construction and skip part of the instantiation cost per call. With no host imports in 16a, the savings would be small; with host imports in 16c, switching to `InstancePre` is a one-pass refactor. Optimising before the use case settles is premature.
- **Why a `MemoryLimiter` per call instead of per engine?** The `max_memory_bytes` is part of `WasmConfig`, which is per-tool. Each call gets its own `Store` (for the fresh-state guarantee), and the limiter lives on the store. Per-engine wouldn't compose if one engine were shared by tools with different memory caps.
- **Why epoch interruption with a ticker thread, instead of a dedicated wall-clock check?** wasmtime doesn't have a native "wall-clock deadline" knob — epoch is the documented mechanism. The ticker thread is a small fixed overhead (~one wakeup per `epoch_tick`); cheaper than the alternatives (signal handlers, OS timers per-call). One ticker per `WasmTool` is the v0 model; if many tools share an engine, future code can share a ticker too.
- **Why `wat` as a regular dep, not feature-flagged?** `WasmTool::from_wat` is on the public API (tests use it heavily; small fixtures are easier to author in WAT than to round-trip through `wasm-as`). Feature-flagging would require every consumer to know whether they need `wat` or just `from_module_bytes`. The dep is small enough that always shipping it is the cleaner default; we can revisit if a downstream needs the slim path.
- **Why pure compute (no host imports) in 16a?** Host imports are a separate trust problem: every host function the guest can call is a potential capability-bypass surface. Designing the host-import API needs the Component Model resolved first (so the guest declares its imports via WIT, the host implements them, and `bindgen!` generates the glue). Doing it before 16b would need throwaway plumbing.

## Adopt-don't-copy

- **`IronClaw`'s wasmtime + Component Model + WIT substrate** — adopted as the architecture for step 16 as a whole. 16a borrows IronClaw's three-bound resource-limiter pattern (fuel + memory + epoch combined). 16b will adopt the WIT-based interface model. No source borrowed.
- **wasmtime's safe API** — we use `Engine`, `Module`, `Store`, `Linker`, `Instance`, `TypedFunc`, and `ResourceLimiter` directly. The workspace's `unsafe_code = "forbid"` lint applies; wasmtime's safe surface is enough for the runtime.

Citations live in `boardproof-tools-wasm/src/lib.rs`.

## What you can do with this step today

- Author a small WASM tool in WAT or Rust→wasm, build a `WasmTool`, register it in a `ToolHost`, submit calls.
- Set `WasmConfig::fuel`, `max_memory_bytes`, `timeout` per tool to bound CPU, heap, and wall-clock time.
- Trust that runaway loops trap with `ToolError::Failed("fuel exhausted")` (deterministic CPU bound) or `ToolError::Timeout` (wall-clock bound) — *both* fail-paths are exercised by the integration test suite.
- Trust that memory-grow past the cap is refused (`memory.grow` returns `-1`; if the guest doesn't check, it traps shortly after).
- Trust that misshaped modules (missing `memory` / `alloc` / `call` exports) fail at construction with a `BuildError::MissingExport`, *before* any call happens.

## Performance baseline (release, x86_64 Linux)

| Operation | Per call |
|---|---|
| `WasmTool::from_wat` (echo, default config) | **~64 ms** |
| `WasmTool::call` (echo, 11-byte input) | **~770 µs** |
| `WasmTool::call` (echo, 4 KiB input) | **~1.9 ms** |

Cold construction is dominated by Cranelift AOT codegen (the echo fixture is tiny; realistic modules will be 200-500 ms). Per-call overhead is dominated by `Linker::instantiate` (re-instantiation per call gives the fresh-sandbox guarantee). Both have natural future-step optimisations (`InstancePre` for instantiation, persistent caches for compilation) — but the current numbers comfortably fit "tools that do real work." See [`bench-results/14-wasm-tool-runtime-skeleton.txt`](../../bench-results/14-wasm-tool-runtime-skeleton.txt) for raw numbers and methodology.

## What this step does **not** ship

- **Host imports.** The guest cannot fetch URLs, read files, query secrets, or open sockets. 16c lands capability-mediated host imports (the guest declares its imports via WIT; the host implements them backed by `Capability::is_granted_by` checks and `SecretBroker::fetch`).
- **Component Model.** 16b lands `wit/tool.wit` + `wasmtime::component::bindgen!` + a Rust→WASM Component fixture.
- **Persistent compile cache.** Every constructor compiles fresh.
- **Async.** `Tool::call` is sync.
- **Multi-tenant resource accounting.** Fuel + memory + epoch are per-call; "this tenant has used X total fuel this hour" is its own subsystem.
- **Snapshot/restore of guest state across calls.** Every call gets a fresh memory.
- **A binary fixture committed to the repo.** 16a's tests author fixtures inline as WAT text; 16b will add a real Rust-source-plus-pre-built-`.wasm` fixture for the Component Model path.

## In summary

Step 16a closes the gap between "BoardProof has a Tool trait" and "BoardProof can run arbitrary sandboxed code." `WasmTool` wraps wasmtime behind the same `Tool` interface every other tool implements; fuel + memory + epoch limits enforce CPU + heap + wall-clock bounds independently; the `ToolError::Timeout` variant from step 13 finally has its first real producer. The skeleton is intentionally minimal — no Component Model, no host imports, no clever optimisations — so 16b and 16c can land additively against a runtime that's already proven correct in isolation.
