# Phase 3 Step 4b — WASM Component Model layer (16b)

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crates touched:** `uniclaw-tools-wasm`
> **New artefact:** `crates/uniclaw-tools-wasm/wit/tool.wit` + a Rust→WASM Component test fixture

## What is this step?

Step 16a shipped the runtime skeleton — fuel + memory + epoch bounds wrapped around a per-call wasmtime store, talking to the guest via a hand-rolled packed-i64 ABI. Step 16b is the **typed-interface upgrade**: tools can now be authored as Component-Model wasm against a small WIT and the host drives them through `wasmtime::component::bindgen!`-generated bindings instead of a packed-i64 trick.

Both paths coexist:

- `WasmTool::from_wat` / `from_module_bytes` — 16a's core wasm path. Same packed-i64 ABI. Same tests still pass.
- `WasmTool::from_component_bytes` — 16b's Component Model path. Typed `tool-api.call(list<u8>) -> result<list<u8>, string>` driven by bindgen.

Internally, `WasmTool` keeps a `WasmKind { Core(Module), Component(Component) }` enum and `Tool::call` dispatches on it. The two arms share engine config, fuel/epoch setup, the memory limiter, and the per-call `Store<StoreData>` factory — only the calling convention differs.

## Where does this fit in the whole Uniclaw?

```
                 Caller
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
     Kernel              ToolHost
                             │
       ┌─────────────────────┼──────────────────────┐
       ▼                     ▼                      ▼
   HttpFetchTool          NoopTool              WasmTool
   (real I/O,             (identity)             │
    capability +                          ┌──────┴──────┐
    SSRF + secrets)                       ▼             ▼
                                     WasmKind        WasmKind
                                     ::Core           ::Component   ◀── new in 16b
                                  (16a packed-i64    (typed WIT
                                   alloc/call)       canonical ABI)
                                       │                   │
                                       └─── shared: ───────┘
                                            engine config
                                            fuel + memory + epoch
                                            StoreData (limiter + WASI ctx)
                                            EpochTicker
                                            Tool trait + ToolOutput
```

The Component Model layer is a calling-convention swap. Everything below it (resource bounds, audit, kernel integration) is unchanged.

## What problem does it solve technically?

Three problems.

### 1. "How do I write a WASM tool in Rust without a hand-rolled ABI?"

16a's guest had to manually expose `alloc`, manage memory, and pack output (ptr, len) into an i64 return value. That's reviewable but tedious. With the Component Model:

```rust
// guest:
impl Guest for Component {
    fn call(input: Vec<u8>) -> Result<Vec<u8>, String> {
        if input.is_empty() {
            Err("empty input".to_string())
        } else {
            Ok(input)
        }
    }
}
```

The canonical ABI handles memory ownership in both directions. The guest sees Rust types; the host sees Rust types; the wire format is generated.

### 2. "How do I evolve the surface without breaking existing tools?"

The WIT package `uniclaw:tool@0.1.0` is versioned. Future-step additions (host imports for I/O, capability checks, secret broker bridges) are additive: a new world `tool-with-host` can land alongside the existing `tool` world without breaking anything that uses the v0 surface.

This is exactly the lever we'll pull in 16c — adding host imports without forcing every existing tool to recompile.

### 3. "How do tools authored in different languages share an interface?"

Component Model is language-agnostic. The same `wit/tool.wit` describes the surface regardless of whether the guest is Rust, Go (via TinyGo+wit-bindgen), C, JavaScript (via componentize-js), or Python (via componentize-py). 16b proves the Rust path; 16c+ proves the rest by *not* needing different host code per language.

## How does it work in plain words?

```rust
use uniclaw_tools_wasm::{WasmConfig, WasmTool};
use uniclaw_tools::{ApprovalPolicy, Tool, ToolManifest};

// 1. Build a tool from Component Model bytes (~46 KB of compiled
//    Rust→WASM Component for the test fixture).
const COMPONENT: &[u8] = include_bytes!("echo-component.wasm");
let tool = WasmTool::from_component_bytes(
    COMPONENT,
    manifest("echo"),
    WasmConfig::default(),
)?;

// 2. Same Tool trait as every other tool. Tool::call dispatches
//    internally to the Component path.
let out = tool.call(&call)?;

// 3. Same ToolOutput, same hash convention. Any
//    RecordToolExecution flow that worked for HttpFetchTool or
//    NoopTool works for this.
```

The v0 WIT is deliberately minimal:

```wit
package uniclaw:tool@0.1.0;

interface tool-api {
    call: func(input: list<u8>) -> result<list<u8>, string>;
}

world tool {
    export tool-api;
}
```

Raw `list<u8>` mirrors the host-side `ToolCall.input: Vec<u8>` + `ToolOutput.bytes: Vec<u8>` already in `uniclaw-tools`. Tools that want JSON encode it themselves rather than baking an envelope into the ABI.

## Why this design choice and not another?

- **Why `list<u8>` rather than IronClaw's record-based `request`/`response` with JSON strings?** `Tool::call` already takes `Vec<u8>` and returns `ToolOutput.bytes: Vec<u8>` — making the WASM ABI match keeps WASM tools first-class peers of native tools. JSON shape is a *tool-author choice*, not a *runtime requirement*. (IronClaw's richer shape with `schema()` and `description()` exports is a future option once a use case demands structured payloads at the ABI layer.)
- **Why keep both `from_module_bytes` and `from_component_bytes` rather than picking one?** Core wasm is smaller, faster to compile, and adequate for many tools. Component Model is more ergonomic and future-proof. We don't need to force a migration; both paths share the runtime, the audit, the resource limits, the trait. Tool authors choose.
- **Why pull `wasmtime-wasi` into the dep tree?** A Rust→WASM Component built against `wasm32-wasip2` automatically declares WASI imports — even if the program never touches them — because `std` does. Without WASI imports satisfied on the host, instantiation fails. We register an *empty* WASI context per call (no preopens, no env, no stdio passthrough), which makes the imports linkable without granting any real capability. Step 16c will replace the empty context with the kind of capability-checked one that actually matters; for 16b the goal is just "instantiation succeeds." Going `no_std` to strip the imports is on the future-step list, blocked on `wit-bindgen-rt`'s std dependency.
- **Why per-call linker construction (`add_to_linker_sync` every call)?** Same fresh-state guarantee as 16a: each call gets its own Store + its own linker + its own WASI context, so nothing leaks across calls. Future optimisation: build a `ComponentLinker` once at construction time and reuse via `InstancePre`. Premature for v0 — measure first, optimise later (and it's not on the trait surface, so the optimisation is purely internal).
- **Why a committed `.wasm` fixture rather than building at test time?** CI runners don't ship `wasm32-wasip2` or `cargo-component`. Pulling those in would inflate CI runtime by orders of magnitude. The committed artefact is reproducible from the source in `tests/fixtures/echo-component/` plus the documented build command (`BUILD.md` next to the source). Reviewers can rebuild locally; CI loads the bytes as-is.
- **Why mirror the WIT into the fixture's own `wit/` directory instead of pointing at `crates/uniclaw-tools-wasm/wit/tool.wit`?** `cargo-component` resolves the WIT package relative to the fixture crate's directory. Pointing across workspace boundaries is awkward (different toolchain, different target dir). A copy is cheap; the BUILD.md notes that both must stay in sync.

## Adopt-don't-copy

- **`IronClaw`'s `near:agent@0.3.0` WIT package design** — the patterns we adopted: a single `tool` interface as the export contract, a separate world definition that imports/exports interfaces, the explicit "guest is untrusted, host satisfies imports under capability" trust model. Uniclaw's v0 surface is leaner (raw bytes, no `schema()`/`description()` exports — those live on the host-side `ToolManifest`). The richer pattern is on the future-step list.
- **`IronClaw`'s `bindgen!` invocation pattern** (`crates/ironclaw_wasm/src/bindings.rs`) — adopted as the shape of our `src/bindings.rs`. Same macro, same world-name argument, same module-level allows for the generator's lints.
- **`IronClaw`'s `StoreData` shape** — adopted as a single struct holding `MemoryLimiter` + `WasiCtx` + `ResourceTable` + the `WasiView` impl. Same pattern, smaller surface (no IronClaw-specific host functions or resource-usage tracking yet).

Citations live in `crates/uniclaw-tools-wasm/src/lib.rs` and `wit/tool.wit`.

## What you can do with this step today

- Author a WASM tool in Rust → compile to a Component → load it via `WasmTool::from_component_bytes` → register it in a `ToolHost`.
- Use the typed `result<list<u8>, string>` ABI: success returns `Ok(bytes)` to the host; logical guest errors return `Err(string)` and surface as `ToolError::Failed("guest: <message>")`. Sandbox failures (fuel exhausted, epoch deadline, memory cap, traps) still surface via the variant they did in 16a — unchanged.
- Run the same fuel + memory + wall-clock limits as core wasm tools. The Component Model layer is a calling-convention swap, not a sandbox change.
- Mix tool kinds in a single `ToolHost`: a core-wasm tool from `from_wat`, a Component tool from `from_component_bytes`, a native `HttpFetchTool` — all sit behind the same `Tool` trait and produce the same kernel-receipt shape.

## Performance baseline (release, x86_64 Linux)

| Operation | 16a core wasm | 16b Component Model |
|---|---|---|
| Cold construction (echo) | ~17 ms | ~860 ms |
| Warm call (11-byte echo input) | ~1.13 ms | ~2.52 ms |

Cold construction is ~50× slower for the Component fixture: it's 46 KB vs a few hundred bytes of core-wasm WAT, and the Component Model adds canonical-ABI glue + WASI import resolution that core wasm skips. Per-call overhead is ~+1.4 ms (~120%) — dominated by per-call `wasmtime_wasi::p2::add_to_linker_sync` and canonical-ABI marshalling. Both have natural future-step optimisations (`InstancePre` for the linker, a serialized-component cache for cold start). See [`bench-results/15-wasm-component-model.txt`](../../bench-results/15-wasm-component-model.txt) for raw numbers and analysis.

The numbers are real-world acceptable for v0. A real WASM tool's per-call cost is dominated by domain compute, not the runtime; the Component Model overhead amortises across whatever work the tool actually does.

## What this step does **not** ship

- **Host imports.** The `tool` world exports only; nothing imported. Step 16c lands a `tool-with-host` world that imports `host` (HTTP fetch routed through `Capability::is_granted_by`, secret-existence check routed through `SecretBroker`). The trait surface for those gates is already in place from steps 13/14/15.
- **`InstancePre` / persistent component cache.** Both are pure internal optimisations and can land additively.
- **Schema / description exports on the guest.** v0 keeps `ToolManifest` host-side. IronClaw's `schema()` + `description()` exports are a future option.
- **Languages other than Rust for the test fixture.** Validating the Component Model surface needs *one* working guest; we picked Rust. A Go fixture (TinyGo + `wit-bindgen-tinygo`) or a JavaScript fixture (`componentize-js`) is a follow-up if interest emerges.
- **Component caching across constructor calls.** Each `from_component_bytes` re-compiles. Cross-call caching needs deduplication keyed on the bytes' hash; not on the v0 path.

## In summary

Step 16b makes WASM tools authorable in idiomatic Rust without a hand-rolled ABI. The same `Tool` trait, the same kernel integration, the same fuel/memory/epoch limits — but the calling convention is now `list<u8> → result<list<u8>, string>` with the Component Model's canonical ABI handling memory ownership for us. The substrate has two valid forms: core wasm for slim/fast, Component Model for typed/ergonomic. 16c will land capability-mediated host imports against this same surface, completing the substrate swap.
