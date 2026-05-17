# Phase 3 Step 4c — WASM Host Imports (16c)

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crates touched:** `boardproof-tools-wasm`
> **New artefacts:** extended `wit/tool.wit` + `tests/fixtures/http-tool-component/` + committed `http-tool-component.wasm`

## What is this step?

Step 16a shipped the runtime (fuel + memory + epoch). Step 16b shipped the typed Component Model layer with `tool-api.call(list<u8>) -> result<list<u8>, string>`. Both used **export-only** worlds — guests could compute, but they couldn't *do* anything.

Step 16c closes that gap: a new `host` interface that guests can import for capability-mediated I/O, plus a `tool-with-host` world that imports `host` and exports `tool-api`. The WASM substrate swap is now complete — WASM tools can fetch HTTP, check secret existence, log, and read the clock through the **same** machinery that native tools use.

The principle: every host import the guest can call is a thin shim that delegates to the existing trait surface from steps 13/14/15. `host::http-fetch` calls `HttpFetchTool::call`. `host::secret-exists` calls `SecretBroker::fetch(name).is_ok()`. `host::log-message` accumulates into `HostState`. There is no parallel implementation; the WASM layer is *facade*, not *fork*.

## Where does this fit in the whole BoardProof?

The Hands layer is now four layers deep:

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
    capability +                          ┌──────┼──────┬──────────────────┐
    SSRF + secrets)                       ▼      ▼      ▼                  ▼
                                     Core    Component  Component-with-host  ◀── new in 16c
                                     (16a)   (16b)      (host imports
                                                         delegated to
                                                         HttpFetchTool +
                                                         SecretBroker)
                                       │       │              │
                                       └─── shared: ──────────┘
                                            engine config
                                            fuel + memory + epoch
                                            StoreData (limiter + WASI ctx
                                                       + optional HostState)
                                            Tool trait + ToolOutput
```

`WasmTool` now has three internal kinds (`Core`, `Component`, `ComponentWithHost`). The kernel doesn't see any of this — it sees the `Tool` trait. A `RecordToolExecution` event for a 16c-built tool produces the same shape of receipt as a 16a-built one, with `secret_used` provenance edges minted from the `secrets_used` list aggregated across the guest's `http-fetch` calls.

## What problem does it solve technically?

Three problems.

### 1. "How does a sandboxed WASM tool make a real HTTP call without re-implementing capability + SSRF + secret injection?"

By calling the host. The new `host::http-fetch` import takes `(url, auth, timeout)`, the host delegates to `HttpFetchTool::call`, the response comes back as a typed `http-response` record. Whatever `HttpFetchTool` enforces (capability allowlist, SSRF gate, bounded read), the WASM guest gets — automatically.

This means a WASM tool can't bypass capability checks even if its author wanted to: there's no host import that takes raw sockets, no syscall surface beyond the four functions in the WIT.

### 2. "How does the guest reference a credential without touching it?"

The WIT `auth-spec` variant is `bearer-header(string)` where the string is the **broker reference name**, not the secret value. The host receives the call, looks up the secret by name, and injects it as `Authorization: Bearer <value>` — the guest never sees the value.

The audit trail tracks the *names* the guest referenced. After `WasmTool::call` returns, `ToolOutput::metadata.secrets_used` holds the deduplicated list of every reference name the guest's `http-fetch` calls touched. The kernel's `RecordToolExecution` mints one `secret_used` provenance edge per name, exactly as it does for native HttpFetchTool calls.

### 3. "How does the host know which secrets exist without leaking the values?"

`host::secret-exists(name) -> bool`. The host calls `broker.fetch(name).is_ok()`, drops the returned `SecretValue` (which zeroes its buffer on Drop), and returns the boolean. The guest learns whether the credential is present; it learns *nothing else*.

This lets a guest fail-fast before starting expensive work that depends on a credential being present, without exposing any value.

## How does it work in plain words?

Host side:

```rust
use std::sync::Arc;
use boardproof_tools_wasm::{WasmConfig, WasmTool};
use boardproof_tools_http::{HttpFetchConfig, HttpFetchTool};
use boardproof_secrets::{InMemorySecretBroker, SecretBroker};

let broker: Arc<dyn SecretBroker> = Arc::new(InMemorySecretBroker::new());
let http = Arc::new(HttpFetchTool::with_broker_and_config(
    vec![GlobPattern::new("api.github.com")],
    Arc::clone(&broker),
    HttpFetchConfig::default(),
));

let tool = WasmTool::from_component_bytes_with_host(
    component_bytes,
    manifest("github-tool"),
    WasmConfig::default(),
    http,
    broker,
)?;

// Same Tool trait. Same kernel integration. Same ToolOutput shape.
let out = tool.call(&call)?;
// out.metadata.secrets_used == ["github.token", ...]  (whichever
// secret refs the guest touched during the call)
```

Guest side (Rust → WASM Component):

```rust
use bindings::boardproof::tool::host;

fn call(input: Vec<u8>) -> Result<Vec<u8>, String> {
    // The guest looks up by name, never by value.
    if !host::secret_exists(&"github.token".into()) {
        return Err("missing github.token".into());
    }

    // The Authorization header is injected by the host. The guest
    // never sees the secret value.
    let resp = host::http_fetch(
        &"https://api.github.com/user".into(),
        Some(&host::AuthSpec::BearerHeader("github.token".into())),
        None,
    )?;

    Ok(resp.body)
}
```

The full call pipeline (additive over 16b's pipeline):

| Step | What | Notes |
|---|---|---|
| 1 | Guest's `tool-api.call` is invoked via canonical ABI | 16b path |
| 2 | Guest calls `host::http-fetch(url, auth, timeout)` | 16c host import |
| 3 | Host delegates to `HttpFetchTool::call` with the args wrapped as `HttpFetchInput` | Same instance the operator built |
| 4 | `HttpFetchTool` runs its existing steps: capability gate → SSRF gate → broker fetch → ureq GET → bounded read | All 16a/14/15 logic |
| 5 | Host decodes the JSON envelope + base64 body | Bridges to the canonical-ABI `http-response` |
| 6 | Guest receives a typed `http-response` record | Status + headers + body |
| 7 | Host accumulates the secret_ref name in `HostState.secrets_used` | Even on failure |
| 8 | When `tool-api.call` returns, `WasmTool` harvests `HostState.secrets_used` into `ToolOutput::metadata.secrets_used` | Surfaced to the kernel |

## Why this design choice and not another?

- **Why delegate to `HttpFetchTool::call` instead of re-implementing HTTP for the guest?** Two enforcement surfaces is one too many. If the WASM-side HTTP code drifted from the native HTTP code, capability checks would diverge, SSRF rules would diverge, secret injection would diverge. Same code path → same enforcement.
- **Why a separate `tool-with-host` world rather than adding `host` imports to the existing `tool` world?** Backwards compatibility. 16b's echo-component fixture (and any pure-compute Component built against 16b) implements the `tool` world with no imports. Adding `host` to that world would force every existing Component to recompile against the new contract. A new world is purely additive.
- **Why pass `Arc<HttpFetchTool>` and `Arc<dyn SecretBroker>` separately to the constructor?** `HttpFetchTool` doesn't currently expose its internal broker reference (it's private). Until we add a `broker()` accessor, the cleanest API is "operator passes both, we trust them to construct with the same broker." Future cleanup path is obvious.
- **Why `secret-exists` rather than `secret-fetch`?** A guest that can fetch the value is a guest that can leak the value (echo it in output, leak via timing, etc.). v0 keeps secret values strictly host-side; the guest only gets a yes/no. If a use case needs richer guest behaviour, we add a guarded variant later — but the secure default ships first.
- **Why aggregate `secrets_used` into `ToolOutput::metadata` rather than as a separate channel?** The kernel already reads `ToolOutput::metadata.secrets_used` to mint `secret_used` provenance edges (step 15). Reusing that surface means the kernel doesn't change at all for 16c — every audit guarantee from step 15 applies to WASM tools by construction.
- **Why no `tool-invoke` (calling another tool from the guest)?** Composition complexity that needs careful approval-flow design. Defer until 16d.
- **Why no `workspace-read`?** Filesystem capability machinery doesn't exist yet (separate step). When it does, `host::workspace-read` becomes a thin shim.
- **Why a JSON round-trip in the host bridge (HttpFetchInput → JSON → Tool::call → JSON envelope → HttpFetchOutput)?** It's the simplest correct path that reuses HttpFetchTool's existing API. ~+1 ms per call in the bench. A future-step refactor could expose a non-JSON entry point on HttpFetchTool to skip this; not worth premature optimisation while the API surface settles.

## Adopt-don't-copy

- **`IronClaw`'s `host` interface in `near:agent@0.3.0`** (`ironclaw/wit/tool.wit`) — the architectural reference for the shape: log-level enum, structured response records, auth-by-reference rather than auth-by-value, secret-existence-only check, `tool-invoke` indirection. BoardProof's v0 `host` interface is a leaner subset (4 functions vs 8) — the richer pieces (workspace-read, tool-invoke, structured rate-limit hints, http-response with `headers-json` string) land additively when use cases demand them.
- **`IronClaw`'s `crates/ironclaw_wasm/src/store.rs` `StoreData` shape** — adopted as `StoreData` holding limiter + WasiCtx + optional `HostState`, with the bindgen-generated `Host` trait implemented on `StoreData` (not on `HostState` directly) so the same store-data type works for both 16a/16b paths (where HostState is None) and 16c paths (where it's Some).
- **`IronClaw`'s rate-limit constants** (1000 entries / 4 KiB per log message) — adopted as `MAX_LOG_ENTRIES` / `MAX_LOG_MESSAGE_BYTES`. Same values; same rationale (cap-busting calls become no-ops, not errors).

Citations live in `crates/boardproof-tools-wasm/src/lib.rs`, `src/host.rs`, and `wit/tool.wit`.

## What you can do with this step today

- Author a Rust→WASM Component that imports `host` and call `http_fetch` / `secret_exists` / `log_message` / `now_millis` from inside the guest.
- Build a `WasmTool` via `from_component_bytes_with_host(...)` that wires the guest's host imports to your `HttpFetchTool` + `SecretBroker`. Same allowlist, same SSRF gate, same auth injection.
- Trust that capability denial in the host's `HttpFetchTool` surfaces in the guest as `Err(string)` from `host::http-fetch`. Sandbox failures (fuel, memory, epoch) still trap from the outside, exactly as in 16a/16b.
- Trust that secret-existence checks never reveal values. The audit chain shows which references the guest touched without revealing any of the values.
- Trust that the kernel's existing `RecordToolExecution` flow records WASM tools' secret usage automatically, via the same `secret_used` provenance edges that step 15 wired up for native tools.

## Performance baseline (release, x86_64 Linux)

| Operation | Per call |
|---|---|
| Direct `HttpFetchTool::call` (no WASM) | ~16.4 ms |
| `WasmTool::call` via 16c host-import to same `HttpFetchTool` | ~27.7 ms |
| Host-import overhead vs direct | **+11.3 ms (+68%)** |

The +11 ms is the per-call sandbox tax: Component instantiation + WASI linker setup + canonical-ABI marshalling of the `http-response` + the JSON+base64 round-trip in the host bridge. Both numbers are dominated by localhost mock TCP teardown (`connection: close` per response defeats keep-alive in both paths). On real APIs with keep-alive, the *absolute* numbers fall ~10×; the *relative* overhead stays similar but the absolute milliseconds become small. `InstancePre` is the obvious future optimisation. See [`bench-results/16-wasm-host-imports.txt`](../../bench-results/16-wasm-host-imports.txt) for raw numbers and the optimisation list.

## What this step does **not** ship

- **`tool-invoke`** (guest calling another tool). Needs careful approval-flow design.
- **`workspace-read`** (guest reading the workspace filesystem). Needs filesystem capability machinery first.
- **Output sanitization at the host boundary.** The guest could echo the body bytes from `http-fetch` in its output, leaking what was fetched. That's step 18 (output sanitization), not 16c.
- **`InstancePre` / persistent component cache.** Both are pure internal optimisations.
- **Schema / description guest exports.** `ToolManifest` host-side stays canonical for v0.
- **Asynchronous host imports.** All four `host` functions are sync. Wasmtime's async-component-model machinery exists but adds complexity; defer.
- **Per-tool resource accounting beyond `secrets_used`** (bytes egressed, http-fetch counts visible in the receipt). The host accumulator tracks them; the receipt surface in `ToolOutput::metadata` only carries `secrets_used` in v0. Future-step `metadata` extensions land additively.

## In summary

Step 16c completes the WASM substrate swap. WASM tools can now do real work — fetch URLs, check secrets, log, query the clock — through the **same** capability + SSRF + secret machinery that native tools use, with the **same** receipt-format guarantees the kernel mints for native tools. The Component Model layer is no longer just a calling-convention upgrade; it's a real sandbox with a real path to do real things, behind a real audit boundary.

The `Tool` trait surface from step 13 has now been validated against three radically different backends:
- `HttpFetchTool` — native sync I/O.
- `WasmTool` (Core / Component / ComponentWithHost) — sandboxed WASM with two ABIs and one capability-mediated import surface.
- `NoopTool` — identity for tests.

Future tools fit behind the same trait. Future host import surfaces extend `host` additively. The kernel records every receipt the same way. Phase 3 has the foundation it needed.
