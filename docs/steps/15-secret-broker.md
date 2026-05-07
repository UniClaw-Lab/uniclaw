# Phase 3 Step 3 — Secret Broker

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crate introduced:** `uniclaw-secrets`
> **Crates updated:** `uniclaw-tools` (`ToolMetadata` on `ToolOutput`), `uniclaw-tools-http` (auth via `BearerHeader`), `uniclaw-kernel` (`secret_used` provenance edges)

## What is this step?

This step ships the **Secret Broker**: the typed surface that lets a tool ask for a credential by *reference name* (e.g. `"github.token"`) and have it injected into the outgoing call without the secret value ever appearing in a tool input, a tool output, or a receipt's audit chain. It also wires the broker through to `HttpFetchTool` (the existing GET tool from step 14) and through to the kernel — every authenticated tool call now records one `secret_used` provenance edge per consumed credential, naming the *reference* not the *value*.

Three pieces land together:

1. **`uniclaw-secrets`** — a new crate with `SecretValue` (drop-zeroizing buffer, redacted Debug, no Display/Serialize/Clone), the `SecretBroker` trait + `BrokerError`, an `InMemorySecretBroker` (BTreeMap-backed), and an `EnvSecretBroker` (reads from environment variables under a configurable prefix).
2. **`HttpFetchTool::with_broker(...)`** — three new constructors that accept an `Arc<dyn SecretBroker>`. `HttpFetchInput` gains an optional `auth: AuthSpec` field; v0 supports `BearerHeader { secret_ref }`. The tool fetches the secret at call time, sets `Authorization: Bearer <value>`, drops the `SecretValue` (which zeroes its buffer), and records the *reference name* in `ToolOutput::metadata.secrets_used`.
3. **`secret_used` provenance** — `KernelEvent::RecordToolExecution` reads `output.metadata.secrets_used` and mints one provenance edge per name, alongside the existing `tool_input` / `tool_output` edges. The audit chain now answers "did this run touch privileged credentials?" without re-running the tool.

## Where does this fit in the whole Uniclaw?

Phase 3's Hands layer is now three layers deep:

```
                  Caller
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      Kernel              ToolHost
                              │
                              ▼
                       HttpFetchTool
                              │
        ┌─────────────────────┼──────────────────────┐
        ▼                     ▼                      ▼
   Capability            SSRF check             SecretBroker
   ::is_granted_by                              fetch(ref) ─→ SecretValue
        │                     │                      │
        │                     │                ┌─────┴─────┐
        │                     │                ▼           ▼
        │                     │             Bearer    metadata
        │                     │             header    .secrets_used.push(ref)
        ▼                     ▼                  │
       (gates pass)                              ▼
                              ┌──────────  ureq GET ───────────┐
                              ▼                                ▼
                         JSON envelope                  Authorization: Bearer …
                                                        (header dies with the
                                                         response; SecretValue
                                                         zeroed on Drop)
                                            │
                                            ▼
                                  RecordToolExecution
                                  (kernel mints
                                   secret_used edge:
                                   to = "secret:<ref>",
                                   never the value)
```

Two follow-on steps in Phase 3 lean on this:

- **Step 16 (WASM tool runtime).** WASM tools cannot be trusted with raw secrets, so the broker fetch must stay on the host side; the WIT interface will surface `auth_inject(...)` host calls that wrap `SecretBroker::fetch` rather than handing the value into the guest. Having the broker contract pinned now makes that interface design a small follow-up rather than a re-architecture.
- **Step 18 (output sanitization).** Sanitization needs to know which credentials a tool consumed so it can scrub them from any free-form output. `metadata.secrets_used` is the channel that delivers that list to the redactor.

## What problem does it solve technically?

Three problems.

### 1. "How do I give a tool a credential without putting it in the tool's input?"

Tool inputs are JSON, hashed into the receipt, replayable for verification — exactly the wrong place for a secret. The fix is to pass the *reference name* in the input and keep the value out of the receipt entirely:

```rust
HttpFetchInput {
    url: "https://api.github.com/user".into(),
    auth: Some(AuthSpec::BearerHeader {
        secret_ref: "github.token".into(),
    }),
}
```

The reference travels through the receipt; the value is fetched from the broker at call time and injected into the outgoing HTTP request. The receipt's `input_hash` is over the JSON above — never over the secret.

### 2. "How do I make sure a missing secret fails closed?"

If the broker isn't configured, or the named secret isn't present, the tool **must not** silently send an unauthenticated request. That's the IronClaw failure mode the trait was designed to prevent: a missing secret turning a privileged call into an unauthenticated one is worse than a hard failure, because the caller assumed authentication was happening.

`HttpFetchTool::call` enforces this in two places:

- If `input.auth` is set and `tool.broker` is `None`: `ToolError::Failed("input requested authentication but tool has no SecretBroker configured")` *before* opening any socket.
- If the broker is present but `fetch(ref)` returns `Err`: `ToolError::Failed("failed to fetch secret '<ref>': <broker error>")` — same socket-free fail-closed.

Two integration tests assert both branches *and* assert that `server.captured()` is empty afterwards: the proof of fail-closed is "no network IO happened."

### 3. "How does the audit chain show a secret was used, without showing the value?"

The kernel's `RecordToolExecution` handler now reads `output.metadata.secrets_used` (a `Vec<String>` of reference names) and mints one provenance edge per name:

```text
ProvenanceEdge {
    from: "receipt:<allowed_id_hex>",
    to:   "secret:github.token",
    kind: "secret_used",
}
```

A verifier walking the receipt log can now answer "list every receipt that used `secret:github.token`" with a structural query — the kernel guarantees the edge format. The secret *value* is never accessible to the kernel (the kernel does not see `ToolOutput.bytes` for hashing purposes; it only sees `output_hash` and `metadata`), so it cannot accidentally record one.

## How does it work in plain words?

```rust
use std::sync::Arc;
use uniclaw_secrets::{InMemorySecretBroker, SecretBroker};
use uniclaw_tools::GlobPattern;
use uniclaw_tools_http::{AuthSpec, HttpFetchConfig, HttpFetchInput, HttpFetchTool};

// 1. Operator configures the broker once at startup.
let mut broker = InMemorySecretBroker::new();
broker.insert_string("github.token", std::env::var("GITHUB_PAT").unwrap());

// 2. Tool is built with an Arc<dyn SecretBroker>.
let tool = HttpFetchTool::with_broker(
    vec![GlobPattern::new("api.github.com")],
    Arc::new(broker),
);

// 3. Caller submits a tool input that references the secret by NAME.
let input = HttpFetchInput {
    url: "https://api.github.com/user".into(),
    auth: Some(AuthSpec::BearerHeader {
        secret_ref: "github.token".into(),
    }),
};
// ... serialize, build ToolCall, kernel approves, tool runs ...

// 4. ToolOutput.metadata.secrets_used == ["github.token"]
// 5. Kernel mints "secret_used" provenance edge to "secret:github.token"
// 6. Receipt audit log now shows credential touched, not its value.
```

The full call pipeline (gates 1-4 are unchanged from step 14; gate 5 is new):

| Step | What | Failure mode |
|---|---|---|
| 1 | Parse `call.input` as `HttpFetchInput` JSON | `ToolError::InvalidInput` |
| 2 | Parse URL, validate scheme, extract host | `ToolError::InvalidInput` |
| 3 | `Capability::is_granted_by(declared, NetConnect(host))` | `ToolError::CapabilityDenied` |
| 4 | `ssrf::is_disallowed_ip(host)` (if not `allow_private_ips`) | `ToolError::Failed` |
| **5** | **Resolve `input.auth` via broker → set Authorization** | **`ToolError::Failed` (fail-closed)** |
| 6 | `req.call()` (ureq, blocking, no redirects) | `ToolError::Failed` |
| 7 | Read body bounded by `max_response_bytes + 1` | `ToolError::Failed` (oversize) |
| 8 | Build `HttpFetchOutput { status, headers, body_b64 }` | — |
| 9 | Serialize envelope + BLAKE3 hash | — |
| 10 | Return `ToolOutput { bytes, output_hash, metadata.secrets_used }` | — |

Auth resolution sits **after** the capability and SSRF gates: a host that's denied or private gets that error *first*, never a "missing broker" error. A unit test (`capability_gate_runs_before_auth_gate`) pins this ordering down.

## Why this design choice and not another?

- **Why `Arc<dyn SecretBroker>`, not a generic parameter?** A generic `Tool<B: SecretBroker>` would force every consumer to thread the broker type through their function signatures and would prevent storing tools in a `Box<dyn Tool>`-like registry (`ToolHost::register`). The dyn-trait avoids that at the cost of a single virtual call per fetch — measured at ~200 ns in the bench, well below any tool-call cost.
- **Why an `Option<Arc<dyn SecretBroker>>`, not always-required?** Most tools don't need a broker (tool foundation, future filesystem-read tool, etc.), and forcing one would push a meaningless `Arc::new(InMemorySecretBroker::new())` into every constructor. Optional + fail-closed-when-needed gives the same safety with cleaner ergonomics.
- **Why expose the secret value as `&str` (`SecretValue::expose`), not `&[u8]`?** All v0 use cases are HTTP headers (UTF-8 text). `&str` matches what `ureq::Request::set` wants. If a future use case needs raw bytes (binary tokens, opaque blobs), we can add `SecretValue::expose_bytes(&self) -> &[u8]` additively.
- **Why no `Clone` on `SecretValue`?** Cloning would mean two buffers exist, two zeroizing-Drops fire, and the surface area for a leak doubles. `InMemorySecretBroker::fetch` re-allocates a fresh `SecretValue` from its stored copy — that's deliberate, not an oversight, and keeps every `SecretValue` in the program owned by exactly one place.
- **Why `secret_used` edges from `receipt:<id>`, not from `tool:<name>`?** The kernel's existing convention is that all provenance edges from a tool-execution receipt have `from = "receipt:<allowed_id_hex>"` and `to = <resource>`. Following that pattern keeps "list edges from this receipt" queries straightforward. The `kind = "secret_used"` is enough to distinguish semantically.
- **Why `BearerHeader` as a tagged enum variant, not a free-form `(String, String)` header pair?** Free-form would let an LLM construct arbitrary headers (cookie, custom auth, MITM-able) — a bigger attack surface than any v0 tool needs. Tagged enum keeps the matrix of supported auth schemes small and reviewable; future variants (`CustomHeader`, `BasicAuth`, `Aws4Sign`) land additively without breaking existing inputs.

## Adopt-don't-copy

- **`IronClaw`'s fail-closed Secret Broker pattern** — adopted as the trait contract: tools surface missing secrets as `ToolError::Failed` rather than silently degrading to unauthenticated requests. Documented in `SecretBroker::fetch`'s doc comment. No source borrowed.
- **`zeroize` crate's drop-zeroing primitive** — adopted as a dependency (we don't reimplement constant-time zeroing). It's a well-vetted, focused crate; reimplementing would be both more code and less safe.
- **`OpenClaw`'s "secret reference, not secret value" model** — adopted as `AuthSpec::BearerHeader { secret_ref: String }` and `metadata.secrets_used: Vec<String>` (names only). The provenance edge format mirrors the same principle. No source borrowed.
- **`ZeroClaw`'s zeroize-on-drop discipline** — adopted in `SecretValue::Drop`. ZeroClaw uses the same `zeroize` crate; we landed at the same answer independently. No source borrowed.

Citations live in `uniclaw-secrets/src/lib.rs` and `uniclaw-secrets/src/broker.rs`.

## What you can do with this step today

- Build a `SecretBroker` (in-memory or env-var) and inject it into `HttpFetchTool` via `with_broker(...)` or `with_broker_and_config(...)`.
- Send a `HttpFetchInput` with `auth: Some(AuthSpec::BearerHeader { secret_ref })`. The tool injects `Authorization: Bearer <value>` from the broker.
- Forget to configure the broker, or reference a missing secret — the call **fail-closes before any socket opens**. The integration test `auth_input_with_no_broker_fails_closed_without_opening_a_socket` proves this end-to-end.
- Walk the receipt log to find every receipt that consumed a given credential — query for edges with `kind = "secret_used"` and `to = "secret:<ref>"`.
- Confirm via `format!("{:?}", broker)` that the broker's Debug never prints names or values (only the count of registered secrets) — there's a unit test for that too.

## Performance baseline (release, x86_64 Linux)

| Operation | Per call |
|---|---|
| `InMemorySecretBroker::fetch` (100 secrets, key in middle) | **~150–250 ns** |
| `HttpFetchTool` warm fetch, unauthenticated (localhost mock) | ~10–20 ms |
| `HttpFetchTool` warm fetch, authenticated via broker | ~10–20 ms (auth overhead in noise) |

The broker fetch costs ~200 ns (BTreeMap lookup + fresh `SecretValue` allocation). The end-to-end auth overhead per HTTP call is dominated by TCP teardown noise on localhost (`connection: close` on every response defeats keep-alive); the actual auth-path work — broker fetch, `format!("Bearer …")`, header set, `Vec<String>::push` — is in the tens of microseconds, well below the per-call HTTP cost. See [`bench-results/13-secret-broker.txt`](../../bench-results/13-secret-broker.txt) for raw numbers.

## What this step does **not** ship

- **Multi-secret tool calls.** v0 supports exactly one `BearerHeader` per call. A future step adds `Vec<AuthSpec>` once a real use case demands it.
- **Auth schemes beyond Bearer.** `BasicAuth`, `CustomHeader`, AWS Sigv4 etc. are deliberate gaps — additive enum variants land when the use case does.
- **ACL-by-caller in v0 brokers.** Both `InMemorySecretBroker` and `EnvSecretBroker` return any registered secret to any caller. The `BrokerError::AccessDenied` variant exists so future ACL-aware backends (Vault policies, KMS IAM) fit cleanly, but v0 doesn't model caller identity.
- **Real Vault / AWS Secrets Manager / GCP Secret Manager backends.** Those are downstream `impl SecretBroker` adapters; this crate only ships the trait + two reference impls.
- **Sanitization of the secret value from tool output.** If a tool somehow includes the secret value in its response body, that body still goes into the receipt's output bytes. Step 18 (output sanitization) closes that gap; for now, it's the tool's responsibility not to echo the secret.
- **Signed-config provenance.** The operator who calls `broker.insert_string` can put any value under any name. A future step ties broker contents to a signed config receipt so an auditor can verify "this name resolved to this hash at this time."

These are explicit deferrals, sequenced behind the use cases that justify them.

## In summary

Step 15 closes the loop on "how does a tool talk to an authenticated API without ever putting the credential in a receipt." `SecretValue` carries the credential through memory with drop-zeroing and a redacted Debug; `SecretBroker` is the trait every backend implements; `HttpFetchTool::with_broker` makes the integration concrete; `metadata.secrets_used` carries the *reference name* up to the kernel; `secret_used` provenance edges record the credential touch in the audit log. The value never appears in receipts, in error messages, in `Debug`, or in `Display`. The kernel's audit chain answers "did this run use privileged credentials, and which ones" by structure — without re-running the tool, and without knowing the secrets it consumed.
