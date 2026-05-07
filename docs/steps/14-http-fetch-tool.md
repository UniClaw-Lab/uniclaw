# Phase 3 Step 2 — Native HTTP Fetch Tool with Capability Enforcement

> **Phase:** 3 — Tools and Secrets
> **PR:** _this PR_
> **Crate introduced:** `uniclaw-tools-http`
> **Crate updated:** `uniclaw-tools` (`Capability::is_granted_by` helper)

## What is this step?

This step ships **the first real `Tool` implementation** in the workspace, validating the `Tool` trait + `Capability` enum + `ApprovalPolicy` machinery from step 13 against actual network code. The tool is `HttpFetchTool` — a synchronous, capability-checked HTTP GET with built-in SSRF defense and bounded response reads. It's small (~280 LOC of impl + 720 LOC of tests), fast to review, and makes the wedge concrete: a Uniclaw deployment can now do something useful, end-to-end and auditable.

It also proves a deliberate choice in the Phase 3 ordering: **build a real Rust-native tool first, then add the WASM substrate**. Two reasons:

1. **The Capability enum needs validating against real I/O.** Step 13 declared `NetConnect(GlobPattern)` but nothing exercised it. Now the host-allowlist gate has a concrete user, and the trait surface is proven before we commit to the WASM Component Model in step 16.
2. **A WASM tool runtime needs capability enforcement *before* it can do anything useful.** Shipping WASM first would mean either (a) WASM tools that can't do I/O (boring), or (b) WASM tools that can do I/O without any capability gate (insecure). This step plus the next two (secrets, then WASM) sequence the dependencies correctly.

## Where does this fit in the whole Uniclaw?

Phase 3 ships the **Hands** layer (master plan §9). Step 13 was the architecture; this step starts populating it.

```
                 Caller
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
     Kernel              ToolHost
   (proposal +         (registry,
    approval)           routes by name)
         │                   │
         │                   ▼
         │           HttpFetchTool::call
         │                   │
         │     ┌─────────────┼─────────────┐
         │     ▼             ▼             ▼
         │  Capability    SSRF check   ureq blocking
         │  ::is_granted_by             GET (no
         │     │                       redirects,
         │     ▼                       bounded read)
         │  pass/deny           │
         │                      ▼
         │              JSON envelope
         │              (status + headers
         │               + body_b64)
         │                      │
         ▼                      │
   RecordToolExecution ◀────────┘
   (input_hash + output_hash → audit chain)
```

After this step, the audit chain finally records actual external work: every HTTP fetch produces a proposal receipt (capability + budget gates) and an execution receipt (input + output hash, signed) — both linked in provenance.

## What problem does it solve technically?

Four problems.

### 1. "How do we stop a tool from connecting wherever it wants?"

The `HttpFetchTool` is constructed with a list of allowed-host glob patterns. Every request runs through `Capability::is_granted_by` against the manifest's declared capabilities **before** the HTTP client is touched:

```rust
let tool = HttpFetchTool::with_allowlist(vec![
    GlobPattern::new("api.example.com"),
    GlobPattern::new("*.googleapis.com"),
]);
// A request to evil.test fails with ToolError::CapabilityDenied,
// no socket opened.
```

This is the gate other tools will use too — `Capability::is_granted_by(declared, requested) -> bool` is now in `uniclaw-tools` as a small public helper.

### 2. "Even if a host is allowlisted, what if it's a private IP?"

Server-Side Request Forgery: an agent told to fetch `http://127.0.0.1:8500/v1/secret` could read internal services, `http://169.254.169.254/latest/meta-data/iam/security-credentials/` could read AWS metadata, `http://192.168.1.1/admin` could touch home-network devices. The `ssrf::is_disallowed_ip` check refuses literal IPs in private/loopback/link-local/multicast/reserved ranges (RFC-cited table in the module doc) by default.

The default config has `allow_private_ips: false`. Tests use `HttpFetchConfig::for_test_localhost()` to override (since the mock server lives on `127.0.0.1`); production never flips the bit.

### 3. "What if a server returns a 10 GB response?"

Bounded read. `HttpFetchConfig::max_response_bytes` (default 10 MiB) caps the body. The tool reads `max + 1` bytes via `Read::take(...)`; if it gets exactly that many, it knows there's more and refuses with `ToolError::Failed("response exceeded max_response_bytes (...)"`. **Partial bodies are never returned** — either the whole body fits and it's served, or nothing.

### 4. "What if the server redirects to evil.test?"

Auto-following redirects would let a 302 hop bypass the capability allowlist (the allowlist applies to the URL the caller submits, not the URL the server bounces them to). `HttpFetchTool` builds its `ureq::Agent` with `.redirects(0)` — 3xx responses come back as the literal status code and `Location` header; the caller decides whether to issue a follow-up request (which goes through the allowlist again).

## How does it work in plain words?

```rust
// Build a tool that's only allowed to talk to api.example.com.
let tool = HttpFetchTool::with_allowlist(vec![
    GlobPattern::new("api.example.com"),
]);

// Construct a Tool call. In a real flow, the kernel has already
// authorized this via a Proposal receipt; the input_hash matches
// the receipt's action.input_hash.
let input = serde_json::to_vec(&HttpFetchInput {
    url: "https://api.example.com/v1/health".into(),
})?;
let call = ToolCall {
    tool_name: "http_fetch".into(),
    target: "https://api.example.com/v1/health".into(),
    input: input.clone(),
    input_hash: Digest(*blake3::hash(&input).as_bytes()),
};

// Execute. Returns ToolOutput { bytes (the JSON envelope), output_hash }.
let output = tool.call(&call)?;

// Submit back to the kernel as RecordToolExecution. The kernel mints
// the $kernel/tool/executed receipt with input/output hashes in
// provenance, linking back to the prior Allowed receipt.
```

The call pipeline:

| Step | What | Failure mode |
|---|---|---|
| 1 | Parse `call.input` as `HttpFetchInput` JSON | `ToolError::InvalidInput` |
| 2 | Parse URL, validate scheme is `http`/`https`, extract host | `ToolError::InvalidInput` |
| 3 | `Capability::is_granted_by(declared, NetConnect(host))` | `ToolError::CapabilityDenied` |
| 4 | `ssrf::is_disallowed_ip(host)` (if not `allow_private_ips`) | `ToolError::Failed` |
| 5 | `agent.get(url).call()` (ureq, blocking, no redirects) | `ToolError::Timeout` / `Failed` |
| 6 | Read body bounded by `max_response_bytes + 1` | `ToolError::Failed` (oversize) |
| 7 | Build `HttpFetchOutput { status, headers, body_b64 }` | — |
| 8 | Serialize envelope + BLAKE3 hash → `ToolOutput` | — |

Capability check happens **before** SSRF check. The order matters for error ergonomics: capability is the host-developer's policy, SSRF is the runtime's defense-in-depth. If a request goes to `evil.test` (not in the allowlist) and `evil.test` happens to resolve to a private IP, the user-visible error is "capability denied," not "SSRF refused" — that's the right hierarchy.

## Why this design choice and not another?

- **Why `ureq` not `reqwest` / `hyper`?** ureq is synchronous (matches `Tool::call`'s sync trait), uses pure-Rust rustls, and pulls a fraction of `reqwest`'s deps. Hyper is too low-level for v0 — we'd be re-implementing what ureq already does.
- **Why JSON envelope, not raw bytes?** Status code and headers matter for any non-trivial HTTP usage. A raw-bytes return would lose them. Base64 of the body keeps the envelope JSON-clean while preserving exact bytes for binary responses.
- **Why hand-rolled mock server in tests, not `wiremock` / `mockito`?** This crate already pulls in ureq + url + serde_json + base64 — adding another HTTP-mocking dep just for tests inflates the dep tree. The mock server is ~80 LOC of `std::net::TcpListener` and exercises exactly what we need.
- **Why no async API?** `Tool::call` is sync (decided at step 13). Async runtimes wrap a sync `Tool` in `tokio::task::spawn_blocking` if they need it. `HttpFetchTool` is sync internally for the same reason: ureq is sync, and synchronous code is easier to reason about for the kind of "kernel approves, tool runs, kernel records" three-phase flow Uniclaw uses.
- **Why GET only?** v0 focus. Adding POST/PUT/DELETE means deciding how request bodies are encoded in the input envelope, how Content-Type is chosen, etc. — a separate step. The JSON envelope shape is forwards-compatible.

## Adopt-don't-copy

- **`IronClaw`'s SSRF defense at the HTTP-client layer** — adopted in `ssrf.rs`. Their implementation runs similar IP-range checks before connecting; the table in our module doc lists the same RFCs and adds the IPv6 side. No source borrowed.
- **`OpenFang`'s capability-enforcement-at-the-tool-boundary pattern** — adopted as `Capability::is_granted_by` (uniclaw-tools) called from `HttpFetchTool::call` before any I/O. Our enum + glob matcher is leaner than OpenFang's; same shape.
- **Conventional HTTP-client choices** — ureq, base64, url are standard Rust ecosystem crates with broad use. We pull them as deps; we don't borrow source.

Citations live in the crate's `lib.rs` and `ssrf.rs` adopt-don't-copy sections.

## What you can do with this step today

- Build an `HttpFetchTool` for any allowlisted hostname pattern.
- Call it directly from Rust, or register it in a `ToolHost` and route by name.
- Submit the tool's output as a `KernelEvent::RecordToolExecution`. The kernel mints a receipt linking the input + output hashes back to the prior Allowed proposal receipt. Every fetch is now end-to-end auditable.
- Use `HttpFetchConfig::for_test_localhost()` for tests against your own mock server; **never** use it in production (it disables the SSRF gate).

## Performance baseline (release, x86_64 Linux)

| Operation | Per call |
|---|---|
| Warm fetch, 5-byte body (localhost mock) | **~25 ms** |
| Warm fetch, 1 MiB body (localhost mock) | **~94 ms** (~11 MiB/s) |
| `Capability::is_granted_by` (the capability gate) | sub-microsecond |
| `ssrf::is_disallowed_ip` (the SSRF gate) | sub-microsecond |

The fetch numbers are dominated by **TCP connection setup + the mock server's per-request thread spawn**, not the tool itself. Our mock server returns `connection: close` on every response, defeating ureq's keep-alive; real-world deployments against a server that supports keep-alive will see warm fetches in the low single-digit milliseconds (mostly the TCP RTT). The two capability/SSRF gates are sub-microsecond and not visible in the totals.

## What this step does **not** ship

- **POST/PUT/DELETE/PATCH.** GET only.
- **Custom request headers** (User-Agent only).
- **Cookies** / session state.
- **Auto-redirect following.** A 3xx is surfaced as-is.
- **DNS rebinding defense.** A hostname that resolves to a public IP at parse time but private at connect time slips through. Documented in the crate doc; pinned-resolution is a future step.
- **Duplicate header preservation.** ureq's high-level API surfaces unique header names; multi-instance headers (e.g. `Set-Cookie`) collapse to the first value. Documented; lower-level header iterator in a follow-up.
- **Streaming.** Full body is read into memory before being returned.

These are explicit deferrals, not oversights. v0 is the smallest-real-tool that proves the trait surface; the gaps fill in once usage clarifies which ones matter.

## In summary

Step 14 makes Uniclaw's first agent capability concrete: a capability-checked, SSRF-defended, response-bounded HTTP GET, audited end-to-end via the existing `KernelEvent::RecordToolExecution` flow from step 13. The trait surface from step 13 is now validated against real I/O, the `Capability` enum has a real consumer, and Phase 3 has its first user-facing capability. WASM (step 16) gets to land as a substrate swap behind a proven trait, not as the first proof.
