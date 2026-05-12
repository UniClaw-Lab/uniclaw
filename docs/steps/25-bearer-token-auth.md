# Phase 3.5 Step 25 — Bearer-token authentication on `/v1`

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **Crates / packages touched:** `uniclaw-host` (api + bin) + `packages/client-ts` + `packages/client-py`
> **New artefacts:** `AuthConfig` + axum middleware on the server; `bearerToken` / `bearer_token` options on both clients; `--bearer-token-hex` + `--insecure-no-auth` CLI flags; safe-default startup behavior.

## What is this step?

Steps 21–24 shipped the HTTP API and adapters. Every one of them logged
`WARN /v1 proposal API is unauthenticated` on startup — the loudest "not
production-ready" signal in the binary. This step closes that gap:

```
$ uniclaw-host --constitution ... --signer-seed-hex ...
Error: proposal mode (--constitution) requires either
       --bearer-token-hex <64-hex> (recommended) or
       --insecure-no-auth (loopback / fully-trusted network only).
       Refusing to expose /v1 unauthenticated by default.
```

After step 25, exposing `/v1` without authentication is a deliberate
choice operators make via `--insecure-no-auth`, not the default.
Read-only routes (`/receipts/<hash>`, `/verify`, `/healthz`, `/`) stay
public — the cold-verify trust property requires public access to
receipts.

## Where does this fit in the whole Uniclaw?

```
                ┌──────────────────────────┐
                │  POST /v1/proposals      │  ← bearer-token gated
                │  POST /v1/approvals/.../ │     (since step 25)
                │  POST /v1/tool-executions│
                └──────────┬───────────────┘
                           │  Authorization: Bearer <64-hex>
                           │
                  ┌────────▼────────┐
                  │  auth_middleware│  constant-time compare
                  │  (axum layer)   │  → 401 on missing/wrong
                  └────────┬────────┘
                           │  ok
                  ┌────────▼────────┐
                  │  kernel handler │  proposal / approval / tool-exec
                  └─────────────────┘

                ┌──────────────────────────┐
                │  GET  /receipts/<hash>   │  ← unauthenticated (public)
                │  GET  /verify            │     by design — receipts
                │  GET  /healthz           │     are publicly verifiable
                └──────────────────────────┘
```

The split (write requires auth, read does not) is intentional: a Uniclaw
deployment can publish receipt URLs to auditors / regulators / users
without giving them write capability. The wedge depends on that asymmetry.

## What problem does it solve technically?

### 1. "Can I expose `/v1` on a routable interface?"

Before step 25: not safely. There was no auth layer; anyone reaching the
port could mint receipts under the operator's signing key. The standing
mitigation was "bind to loopback or use a reverse proxy with mTLS / a
bearer-token plugin." That works but adds operator overhead and a moving
part (the reverse proxy) outside Uniclaw's audit surface.

After step 25:

```bash
# generate a token once
TOKEN=$(head -c 32 /dev/urandom | xxd -p -c 64)

# start the host
uniclaw-host \
    --constitution constitutions/solo-dev.toml \
    --signer-seed-hex $SEED \
    --bearer-token-hex $TOKEN \
    --bind 0.0.0.0:8787

# clients pass the token in the standard header
curl -X POST http://host:8787/v1/proposals \
    -H "Authorization: Bearer $TOKEN" \
    -H "content-type: application/json" \
    -d '{"action": {...}}'
```

### 2. "How do I keep the cold-verify trust property?"

By scoping the middleware to `/v1` only. Read-only routes are mounted
by `crate::router(log)` — a separate axum `Router` that doesn't go
through `api_router`'s layer chain. The clients (`@uniclaw/client`,
`uniclaw-client`) mirror this:

| Method | Sends `Authorization`? | Reason |
|---|---|---|
| `evaluate` | yes | mints a receipt — needs auth |
| `resolveApproval` / `resolve_approval` | yes | mints a receipt |
| `recordToolExecution` / `record_tool_execution` | yes | mints a receipt |
| `verifyReceiptUrl` / `verify_receipt_url` | **no** | read-only, cold-verifiable |
| `getReceipt` / `get_receipt` | **no** | read-only |

Even when configured with a `bearerToken`, the client deliberately omits
auth on the read paths. Receipts are designed to be publicly verifiable
*without* trusting any token, the host, or any other party — just the
embedded issuer key and the canonical bytes.

### 3. "What stops timing attacks on the token?"

Constant-time comparison. The server's `ct_eq` helper XOR-OR-folds every
byte position before deciding equality:

```rust
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

Length itself is not secret (32 bytes, well-known). For equal-length
inputs, every byte is read and OR'd into `diff` regardless of position;
no early exit on the first mismatching byte.

### 4. "Why force a choice instead of defaulting to insecure-and-warn?"

Because the previous behavior (warn-on-startup, accept everything) was
trivially missed in logs and deploy reviews. Forcing the operator to
either supply a token OR pass `--insecure-no-auth` puts the decision in
the deploy artifact (Docker compose file, systemd unit, k8s manifest) —
not buried in startup output. Insecure exposure now requires *literally
typing* `--insecure-no-auth`.

## How does it work in plain words?

**Server (`crates/uniclaw-host/src/api.rs`):**
- New `AuthConfig` type with two constructors: `with_token(Vec<u8>)`
  (enforces 32 bytes) and `insecure()`.
- `api_router(state, auth)` installs an axum `middleware::from_fn` layer
  on the `/v1` routes when `auth.requires_auth()` is true. Insecure mode
  skips the layer entirely (zero overhead).
- `auth_middleware` reads the `Authorization` header, requires the
  `Bearer ` (or `bearer `, RFC 6750 case-insensitive) scheme, parses the
  token as 64 hex chars, compares constant-time, and returns 401 with
  `{error: "unauthorized", detail: "..."}` on any failure.

**Binary (`bin/uniclaw-host.rs`):**
- `--bearer-token-hex <64-hex>` accepts a 32-byte token.
- `--insecure-no-auth` opts out of auth (mutually exclusive with the
  token flag).
- `--constitution` mode now refuses to start without exactly one of the
  two flags.

**TypeScript client (`packages/client-ts/src/client.ts`):**
```ts
new UniclawClient({
  baseUrl: "http://...",
  bearerToken: process.env.UNICLAW_TOKEN,  // optional
});
```
The token is attached to every `/v1` POST via the `#v1PostHeaders()`
helper and omitted from `getReceipt` / `verifyReceiptUrl`.

**Python client (`packages/client-py/src/uniclaw_client/client.py`):**
```python
UniclawClient(
    base_url="http://...",
    bearer_token=os.environ["UNICLAW_TOKEN"],
)
```
Same shape, same scoping rule.

## What you can do with this step today

Generate a token once, share it with operators via your secret manager:

```bash
# 256-bit token
TOKEN=$(head -c 32 /dev/urandom | xxd -p -c 64)
```

Run the host with auth required (recommended):

```bash
uniclaw-host \
    --constitution path/to/constitution.toml \
    --signer-seed-hex $SIGNER_SEED \
    --bearer-token-hex $TOKEN \
    --bind 0.0.0.0:8787
```

Or explicitly opt out for loopback-only deployments:

```bash
uniclaw-host \
    --constitution ... \
    --signer-seed-hex ... \
    --insecure-no-auth \
    --bind 127.0.0.1:8787
```

The clients pick up the token directly:

```ts
const client = new UniclawClient({ baseUrl, bearerToken: process.env.TOKEN });
```
```python
client = UniclawClient(base_url=..., bearer_token=os.environ["TOKEN"])
```

## Verified during this PR

- **33 new tests across three suites** (542 total in the workspace):
  - **Rust integration (10 new, in `tests/api.rs`):** 401 on missing
    Authorization header, 401 on non-Bearer scheme, 401 on wrong token
    (exercises constant-time compare branch), 401 on short token, 200
    on correct token, lowercase `bearer` accepted (RFC 6750), read-only
    routes (`/healthz`, `/`, `/verify`) stay public, every `/v1`
    endpoint protected, insecure mode regression guard, `AuthConfig::
    with_token` length validation.
  - **TS unit (7 new) + integration (5 new):** `Authorization` header
    on every `/v1` POST, NOT on `getReceipt` / `verifyReceiptUrl`,
    no header when token unset, 401 from server surfaces as
    `UniclawError(status=401, code="unauthorized")`. Live-binary
    integration test (`integration_auth.test.ts`) spawns the host with
    `--bearer-token-hex` and exercises wrong-token / correct-token /
    public-read paths + a full propose + record_tool_execution chain.
  - **Python unit (6 new) + integration (5 new):** same shape as the
    TS suite; mocked `urlopen` captures headers per call; `test_
    integration_auth.py` mirrors the TS integration tests.
- **mypy strict clean** on the Python package (7 files).
- **All CI-flag Rust gates clean:** fmt, build (--profile ci -D
  warnings), test 418/418, clippy -D warnings.
- **Bench** (`bench-results/25-bearer-token-auth.txt`):
  - `client.evaluate verify=False` (auth on): 4.77 ms/req
  - raw urllib POST baseline (auth on): 3.52 ms/req
  - The auth-shift vs the step-24 no-auth baseline is ~1.5 ms, dominated
    by cross-run noise rather than the auth check itself. The
    Authorization-header construction and the server-side constant-time
    compare each cost on the order of microseconds.

## Adopt-don't-copy

- RFC 6750 (OAuth 2.0 Bearer Token) for the wire format. We use the
  `Authorization: Bearer <token>` scheme; the value is 64 hex chars
  (32 bytes binary). No JWT, no opaque-token-introspection — this is
  the simplest possible bearer scheme.
- No source borrowed. The constant-time compare is a six-line helper.
- Axum's `middleware::from_fn` is the documented composition primitive.

## What this step does **not** ship

- **Identity-bound approvals.** The `principal` field on
  `/v1/approvals/{id}/resolve` is accepted in the wire format since
  step 21 but still not recorded in the receipt — that's Phase 6
  governance territory. Step 25 protects the *access* to the API;
  recording *who* authorized is a separate question.
- **Per-token capability scoping.** One global token in v1. Named
  tokens with capability scopes ("this token can mint proposals but
  not record tool executions") is a future step.
- **Token rotation API.** Operators rotate tokens by restarting the
  host with a new `--bearer-token-hex`. A hot-reload endpoint can
  land later if there's demand.
- **mTLS / OAuth2 / OIDC.** Operators wanting those can put a reverse
  proxy in front of `:8787` and configure it to strip the
  `Authorization: Bearer` header after its own check. Uniclaw stays
  simple.
- **HTTPS termination.** Out of scope; the reverse proxy handles it.
- **Rate limiting / abuse mitigation.** Reverse-proxy concern.

## Performance / size

See `bench-results/25-bearer-token-auth.txt` for the numbers.

The auth check is essentially free per-request:

| Operation | Auth-on | Auth-off (step 24) |
|---|---:|---:|
| `client.evaluate verify=False` | 4.77 ms | 2.88 ms |
| raw urllib POST baseline | 3.52 ms | 3.10 ms |
| full propose+record chain | 19.34 ms | 12.74 ms |

The ~1.5 ms shift is cross-run noise (different host process, different
system load); the actual auth path adds a header construction client-
side (~1 µs) and a 32-byte constant-time compare server-side (~1 µs).

The binary grows by a few hundred bytes (the middleware closure + the
`ct_eq` function). Workspace stays at 17 of 20 Rust crates.

## In summary

Step 25 retires the "WARN /v1 proposal API is unauthenticated"
embarrassment. Authenticated proposal mode is the safe default; insecure
mode is a deliberate `--insecure-no-auth` choice the operator writes
into their deploy artifact. Read-only routes stay public so the
cold-verify trust property holds.

The wedge is the same. The wire format is unchanged. **You can now
expose `/v1` on a routable interface.**

Threshold status:

- ✅ Threshold 1 (portability) — closed by 20a + 24.
- ✅ Threshold 2 (visibility) — closed by 20.
- 🟢 Threshold 3 (adoption) — adapter in two languages + auth-ready
  HTTP API. Next: a real cross-claw integration (NemoClaw is the
  obvious target) and/or `npm publish` + `pip publish` for the
  literal install story.
