# Phase 3.5 Step 24 — `uniclaw-client` Python SDK

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **New top-level dir:** `packages/client-py/` (third packaging unit; first two were `@uniclaw/verifier` and `@uniclaw/client`)
> **Workspace:** still 17 of 20 Rust crates — Python package doesn't count

## What is this step?

Step 22 closed threshold 1 *halfway* — the deep-strategy memory's literal portability test reads *"a TypeScript developer can `npm install` a verifier and validate a Uniclaw receipt minted on a Rust kernel"*. After step 22, that's true.

But the SAME memory also says threshold 1 needs *"TS + at least one downstream language"*. **This step adds the downstream language.**

Python is the natural pick:

1. **Compliance tooling is Python.** SOC 2 / HIPAA / EU AI Act evidence pipelines run on Python. A `pip install uniclaw-client` is the on-ramp to every regulated-industry buyer.
2. **NemoClaw is Python.** A future NemoClaw integration uses this package directly.
3. **Different language ⇒ stronger conformance.** Three implementations (Rust kernel, TS verifier, Python verifier) all running over `canonical-v2.json` and producing byte-identical output is the proof that the receipt format genuinely is cross-language.

After this PR, the threshold-1 test is literally true in two languages, and the wedge has a strong "receipt-as-protocol" claim to lean on.

## Where does this fit in the whole Uniclaw?

```
                  ┌──────────────────────────────┐
                  │ canonical-v2.json (5 vectors)│  the single source of truth
                  │   body → canonical_hex       │
                  │   body → blake3_hex          │
                  └────────────────┬─────────────┘
                                   │ asserted by
       ┌───────────────────────────┼───────────────────────────────┐
       ▼                           ▼                               ▼
  ┌─────────────────┐    ┌────────────────────┐         ┌────────────────────┐
  │ Rust            │    │ @uniclaw/verifier  │         │ uniclaw-client     │
  │ uniclaw-receipt │    │ + @uniclaw/client  │         │ (this PR)          │
  │ canonical.rs    │    │ src/canonical.ts   │         │ _canonical.py      │
  └─────────────────┘    └────────────────────┘         └────────────────────┘
        │                          │                              │
        ▼                          ▼                              ▼
   cargo test          vitest (10 conformance asserts)    pytest (11 conformance asserts)
```

All three implementations load the same fixture. Any byte-level divergence fails the conformance test in whichever language drifted first.

## What problem does it solve technically?

### 1. "How do I anchor agent actions from a Python runtime?"

Before step 24, the answer was *"call the HTTP endpoints yourself, parse JSON, manage Ed25519 + BLAKE3 + JCS by hand."* That's the same gap step 22 closed for TypeScript.

After this PR, it's:

```python
from uniclaw_client import UniclawClient, Action

client = UniclawClient(base_url="http://127.0.0.1:8787")

decision = client.evaluate(Action(
    kind="http.fetch",
    target="https://api.example.com/data",
    input_hash=blake3_hex(input_bytes),
))

match decision.kind:
    case "allowed":  ...
    case "denied":   ...
    case "pending":  ...
```

The same discriminated-union shape as the TS client, adapted to Python pattern matching. The full step-23 tool-execution path is also exposed (`client.record_tool_execution(...)` with optional `secrets_used` and `redaction` audit data).

### 2. "How do I prove three implementations agree byte-for-byte?"

By loading the same fixture in all three. `packages/client-py/tests/test_conformance.py` does what `packages/verifier-ts/tests/conformance.test.ts` does — parametrize over the 5 vectors in `canonical-v2.json`, recompute canonical bytes and BLAKE3 hashes, assert byte-identity. 11 assertions per language; **22 cross-language assertions total** that must hold on every PR touching `canonical.rs`, `canonical.ts`, or `_canonical.py`.

### 3. "How does the verify-by-default trust property apply in Python?"

Same as the TS client. After every mint:

1. The client fetches the full receipt JSON via `GET /receipts/<hash>`.
2. It reconstructs canonical body bytes via the in-process JCS port.
3. It recomputes the BLAKE3 content_id and compares against (a) the server's claimed `content_id` AND (b) the URL hash.
4. It verifies the Ed25519 signature against the receipt's embedded issuer key.

If any check fails, `UniclawVerifyError` is raised before the caller sees the decision. The integration test exercises this with a `urlopen` patch that intercepts the GET response, mutates one byte of the body, and confirms the client rejects it (`test_verify_by_default_catches_tampered_receipt`).

### 4. "Why pynacl + blake3 + stdlib urllib?"

Minimal surface. Each dep has a single, focused purpose:

- **`PyNaCl`** — libsodium binding for Ed25519. Audited. No extra functionality we don't use.
- **`blake3`** — official BLAKE3 PyPI package. Ships precompiled wheels for Linux/macOS/Windows + Python 3.10-3.13. Falls back to a pure-Python implementation if no wheel is available (slower but works).
- **`urllib.request`** — Python stdlib. No need for `requests` / `httpx` / `aiohttp` for a simple JSON-over-HTTP client. Anyone wanting custom timeout / auth / retries can wrap or replace the client's request methods.

Total transitive size: ~5 MB installed (libsodium dominates). No native build required for users.

## How does it work in plain words?

Six modules, ~700 LOC across `src/uniclaw_client/`:

- **`_canonical.py`** — JCS port. Python integers + dict[str, ...] + list + str + bool + None. Floats raise.
- **`_hex.py`** — hex helpers (lossless, hex-only).
- **`types.py`** — frozen dataclasses for `Action`, `Decision` (discriminated union via `Literal["..."]` kind field), `Redaction`, `RuleMatch`, `VerifyResult`.
- **`errors.py`** — `UniclawError` (HTTP-status-mapped) and `UniclawVerifyError`.
- **`verify.py`** — `canonicalize`, `compute_content_id_*`, `verify_receipt*`. Uses `pynacl` + `blake3`.
- **`client.py`** — `UniclawClient` class. Wraps `urlopen` with snake_case wire conversion at the boundary. Verify-by-default applies on every mint.

A request flows like this:

```
client.evaluate(Action(...))
   │
   ▼ camelCase Action → snake_case wire dict
   │
urlopen(POST /v1/proposals, json body)
   │
   ▼ parse JSON, validate shape
   │
build AllowedDecision (or DeniedDecision/PendingDecision)
   │
   ▼ if verify_by_default:
   │     urlopen(GET /receipts/<hash>)
   │     JCS canonicalize → BLAKE3 → check content_id
   │     Ed25519 verify against embedded issuer
   │
return Decision
```

## What you can do with this step today

- **Integrate from any Python runtime:**
  ```bash
  pip install uniclaw-client
  ```
- **Run the conformance test** to verify your install matches the canonical fixture:
  ```bash
  cd packages/client-py && python -m pytest tests/test_conformance.py
  ```
- **Drive a full agent flow** end-to-end against `uniclaw-host`: see `tests/test_integration.py` for a worked example (allowed / pending → approved / denied / tool execution with secrets + redaction / tamper rejection).
- **Use just the verifier** (no client needed) in a compliance audit script:
  ```python
  from uniclaw_client import verify_receipt_url
  for url in receipts_to_audit:
      r = verify_receipt_url(url)
      if not r.ok: raise AuditFailure(url, r.error)
  ```

## Verified during this PR

- **65 tests pass** across five files:
  - `test_canonical.py` — 12 unit tests for the JCS port.
  - `test_conformance.py` — 11 cross-language assertions against `canonical-v2.json` (1 format check + 5 canonical bytes + 5 BLAKE3 content_ids). Loads the SAME fixture Rust and TS use.
  - `test_verify.py` — 13 sign+verify roundtrip + tamper detection tests using PyNaCl's deterministic Ed25519.
  - `test_client.py` — 19 unit tests with mocked `urlopen`: wire shape, decision narrowing, redaction camelCase ↔ snake_case, 400/404/409 mapping, baseUrl normalization, `get_receipt`.
  - `test_integration.py` — 10 integration tests against a live `uniclaw-host` subprocess (opt-in via `UNICLAW_INTEGRATION=1`). Includes a tamper test that confirms verify-by-default rejects a mutated receipt over a real HTTP round-trip.
- **mypy strict** clean across all 7 source files.
- **All 4 Rust gates still clean** (no Rust changes): fmt, build, **test 408/408**, clippy.
- **Bench** (`bench-results/24-python-client.txt`):
  - `client.evaluate verify=True`: **5.19 ms/req** — Python is **2.5×–3.5× faster** than the TS client (12-19 ms) because `pynacl` and `blake3` are C-bound, while `@noble/*` is pure-JS.
  - `client.evaluate verify=False`: 2.88 ms/req.
  - Raw urllib POST baseline: 3.10 ms/req.
  - **Client overhead: -0.22 ms/req** (within noise; effectively zero).
  - `record_tool_execution verify=False`: 4.12 ms/req.
  - Full propose+record chain (both verify=True): **12.74 ms/req**.

## Adopt-don't-copy

- The JCS port is from RFC 8785; no source borrowed from any other claw.
- `pynacl` and `blake3` are external dependencies, not vendored.
- No reference claw ships a Python verifier or client; this is net-new territory for the protocol.

## What this step does **not** ship

- **PyPI publish.** Operations task — credentials, release process, namespace reservation on PyPI. The package code, tests, README, and bench are in this PR; publishing is `python -m build && twine upload` once `uniclaw-client` is reserved.
- **Async I/O variant.** Sync first. An `aiohttp`-based async sibling can land later if there's demand. The trust model is identical; only the I/O transport differs.
- **Go / Swift / Java siblings.** Each will conform to the same wire format. Future steps.
- **Schema-version-1 fixture in the conformance test.** v1 receipts use a different canonicalization (legacy `json.dumps`); the conformance fixture is v2-only. v1 verification still works in `verify_receipt` because the canonicalizer dispatches on `schema_version`.
- **A bundled CLI** (`uniclaw-verify-py`). The TS package shipped one as a convenience; the Python package focuses on library use. Anyone wanting a CLI can `python -m uniclaw_client.verify` in a follow-up.

## Performance / size

See `bench-results/24-python-client.txt`. Headline numbers:

| Operation | Python (this PR) | TypeScript (step 22) |
|---|---:|---:|
| `evaluate verify=True` | **5.19 ms** | 12-19 ms |
| `evaluate verify=False` | 2.88 ms | 3.75 ms |
| `record_tool_execution verify=False` | 4.12 ms | 3.11 ms |
| Full chain (both verify=True) | **12.74 ms** | 20.6 ms |

The Python client is faster than the TS client for any operation involving cryptography. Same Rust kernel, same wire format, same trust property — just different language-native crypto.

## In summary

Step 24 closes threshold 1 in the strongest possible way. The receipt is now:

- **Portable** — Rust + TypeScript + Python all produce byte-identical canonical output; all three verify cold.
- **Programmable** in three languages.
- **Installable** via `pip install uniclaw-client` (operations PR away from being on PyPI).

Threshold status:

- ✅ Threshold 1 (portability) — **fully closed.** Two non-Rust languages with byte-identical conformance.
- ✅ Threshold 2 (visibility) — closed by step 20.
- 🟢 Threshold 3 (adoption) — **adapter is now available in two languages, plus the HTTP API.** Next: an actual cross-claw integration (NemoClaw with this Python client is the obvious target), then `npm publish` + `pip publish` for the literal `npm install` / `pip install` story.

The receipt is portable in Rust. The receipt is portable in TypeScript. **The receipt is portable in Python.** Three languages, three test suites, one fixture, one set of bytes.
