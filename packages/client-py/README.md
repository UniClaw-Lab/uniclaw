# `boardproof-client` (Python)

Python client + verifier for [BoardProof](https://github.com/UniClaw-Lab/boardproof) receipts. The on-ramp for any Python-based runtime — NemoClaw bridges, compliance tooling, custom agents — that wants to anchor agent actions into BoardProof receipts.

One class, four operations, verify-by-default. Python 3.10+.

## Why this exists

Step 22 shipped the TypeScript client. This Python sibling closes threshold 1 of the deep-strategy thresholds: **a Python developer can `pip install` a verifier + client and validate a BoardProof receipt minted on a Rust kernel — bytes match, on any platform**.

Python is also the de-facto language for compliance tooling (SOC 2, HIPAA, EU AI Act) and the host language for NemoClaw. This package opens both adoption paths directly.

## Install

```bash
pip install boardproof-client
```

Two production dependencies, both with audited security history and precompiled wheels for major platforms:

- [`PyNaCl`](https://pynacl.readthedocs.io/) — Ed25519 (libsodium binding).
- [`blake3`](https://pypi.org/project/blake3/) — BLAKE3 with optional C acceleration.

No HTTP client dependency — the package uses the standard-library `urllib.request`.

## Usage

```python
from boardproof_client import BoardProofClient, Action

client = BoardProofClient(base_url="http://127.0.0.1:8787")

decision = client.evaluate(Action(
    kind="http.fetch",
    target="https://api.example.com/data",
    input_hash="00" * 32,
))

match decision.kind:
    case "allowed":
        run_tool(decision.receipt_url)
    case "denied":
        log_blocked(decision.content_id)
    case "pending":
        final = client.resolve_approval(
            decision.content_id,
            principal="operator@example.com",
            outcome="approved",
        )
```

The `decision` is a discriminated union; match on `.kind` and Python's pattern matching narrows the rest.

### Tool execution (step 23)

```python
from boardproof_client import Redaction, RuleMatch

exec_d = client.record_tool_execution(
    allowed_receipt_id=decision.content_id,
    output_hash="11" * 32,
    secrets_used=["github.token"],
    redaction=Redaction(
        redacted_output_hash="22" * 32,
        stack_hash="33" * 32,
        matches=(RuleMatch(rule_id="github_pat", count=1),),
    ),
)
```

`secrets_used` carries the **reference names** of secrets the tool consumed (e.g. `"github.token"`). The kernel mints one `secret_used` provenance edge per name. **Secret values never cross any wire** — neither to the kernel nor to the receipt.

### Standalone verifier

```python
from boardproof_client import verify_receipt_url

result = verify_receipt_url("http://localhost:8787/receipts/abc...")
if result.ok:
    print("verified", result.content_id_hex, result.decision)
else:
    print("failed:", result.error)
```

## Verify-by-default

Every mint is verified locally before being returned. If the recomputed signature doesn't validate, `BoardProofVerifyError` is raised:

```python
from boardproof_client import BoardProofVerifyError

try:
    client.evaluate(...)
except BoardProofVerifyError as e:
    print("server returned a tampered receipt:", e.detail)
```

Override per-call with `verify=False` or globally with `BoardProofClient(base_url, verify_by_default=False)`.

The verify path runs entirely in-process: JCS canonicalize → BLAKE3 → Ed25519. On the bench machine, that's ~2 ms total — fast enough to be the default. See `bench-results/24-python-client.txt`.

## API surface

```python
class BoardProofClient:
    def __init__(self, base_url: str, *, verify_by_default: bool = True, timeout: float = 10.0): ...

    def evaluate(self, action: Action, *, verify: bool | None = None) -> Decision: ...
    def resolve_approval(self, content_id: str, *, principal: str,
                         outcome: Literal["approved", "denied"],
                         verify: bool | None = None) -> ApprovedDecision | DeniedDecision: ...
    def record_tool_execution(self, *, allowed_receipt_id: str,
                              output_hash: str | None = None,
                              error: str | None = None,
                              secrets_used: Iterable[str] | None = None,
                              redaction: Redaction | None = None,
                              verify: bool | None = None) -> AllowedDecision: ...
    def verify_receipt_url(self, url: str) -> VerifyResult: ...
    def get_receipt(self, content_id: str) -> dict[str, Any]: ...
```

Errors: `BoardProofError` (HTTP status + code + detail) and `BoardProofVerifyError` (content_id + detail).

## Trust model

- **Verify locally.** No HTTP request asks the server whether a receipt is valid; everything happens in the caller's process.
- **Re-verify the content_id too.** The recomputed BLAKE3 hash is compared against the server's claimed `content_id`. If they differ, the server lied about what it returned.
- **No authentication in the wire format** (yet). The BoardProof `--constitution` mode is unauthenticated; expose only on loopback / a trusted segment. A future BoardProof release adds bearer-token auth; this client will pick it up via a custom `urlopen` wrapper.

## Pairs with

- **`boardproof-host --constitution …`** — the Rust sidecar binary. Build with `cargo build --release --bin boardproof-host -p boardproof-host` and run next to your Python process.
- **`@boardproof/verifier`** + **`@boardproof/client`** — the TypeScript siblings. Same wire format, same conformance fixture.

## Testing

```bash
pip install -e .[dev]

# Unit tests (mocked urlopen) + conformance against canonical-v2.json:
python -m pytest

# Integration tests against a live boardproof-host (opt-in):
cargo build --release --bin boardproof-host -p boardproof-host
BOARDPROOF_INTEGRATION=1 python -m pytest

# Type-check:
python -m mypy src/boardproof_client
```

## License

MIT OR Apache-2.0, matching the BoardProof monorepo.
