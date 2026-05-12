"""Unit tests for ``UniclawClient`` with mocked ``urlopen``. Cover
the request shape (snake_case wire / Pythonic API), the response
parsing, the discriminated union, the redaction wire conversion,
and the error mapping.

The integration test (``tests/test_integration.py``) covers the
live-binary end-to-end flow.
"""

from __future__ import annotations

import io
import json
from typing import Any, Iterator
from unittest.mock import patch

import pytest

from uniclaw_client import (
    Action,
    Redaction,
    RuleMatch,
    UniclawClient,
    UniclawError,
)


BASE = "http://127.0.0.1:9999"

ALLOWED_RESP = {
    "decision": "allowed",
    "content_id": "a" * 64,
    "receipt_url": f"/receipts/{'a' * 64}",
    "issuer": "b" * 64,
    "sequence": 0,
    "schema_version": 2,
}

DENIED_RESP = {
    "decision": "denied",
    "content_id": "c" * 64,
    "receipt_url": f"/receipts/{'c' * 64}",
    "issuer": "b" * 64,
    "sequence": 1,
    "schema_version": 2,
}

PENDING_RESP = {
    "decision": "pending",
    "content_id": "d" * 64,
    "receipt_url": f"/receipts/{'d' * 64}",
    "issuer": "b" * 64,
    "sequence": 2,
    "schema_version": 2,
}

APPROVED_RESP = {
    "decision": "approved",
    "content_id": "e" * 64,
    "receipt_url": f"/receipts/{'e' * 64}",
    "issuer": "b" * 64,
    "sequence": 3,
    "schema_version": 2,
}

TOOL_EXEC_RESP = {
    "decision": "allowed",
    "content_id": "9" * 64,
    "receipt_url": f"/receipts/{'9' * 64}",
    "issuer": "b" * 64,
    "sequence": 4,
    "schema_version": 2,
}


class _FakeHTTPResponse:
    """Minimal stand-in for urllib's HTTPResponse context manager."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *_exc: object) -> None:
        pass


class _Recorder:
    """Captures urlopen calls so tests can assert request shape."""

    def __init__(self, handlers: dict[str, dict[str, Any]]) -> None:
        # handlers: "METHOD URL" → {"status": int, "body": dict|str}
        self.handlers = handlers
        self.calls: list[dict[str, Any]] = []

    def __call__(self, req: Any, **_kwargs: Any) -> _FakeHTTPResponse:
        url = req.full_url
        method = req.get_method()
        body: Any = None
        if req.data:
            try:
                body = json.loads(req.data.decode("utf-8"))
            except json.JSONDecodeError:
                body = req.data.decode("utf-8", errors="replace")
        # urllib.request.Request stores headers in `req.headers`
        # (a dict with title-cased keys). We normalize to lowercase
        # for assertion ergonomics.
        headers: dict[str, str] = {
            k.lower(): v for k, v in dict(req.headers).items()
        }
        self.calls.append({"url": url, "method": method, "body": body, "headers": headers})
        key = f"{method} {url}"
        handler = self.handlers.get(key)
        if handler is None:
            from urllib.error import HTTPError

            raise HTTPError(url, 599, f"unhandled mock: {key}", {}, io.BytesIO(b""))
        status = handler.get("status", 200)
        resp_body = handler["body"]
        body_bytes = (
            json.dumps(resp_body).encode("utf-8") if isinstance(resp_body, (dict, list)) else str(resp_body).encode("utf-8")
        )
        if status >= 400:
            from urllib.error import HTTPError

            raise HTTPError(url, status, "mock", {}, io.BytesIO(body_bytes))
        return _FakeHTTPResponse(status, body_bytes)


@pytest.fixture()
def mock_urlopen() -> Iterator[_Recorder]:
    """Yields a Recorder; tests configure handlers before issuing calls."""
    rec = _Recorder({})
    with patch("urllib.request.urlopen", side_effect=rec):
        yield rec


def client(*, verify_by_default: bool = False) -> UniclawClient:
    return UniclawClient(base_url=BASE, verify_by_default=verify_by_default)


# ---------------------------------------------------------------------
# evaluate — wire shape
# ---------------------------------------------------------------------


def test_evaluate_posts_to_proposals_with_snake_case_body(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": ALLOWED_RESP}
    c = client()
    c.evaluate(Action(kind="http.fetch", target="https://example.com/", input_hash="00" * 32))
    assert len(mock_urlopen.calls) == 1
    assert mock_urlopen.calls[0]["url"] == f"{BASE}/v1/proposals"
    assert mock_urlopen.calls[0]["method"] == "POST"
    assert mock_urlopen.calls[0]["body"] == {
        "action": {
            "kind": "http.fetch",
            "target": "https://example.com/",
            "input_hash": "00" * 32,
        }
    }


def test_evaluate_returns_allowed_with_absolute_url(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": ALLOWED_RESP}
    c = client()
    d = c.evaluate(Action(kind="http.fetch", target="x", input_hash="00" * 32))
    assert d.kind == "allowed"
    assert d.content_id == "a" * 64
    assert d.receipt_url == f"{BASE}/receipts/{'a' * 64}"
    assert d.issuer == "b" * 64
    assert d.sequence == 0
    assert d.schema_version == 2


def test_evaluate_strips_trailing_slashes(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": ALLOWED_RESP}
    c = UniclawClient(base_url=f"{BASE}////", verify_by_default=False)
    c.evaluate(Action(kind="x", target="y", input_hash="00" * 32))
    assert mock_urlopen.calls[0]["url"] == f"{BASE}/v1/proposals"


# ---------------------------------------------------------------------
# evaluate — decision variants
# ---------------------------------------------------------------------


def test_evaluate_maps_denied(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": DENIED_RESP}
    d = client().evaluate(Action(kind="shell.exec", target="rm", input_hash="00" * 32))
    assert d.kind == "denied"


def test_evaluate_maps_pending(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": PENDING_RESP}
    d = client().evaluate(Action(kind="x", target="/admin/", input_hash="00" * 32))
    assert d.kind == "pending"


def test_evaluate_unknown_decision_raises(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {
        "body": {**ALLOWED_RESP, "decision": "weird"},
    }
    with pytest.raises(UniclawError, match="unknown decision"):
        client().evaluate(Action(kind="x", target="y", input_hash="00" * 32))


# ---------------------------------------------------------------------
# resolve_approval
# ---------------------------------------------------------------------


def test_resolve_approval_posts_to_resolve_url(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/approvals/{'d' * 64}/resolve"] = {
        "body": APPROVED_RESP,
    }
    d = client().resolve_approval(
        "d" * 64, principal="operator@example.com", outcome="approved",
    )
    assert d.kind == "approved"
    assert mock_urlopen.calls[0]["body"] == {
        "principal": "operator@example.com",
        "outcome": "approved",
    }


def test_resolve_approval_404(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/approvals/{'f' * 64}/resolve"] = {
        "status": 404,
        "body": {"error": "not_found", "detail": "no receipt"},
    }
    with pytest.raises(UniclawError) as exc:
        client().resolve_approval(
            "f" * 64, principal="x", outcome="approved",
        )
    assert exc.value.status == 404
    assert exc.value.code == "not_found"


def test_resolve_approval_409(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/approvals/{'a' * 64}/resolve"] = {
        "status": 409,
        "body": {"error": "conflict", "detail": "not pending"},
    }
    with pytest.raises(UniclawError) as exc:
        client().resolve_approval(
            "a" * 64, principal="x", outcome="approved",
        )
    assert exc.value.status == 409


# ---------------------------------------------------------------------
# record_tool_execution
# ---------------------------------------------------------------------


def test_record_tool_execution_minimum_shape(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {"body": TOOL_EXEC_RESP}
    d = client().record_tool_execution(
        allowed_receipt_id="f" * 64,
        output_hash="11" * 32,
    )
    assert d.kind == "allowed"
    assert mock_urlopen.calls[0]["body"] == {
        "allowed_receipt_id": "f" * 64,
        "output_hash": "11" * 32,
    }


def test_record_tool_execution_includes_secrets_only_when_non_empty(
    mock_urlopen: _Recorder,
) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {"body": TOOL_EXEC_RESP}
    client().record_tool_execution(
        allowed_receipt_id="f" * 64,
        output_hash="11" * 32,
        secrets_used=["github.token", "slack.webhook"],
    )
    assert mock_urlopen.calls[0]["body"] == {
        "allowed_receipt_id": "f" * 64,
        "output_hash": "11" * 32,
        "secrets_used": ["github.token", "slack.webhook"],
    }


def test_record_tool_execution_omits_empty_secrets(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {"body": TOOL_EXEC_RESP}
    client().record_tool_execution(
        allowed_receipt_id="f" * 64,
        output_hash="11" * 32,
        secrets_used=[],
    )
    # Empty list omitted (smaller wire body; server's #[serde(default)]
    # treats either as equivalent).
    assert mock_urlopen.calls[0]["body"] == {
        "allowed_receipt_id": "f" * 64,
        "output_hash": "11" * 32,
    }


def test_record_tool_execution_camelcase_redaction(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {"body": TOOL_EXEC_RESP}
    client().record_tool_execution(
        allowed_receipt_id="f" * 64,
        output_hash="11" * 32,
        redaction=Redaction(
            redacted_output_hash="22" * 32,
            stack_hash="33" * 32,
            matches=(RuleMatch(rule_id="github_pat", count=1),),
        ),
    )
    assert mock_urlopen.calls[0]["body"] == {
        "allowed_receipt_id": "f" * 64,
        "output_hash": "11" * 32,
        "redaction": {
            "redacted_output_hash": "22" * 32,
            "stack_hash": "33" * 32,
            "matches": [{"rule_id": "github_pat", "count": 1}],
        },
    }


def test_record_tool_execution_failure_shape(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {"body": TOOL_EXEC_RESP}
    client().record_tool_execution(
        allowed_receipt_id="f" * 64,
        error="connection refused",
    )
    assert mock_urlopen.calls[0]["body"] == {
        "allowed_receipt_id": "f" * 64,
        "error": "connection refused",
    }


def test_record_tool_execution_surfaces_400(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {
        "status": 400,
        "body": {"error": "bad_request", "detail": "exactly one of output_hash or error must be set"},
    }
    with pytest.raises(UniclawError) as exc:
        client().record_tool_execution(allowed_receipt_id="f" * 64)
    assert exc.value.status == 400
    assert exc.value.code == "bad_request"


def test_record_tool_execution_surfaces_404(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {
        "status": 404,
        "body": {"error": "not_found", "detail": "no receipt"},
    }
    with pytest.raises(UniclawError) as exc:
        client().record_tool_execution(allowed_receipt_id="f" * 64, output_hash="11" * 32)
    assert exc.value.status == 404


def test_record_tool_execution_surfaces_409(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {
        "status": 409,
        "body": {"error": "conflict", "detail": "not tool.*"},
    }
    with pytest.raises(UniclawError) as exc:
        client().record_tool_execution(allowed_receipt_id="f" * 64, output_hash="11" * 32)
    assert exc.value.status == 409


# ---------------------------------------------------------------------
# get_receipt
# ---------------------------------------------------------------------


def test_get_receipt_returns_parsed_json(mock_urlopen: _Recorder) -> None:
    receipt_body = {"version": 1, "body": {"foo": "bar"}}
    mock_urlopen.handlers[f"GET {BASE}/receipts/{'a' * 64}"] = {"body": receipt_body}
    r = client().get_receipt("a" * 64)
    assert r == receipt_body
    assert mock_urlopen.calls[0]["method"] == "GET"


def test_get_receipt_404_surfaces(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"GET {BASE}/receipts/{'a' * 64}"] = {
        "status": 404,
        "body": {"error": "receipt_not_found", "detail": "..."},
    }
    with pytest.raises(UniclawError) as exc:
        client().get_receipt("a" * 64)
    assert exc.value.status == 404


# ---------------------------------------------------------------------
# Step 25 — bearer-token auth
# ---------------------------------------------------------------------


TOKEN_HEX = "a5" * 32


def test_auth_attaches_bearer_header_on_post_proposals(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": ALLOWED_RESP}
    c = UniclawClient(
        base_url=BASE,
        verify_by_default=False,
        bearer_token=TOKEN_HEX,
    )
    c.evaluate(Action(kind="x", target="y", input_hash="00" * 32))
    assert mock_urlopen.calls[0]["headers"]["authorization"] == f"Bearer {TOKEN_HEX}"
    assert mock_urlopen.calls[0]["headers"]["content-type"] == "application/json"


def test_auth_attaches_bearer_header_on_resolve(mock_urlopen: _Recorder) -> None:
    cid = "d" * 64
    mock_urlopen.handlers[f"POST {BASE}/v1/approvals/{cid}/resolve"] = {"body": APPROVED_RESP}
    c = UniclawClient(
        base_url=BASE,
        verify_by_default=False,
        bearer_token=TOKEN_HEX,
    )
    c.resolve_approval(cid, principal="ops", outcome="approved")
    assert mock_urlopen.calls[0]["headers"]["authorization"] == f"Bearer {TOKEN_HEX}"


def test_auth_attaches_bearer_header_on_tool_execution(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/tool-executions"] = {"body": TOOL_EXEC_RESP}
    c = UniclawClient(
        base_url=BASE,
        verify_by_default=False,
        bearer_token=TOKEN_HEX,
    )
    c.record_tool_execution(allowed_receipt_id="f" * 64, output_hash="11" * 32)
    assert mock_urlopen.calls[0]["headers"]["authorization"] == f"Bearer {TOKEN_HEX}"


def test_auth_does_not_attach_header_on_get_receipt(mock_urlopen: _Recorder) -> None:
    receipt = {"version": 1, "body": {"foo": "bar"}}
    cid = "a" * 64
    mock_urlopen.handlers[f"GET {BASE}/receipts/{cid}"] = {"body": receipt}
    c = UniclawClient(
        base_url=BASE,
        verify_by_default=False,
        bearer_token=TOKEN_HEX,
    )
    c.get_receipt(cid)
    assert mock_urlopen.calls[0]["method"] == "GET"
    # Read-only routes must not carry auth — the receipt-is-public
    # property depends on it.
    assert "authorization" not in mock_urlopen.calls[0]["headers"]


def test_no_token_means_no_authorization_header(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {"body": ALLOWED_RESP}
    c = UniclawClient(base_url=BASE, verify_by_default=False)
    c.evaluate(Action(kind="x", target="y", input_hash="00" * 32))
    assert "authorization" not in mock_urlopen.calls[0]["headers"]
    assert mock_urlopen.calls[0]["headers"]["content-type"] == "application/json"


def test_server_401_surfaces_as_unauthorized_error(mock_urlopen: _Recorder) -> None:
    mock_urlopen.handlers[f"POST {BASE}/v1/proposals"] = {
        "status": 401,
        "body": {"error": "unauthorized", "detail": "missing Authorization header"},
    }
    c = UniclawClient(base_url=BASE, verify_by_default=False)
    with pytest.raises(UniclawError) as exc:
        c.evaluate(Action(kind="x", target="y", input_hash="00" * 32))
    assert exc.value.status == 401
    assert exc.value.code == "unauthorized"
