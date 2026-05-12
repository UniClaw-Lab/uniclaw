"""``UniclawClient`` — the Python adapter for Uniclaw's HTTP
proposal API (step 21 + step 23).

One class, four operations:

  - ``evaluate(action)``               → POST /v1/proposals
  - ``resolve_approval(content_id, …)`` → POST /v1/approvals/{id}/resolve
  - ``record_tool_execution(…)``       → POST /v1/tool-executions
  - ``get_receipt(content_id)``        → GET  /receipts/{hash}

Plus ``verify_receipt_url(url)`` which re-exports the verify path.

**Verify-by-default.** Every mint goes through the verifier before
being returned to the caller. If the recomputed signature doesn't
validate (or the recomputed content_id differs from the server's
claim), :class:`UniclawVerifyError` is raised. The caller can opt
out per-call with ``verify=False`` or globally with
``verify_by_default=False``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Iterable, Literal

from .errors import UniclawError, UniclawVerifyError
from .types import (
    Action,
    AllowedDecision,
    ApprovedDecision,
    Decision,
    DeniedDecision,
    PendingDecision,
    Redaction,
    VerifyResult,
)
from .verify import verify_receipt_json


class UniclawClient:
    """Idiomatic Python client for the Uniclaw HTTP proposal API.

    One instance per ``uniclaw-host`` you talk to.

    Args:
        base_url: e.g. ``"http://127.0.0.1:8787"``. Trailing slashes
            are tolerated.
        verify_by_default: When ``True`` (default), every mint is
            verified locally against its embedded issuer key before
            being returned. Per-call override via the ``verify``
            keyword on :meth:`evaluate` / :meth:`resolve_approval` /
            :meth:`record_tool_execution`.
        timeout: HTTP timeout in seconds (passed to ``urlopen``).
    """

    def __init__(
        self,
        base_url: str,
        *,
        verify_by_default: bool = True,
        timeout: float = 10.0,
    ) -> None:
        # Strip trailing slashes so f"{base_url}/v1/…" doesn't produce
        # a double slash.
        self._base_url = base_url.rstrip("/")
        self._verify_by_default = verify_by_default
        self._timeout = timeout

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    def evaluate(self, action: Action, *, verify: bool | None = None) -> Decision:
        """Submit an action for evaluation. Returns the kernel's decision
        as a discriminated union (match on ``.kind``).

        Example::

            d = client.evaluate(Action("http.fetch", "https://...", "00"*32))
            match d.kind:
                case "allowed":  run(d.receipt_url)
                case "denied":   block()
                case "pending":  client.resolve_approval(d.content_id, …)
        """
        wire = {
            "action": {
                "kind": action.kind,
                "target": action.target,
                "input_hash": action.input_hash,
            }
        }
        resp = self._post("/v1/proposals", wire)
        decision = self._build_decision(resp)
        self._maybe_verify(decision, verify)
        return decision

    def resolve_approval(
        self,
        content_id: str,
        *,
        principal: str,
        outcome: Literal["approved", "denied"],
        verify: bool | None = None,
    ) -> ApprovedDecision | DeniedDecision:
        """Resolve a pending receipt.

        The kernel re-verifies the pending receipt's signature and
        decision before honouring the resolve; see
        ``Kernel::handle_resolve_approval`` for the gate.
        """
        wire = {"principal": principal, "outcome": outcome}
        resp = self._post(f"/v1/approvals/{content_id}/resolve", wire)
        decision = self._build_decision(resp)
        if decision.kind not in ("approved", "denied"):
            raise RuntimeError(
                f"unexpected resolve response: kind={decision.kind} (server bug?)",
            )
        self._maybe_verify(decision, verify)
        # Type-narrow for static checkers.
        assert isinstance(decision, (ApprovedDecision, DeniedDecision))
        return decision

    def record_tool_execution(
        self,
        *,
        allowed_receipt_id: str,
        output_hash: str | None = None,
        error: str | None = None,
        secrets_used: Iterable[str] | None = None,
        redaction: Redaction | None = None,
        verify: bool | None = None,
    ) -> AllowedDecision:
        """Record a completed external tool call into the chain.

        ``allowed_receipt_id`` must reference a previously-minted
        ``Allowed`` proposal receipt whose ``action.kind`` begins with
        ``tool.``. Exactly one of ``output_hash`` / ``error`` must be
        set.

        Returns an :class:`AllowedDecision` — the
        ``$kernel/tool/executed`` receipt is always minted with
        ``decision: "allowed"``.
        """
        wire: dict[str, Any] = {"allowed_receipt_id": allowed_receipt_id}
        if output_hash is not None:
            wire["output_hash"] = output_hash
        if error is not None:
            wire["error"] = error
        if secrets_used is not None:
            secrets_list = list(secrets_used)
            if secrets_list:
                wire["secrets_used"] = secrets_list
        if redaction is not None:
            wire["redaction"] = {
                "redacted_output_hash": redaction.redacted_output_hash,
                "stack_hash": redaction.stack_hash,
                "matches": [
                    {"rule_id": m.rule_id, "count": m.count}
                    for m in redaction.matches
                ],
            }
        resp = self._post("/v1/tool-executions", wire)
        decision = self._build_decision(resp)
        if decision.kind != "allowed":
            raise RuntimeError(
                f"unexpected tool-execution response: kind={decision.kind} (server bug?)",
            )
        self._maybe_verify(decision, verify)
        assert isinstance(decision, AllowedDecision)
        return decision

    def get_receipt(self, content_id: str) -> dict[str, Any]:
        """GET ``/receipts/{content_id}`` and return parsed JSON.

        Does NOT verify — use :meth:`verify_receipt_url` when you
        want the signature checked.
        """
        url = f"{self._base_url}/receipts/{content_id}"
        text = self._get(url)
        result: Any = json.loads(text)
        if not isinstance(result, dict):
            raise UniclawError(200, "malformed_response", "receipt JSON was not an object")
        return result

    def verify_receipt_url(self, url: str) -> VerifyResult:
        """Fetch a receipt URL and verify it cold. Returns a
        :class:`VerifyResult`."""
        text = self._get(url)
        return verify_receipt_json(text)

    # ------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            method="POST",
            data=data,
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                raw = resp.read().decode("utf-8")
                parsed: Any = json.loads(raw)
                if not isinstance(parsed, dict):
                    raise UniclawError(
                        resp.status, "malformed_response", "response was not a JSON object",
                    )
                return parsed
        except urllib.error.HTTPError as e:
            raise self._parse_http_error(e) from e
        except urllib.error.URLError as e:
            raise UniclawError(0, "fetch_failed", f"POST {url}: {e.reason}") from e

    def _get(self, url: str) -> str:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                if resp.status < 200 or resp.status >= 300:
                    raise UniclawError(
                        resp.status, "fetch_failed", f"GET {url} → HTTP {resp.status}",
                    )
                payload: bytes = resp.read()
                return payload.decode("utf-8")
        except urllib.error.HTTPError as e:
            raise self._parse_http_error(e) from e
        except urllib.error.URLError as e:
            raise UniclawError(0, "fetch_failed", f"GET {url}: {e.reason}") from e

    def _parse_http_error(self, e: urllib.error.HTTPError) -> UniclawError:
        """Map a urllib HTTPError to a typed UniclawError, parsing the
        server's ``{error, detail}`` body when possible."""
        status = e.code
        try:
            body = e.read().decode("utf-8")
        except Exception:  # pragma: no cover — best effort
            return UniclawError(status, "non_text_response", "<unreadable response body>")
        try:
            parsed: Any = json.loads(body)
        except json.JSONDecodeError:
            return UniclawError(status, "non_json_response", body[:200])
        if isinstance(parsed, dict) and isinstance(parsed.get("error"), str) and isinstance(parsed.get("detail"), str):
            return UniclawError(status, parsed["error"], parsed["detail"])
        return UniclawError(status, "unknown", str(parsed)[:200])

    def _build_decision(self, resp: dict[str, Any]) -> Decision:
        # Validate the wire-shape minimum. Defensive: production
        # servers should always return all fields, but a partial
        # response or a misconfigured proxy could mangle things.
        for key in ("decision", "content_id", "receipt_url", "issuer", "sequence", "schema_version"):
            if key not in resp:
                raise UniclawError(
                    200, "malformed_response", f"server response missing field {key!r}",
                )
        decision_str = resp["decision"]
        if not isinstance(decision_str, str):
            raise UniclawError(200, "malformed_response", "decision must be a string")
        receipt_url = resp["receipt_url"]
        if not isinstance(receipt_url, str):
            raise UniclawError(200, "malformed_response", "receipt_url must be a string")

        content_id = str(resp["content_id"])
        absolute_url = self._join_url(self._base_url, receipt_url)
        issuer = str(resp["issuer"])
        sequence = int(resp["sequence"])
        schema_version = int(resp["schema_version"])

        if decision_str == "allowed":
            return AllowedDecision(
                content_id=content_id,
                receipt_url=absolute_url,
                issuer=issuer,
                sequence=sequence,
                schema_version=schema_version,
            )
        if decision_str == "denied":
            return DeniedDecision(
                content_id=content_id,
                receipt_url=absolute_url,
                issuer=issuer,
                sequence=sequence,
                schema_version=schema_version,
            )
        if decision_str == "approved":
            return ApprovedDecision(
                content_id=content_id,
                receipt_url=absolute_url,
                issuer=issuer,
                sequence=sequence,
                schema_version=schema_version,
            )
        if decision_str == "pending":
            return PendingDecision(
                content_id=content_id,
                receipt_url=absolute_url,
                issuer=issuer,
                sequence=sequence,
                schema_version=schema_version,
            )
        raise UniclawError(
            200, "malformed_response", f"unknown decision in response: {decision_str!r}",
        )

    def _maybe_verify(self, decision: Decision, verify: bool | None) -> None:
        do_verify = self._verify_by_default if verify is None else verify
        if not do_verify:
            return
        result = self.verify_receipt_url(decision.receipt_url)
        if not result.ok:
            raise UniclawVerifyError(
                decision.content_id,
                result.error or "signature did not verify under the embedded issuer key",
            )
        # Defense in depth: server's claimed content_id must match
        # the bytes we just hashed locally.
        if result.content_id_hex != decision.content_id:
            raise UniclawVerifyError(
                decision.content_id,
                f"server claimed content_id {decision.content_id} but the recomputed hash is {result.content_id_hex}",
            )

    @staticmethod
    def _join_url(base: str, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if path.startswith("/"):
            return f"{base}{path}"
        return f"{base}/{path}"
