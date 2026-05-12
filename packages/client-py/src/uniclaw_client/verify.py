"""Receipt verification.

Recomputes the canonical body bytes (RFC 8785 JCS), the BLAKE3
``content_id``, and the Ed25519 signature against the receipt's
embedded issuer key. Everything runs in-process; the server is
never asked whether a receipt is valid.

Python port of ``packages/verifier-ts/src/verify.ts``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from blake3 import blake3
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ._canonical import canonicalize_body
from ._hex import bytes_to_hex, hex_to_bytes
from .errors import UniclawError
from .types import VerifyResult


def canonicalize(body: dict[str, Any]) -> bytes:
    """Encode ``body`` to its canonical byte form. Dispatches on
    ``body.schema_version``: v1 uses legacy JSON; v2+ uses JCS."""
    return canonicalize_body(body)


def compute_content_id_bytes(body: dict[str, Any]) -> bytes:
    """BLAKE3 over the canonical body bytes. Returns 32 raw bytes."""
    return blake3(canonicalize(body)).digest()


def compute_content_id_hex(body: dict[str, Any]) -> str:
    """Hex form of :func:`compute_content_id_bytes` (64 chars)."""
    return bytes_to_hex(compute_content_id_bytes(body))


def verify_receipt(receipt: dict[str, Any]) -> VerifyResult:
    """Verify a parsed receipt dict.

    Returns a :class:`VerifyResult` regardless of success/failure.
    Only catastrophically malformed input raises (TypeError /
    ValueError); structurally-valid-but-invalid receipts return
    ``ok=False`` with ``error`` populated.
    """
    if not isinstance(receipt, dict):
        return _err("input is not a JSON object")
    body = receipt.get("body")
    if not isinstance(body, dict):
        return _err("receipt is missing a body")
    issuer_hex = receipt.get("issuer")
    signature_hex = receipt.get("signature")
    if not isinstance(issuer_hex, str):
        return _err("issuer must be a hex string")
    if not isinstance(signature_hex, str):
        return _err("signature must be a hex string")

    schema_version = body.get("schema_version", 0)
    decision = body.get("decision", "")
    schema_version_i = schema_version if isinstance(schema_version, int) else 0
    decision_s = decision if isinstance(decision, str) else ""
    # Step 19a: surface body.key_id when present.
    key_id_raw = body.get("key_id")
    key_id_s = key_id_raw if isinstance(key_id_raw, str) else None

    try:
        issuer_bytes = hex_to_bytes(issuer_hex)
    except (ValueError, TypeError) as e:
        return _err(str(e), issuer_hex=issuer_hex, schema_version=schema_version_i, decision=decision_s)
    if len(issuer_bytes) != 32:
        return _err(
            f"issuer must be 32 bytes, got {len(issuer_bytes)}",
            issuer_hex=issuer_hex,
            schema_version=schema_version_i,
            decision=decision_s,
        )
    try:
        signature_bytes = hex_to_bytes(signature_hex)
    except (ValueError, TypeError) as e:
        return _err(str(e), issuer_hex=issuer_hex, schema_version=schema_version_i, decision=decision_s)
    if len(signature_bytes) != 64:
        return _err(
            f"signature must be 64 bytes, got {len(signature_bytes)}",
            issuer_hex=issuer_hex,
            schema_version=schema_version_i,
            decision=decision_s,
        )

    try:
        canonical_bytes = canonicalize(body)
    except (TypeError, ValueError) as e:
        return _err(f"canonicalize: {e}", issuer_hex=issuer_hex, schema_version=schema_version_i, decision=decision_s)

    content_id_hex = bytes_to_hex(blake3(canonical_bytes).digest())

    try:
        VerifyKey(issuer_bytes).verify(canonical_bytes, signature_bytes)
    except BadSignatureError:
        return VerifyResult(
            ok=False,
            content_id_hex=content_id_hex,
            issuer_hex=issuer_hex,
            schema_version=schema_version_i,
            decision=decision_s,
            key_id=key_id_s,
            error="signature did not verify under the embedded issuer key",
        )

    return VerifyResult(
        ok=True,
        content_id_hex=content_id_hex,
        issuer_hex=issuer_hex,
        schema_version=schema_version_i,
        decision=decision_s,
        key_id=key_id_s,
    )


def verify_receipt_json(json_text: str) -> VerifyResult:
    """Parse + verify a raw receipt JSON string."""
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as e:
        return _err(f"invalid JSON: {e}")
    return verify_receipt(parsed)


def verify_receipt_url(url: str, *, timeout: float = 10.0) -> VerifyResult:
    """Fetch a receipt URL and verify it cold.

    Uses stdlib ``urllib.request`` (no extra HTTP dependency). Raises
    :class:`UniclawError` if the GET itself fails (network error /
    non-2xx); the returned :class:`VerifyResult` reports verification
    failure.
    """
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted URL by design)
            if resp.status < 200 or resp.status >= 300:
                raise UniclawError(resp.status, "fetch_failed", f"GET {url} → HTTP {resp.status}")
            text = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise UniclawError(e.code, "fetch_failed", f"GET {url} → HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise UniclawError(0, "fetch_failed", f"GET {url}: {e.reason}") from e
    return verify_receipt_json(text)


def _err(
    error: str,
    *,
    content_id_hex: str = "",
    issuer_hex: str = "",
    schema_version: int = 0,
    decision: str = "",
) -> VerifyResult:
    return VerifyResult(
        ok=False,
        content_id_hex=content_id_hex,
        issuer_hex=issuer_hex,
        schema_version=schema_version,
        decision=decision,
        error=error,
    )
