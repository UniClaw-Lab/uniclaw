"""Public types for ``uniclaw_client``.

Python port of ``packages/client-ts/src/types.ts``. The discriminated
union uses a string ``kind`` field so callers can ``match`` on it
(Python 3.10+ structural pattern matching).

Pending decisions do NOT carry inline ``.approve()`` / ``.deny()``
callbacks (that was idiomatic in TS but awkward in Python's frozen
dataclasses). Resolve a pending receipt explicitly:

    pending = client.evaluate(action)
    if pending.kind == "pending":
        final = client.resolve_approval(
            pending.content_id,
            principal="operator@example.com",
            outcome="approved",
        )
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union


@dataclass(frozen=True)
class Action:
    """User-facing action shape. ``input_hash`` is a 64-char hex
    string committing to whatever bytes the agent intends to act on
    (e.g. the raw input payload of an HTTP request)."""

    kind: str
    target: str
    input_hash: str


@dataclass(frozen=True)
class RuleMatch:
    """One redactor rule's match count."""

    rule_id: str
    count: int


@dataclass(frozen=True)
class Redaction:
    """Wire-equivalent of the kernel's ``RedactionReport`` (step 18).

    Submitted alongside a tool execution to commit the receipt to a
    post-redaction ``output_hash`` and populate
    ``body.redactor_stack_hash``.
    """

    redacted_output_hash: str
    stack_hash: str
    matches: tuple[RuleMatch, ...] = ()


@dataclass(frozen=True)
class _DecisionBase:
    """Fields common to every minted decision.

    ``receipt_url`` is absolute (the client joins the server's
    relative ``/receipts/<hash>`` with the configured ``base_url``).
    """

    content_id: str
    receipt_url: str
    issuer: str
    sequence: int
    schema_version: int


@dataclass(frozen=True)
class AllowedDecision(_DecisionBase):
    kind: Literal["allowed"] = "allowed"


@dataclass(frozen=True)
class DeniedDecision(_DecisionBase):
    kind: Literal["denied"] = "denied"


@dataclass(frozen=True)
class ApprovedDecision(_DecisionBase):
    kind: Literal["approved"] = "approved"


@dataclass(frozen=True)
class PendingDecision(_DecisionBase):
    kind: Literal["pending"] = "pending"


Decision = Union[AllowedDecision, DeniedDecision, ApprovedDecision, PendingDecision]


@dataclass(frozen=True)
class VerifyResult:
    """Result of verifying a receipt locally."""

    ok: bool
    content_id_hex: str
    issuer_hex: str
    schema_version: int
    decision: str
    error: str | None = None
