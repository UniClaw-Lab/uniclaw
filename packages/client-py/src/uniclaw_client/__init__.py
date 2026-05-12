"""``uniclaw-client`` — Python adapter for Uniclaw receipts.

The package surface is intentionally narrow: one client class, two
exception types, the discriminated decision union, and standalone
verifier helpers for callers that want to verify without minting.

See the README and `docs/steps/24-python-client.md` in the parent
repo for how this fits the wedge.
"""

from __future__ import annotations

from .client import UniclawClient
from .errors import UniclawError, UniclawVerifyError
from .types import (
    Action,
    AllowedDecision,
    ApprovedDecision,
    Decision,
    DeniedDecision,
    PendingDecision,
    Redaction,
    RuleMatch,
    VerifyResult,
)
from .verify import (
    canonicalize,
    compute_content_id_bytes,
    compute_content_id_hex,
    verify_receipt,
    verify_receipt_json,
    verify_receipt_url,
)

__version__ = "0.1.0"

__all__ = [
    "Action",
    "AllowedDecision",
    "ApprovedDecision",
    "Decision",
    "DeniedDecision",
    "PendingDecision",
    "Redaction",
    "RuleMatch",
    "UniclawClient",
    "UniclawError",
    "UniclawVerifyError",
    "VerifyResult",
    "canonicalize",
    "compute_content_id_bytes",
    "compute_content_id_hex",
    "verify_receipt",
    "verify_receipt_json",
    "verify_receipt_url",
    "__version__",
]
