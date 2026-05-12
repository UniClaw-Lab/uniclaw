"""Exception types raised by ``uniclaw_client``."""

from __future__ import annotations


class UniclawError(Exception):
    """Raised when the Uniclaw HTTP API returns a 4xx/5xx response.

    The server's wire-format error body (``{error, detail}``) is
    parsed and surfaced in ``code`` + ``detail``; ``status`` is the
    HTTP status code. Callers can branch on ``status`` (e.g. 404 =
    unknown receipt, 409 = state conflict) or on ``code`` (e.g.
    ``"not_found"``, ``"conflict"``, ``"bad_request"``).
    """

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(f"UniclawError [{status} {code}]: {detail}")
        self.status = status
        self.code = code
        self.detail = detail


class UniclawVerifyError(Exception):
    """Raised when verify-by-default catches a receipt whose signature
    does not validate (or whose recomputed content_id differs from the
    server's claim).

    Carries the receipt's content_id so callers can correlate with
    logs.
    """

    def __init__(self, content_id: str, detail: str) -> None:
        super().__init__(f"UniclawVerifyError [{content_id}]: {detail}")
        self.content_id = content_id
        self.detail = detail
