/// Error thrown by `UniclawClient` when the HTTP API returns a
/// 4xx/5xx response. The server's wire-format error body
/// (`{error, detail}`) is parsed and surfaced in `code` + `detail`;
/// `status` is the HTTP status code.
///
/// Callers can branch on `status` (e.g. `404` = unknown receipt,
/// `409` = state conflict) or on `code` (e.g. `"not_found"`,
/// `"conflict"`, `"bad_request"`).
export class UniclawError extends Error {
  override readonly name = "UniclawError";
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly detail: string,
  ) {
    super(`UniclawError [${status} ${code}]: ${detail}`);
  }
}

/// Thrown by `UniclawClient` when verify-by-default catches a
/// receipt whose signature does not validate. Carries the
/// receipt's recomputed content_id so callers can correlate with
/// logs.
export class UniclawVerifyError extends Error {
  override readonly name = "UniclawVerifyError";
  constructor(
    public readonly contentId: string,
    public readonly detail: string,
  ) {
    super(`UniclawVerifyError [${contentId}]: ${detail}`);
  }
}
