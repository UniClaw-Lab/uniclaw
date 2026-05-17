/// Error thrown by `BoardProofClient` when the HTTP API returns a
/// 4xx/5xx response. The server's wire-format error body
/// (`{error, detail}`) is parsed and surfaced in `code` + `detail`;
/// `status` is the HTTP status code.
///
/// Callers can branch on `status` (e.g. `404` = unknown receipt,
/// `409` = state conflict) or on `code` (e.g. `"not_found"`,
/// `"conflict"`, `"bad_request"`).
export class BoardProofError extends Error {
  override readonly name = "BoardProofError";
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly detail: string,
  ) {
    super(`BoardProofError [${status} ${code}]: ${detail}`);
  }
}

/// Thrown by `BoardProofClient` when verify-by-default catches a
/// receipt whose signature does not validate. Carries the
/// receipt's recomputed content_id so callers can correlate with
/// logs.
export class BoardProofVerifyError extends Error {
  override readonly name = "BoardProofVerifyError";
  constructor(
    public readonly contentId: string,
    public readonly detail: string,
  ) {
    super(`BoardProofVerifyError [${contentId}]: ${detail}`);
  }
}
