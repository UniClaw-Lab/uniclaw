// Public types for `@uniclaw/client`. Shapes are camelCased for
// idiomatic TypeScript; the client transparently converts to/from
// the snake_cased wire format defined in
// `crates/uniclaw-host/src/api.rs`.

/// User-facing action shape. `inputHash` is a 64-char hex string
/// committing to whatever bytes the agent intends to act on (e.g.
/// the raw input payload of an HTTP request).
export interface Action {
  kind: string;
  target: string;
  inputHash: string;
}

/// Fields common to every minted decision. `receiptUrl` is an
/// absolute URL (the client joins the server's relative
/// `/receipts/<hash>` against the configured `baseUrl`).
export interface DecisionBase {
  contentId: string;
  receiptUrl: string;
  issuer: string;
  sequence: number;
  schemaVersion: number;
}

export interface AllowedDecision extends DecisionBase {
  kind: "allowed";
}

export interface DeniedDecision extends DecisionBase {
  kind: "denied";
}

export interface ApprovedDecision extends DecisionBase {
  kind: "approved";
}

/// Pending receipts carry callbacks an operator UI can invoke
/// directly:
///
/// ```ts
/// if (decision.kind === "pending") {
///   const final = await decision.approve("operator@example.com");
/// }
/// ```
///
/// The callbacks delegate to `client.resolveApproval(...)` and
/// inherit its verify-by-default behavior. Both return a fully-
/// resolved decision (`ApprovedDecision | DeniedDecision`) — the
/// kernel may downgrade an approve to a denial at resolve time
/// (e.g. budget exhausted), and the type system surfaces that.
export interface PendingDecision extends DecisionBase {
  kind: "pending";
  approve(principal: string): Promise<ApprovedDecision | DeniedDecision>;
  deny(principal: string): Promise<DeniedDecision>;
}

export type Decision =
  | AllowedDecision
  | DeniedDecision
  | ApprovedDecision
  | PendingDecision;

/// Wire-format response from `POST /v1/proposals` and
/// `POST /v1/approvals/{id}/resolve`. Internal — exported for
/// tests only.
export interface WireReceiptResponse {
  decision: string;
  content_id: string;
  receipt_url: string;
  issuer: string;
  sequence: number;
  schema_version: number;
}

/// Wire-format error body. The server emits this on every 4xx/5xx
/// response.
export interface WireErrorBody {
  error: string;
  detail: string;
}
