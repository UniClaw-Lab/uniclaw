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

/// Payload for `client.recordToolExecution(...)`. Exactly one of
/// `outputHash` / `error` must be set:
///
/// - `outputHash` (success): 64 hex chars (BLAKE3 of the tool's
///   raw output bytes). The actual bytes never enter the kernel
///   or the receipt — only the hash + audit metadata.
/// - `error` (failure): free-form human-readable message.
///
/// `secretsUsed` lists the REFERENCE NAMES of secrets consumed
/// during the call. Values never cross any wire — neither to the
/// kernel nor to the receipt. Defaults to empty.
///
/// `redaction`, when set, commits the receipt to a post-redaction
/// `outputHash` and populates `body.redactor_stack_hash`. The
/// kernel mints one `redaction_applied` provenance edge per rule
/// with `count > 0`.
export interface ToolExecutionInput {
  allowedReceiptId: string;
  outputHash?: string;
  error?: string;
  secretsUsed?: string[];
  redaction?: RedactionReportInput;
}

/// Wire-equivalent of the kernel's `RedactionReport` (step 18).
/// Caller produces this from whatever redactor it ran over the
/// tool's output bytes before submitting the execution event.
export interface RedactionReportInput {
  redactedOutputHash: string;
  matches: RuleMatchInput[];
  stackHash: string;
}

export interface RuleMatchInput {
  ruleId: string;
  count: number;
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
  /// Step 19a: operator-chosen identifier for the signing key
  /// when the server's signer was configured with one (`--key-id`
  /// on `uniclaw-host`). Absent when the signer has no `key_id`.
  /// Use it to correlate with an external key directory entry
  /// (rotation, revocation, expiry).
  keyId?: string;
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
  /// Step 19a — omitted on the wire when the server's signer
  /// didn't set a key_id (skip_serializing_if = "Option::is_none").
  key_id?: string;
}

/// Wire-format error body. The server emits this on every 4xx/5xx
/// response.
export interface WireErrorBody {
  error: string;
  detail: string;
}
