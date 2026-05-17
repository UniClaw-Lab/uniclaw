// Public API for `@boardproof/client`.
//
// The package wraps BoardProof's HTTP proposal API (step 21) and
// verifier (step 20a) into a single idiomatic TypeScript surface.
// One class, three operations, verify-by-default.

export { BoardProofClient } from "./client.js";
export type { BoardProofClientOptions, EvaluateOptions } from "./client.js";

export { BoardProofError, BoardProofVerifyError } from "./error.js";

export type {
  Action,
  AllowedDecision,
  ApprovedDecision,
  Decision,
  DecisionBase,
  DeniedDecision,
  PendingDecision,
  RedactionReportInput,
  RuleMatchInput,
  ToolExecutionInput,
} from "./types.js";

// Re-export the verifier's result type for callers that consume
// `verifyReceiptUrl()`.
export type { VerifyResult } from "@boardproof/verifier";
