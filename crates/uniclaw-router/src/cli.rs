//! Terminal `ApprovalRouter` — prompts a human operator on a TTY.
//!
//! Generic over input + output so tests can drive it with `Cursor<Vec<u8>>`
//! and so it can be wired into TUI frameworks later without rewriting the
//! prompting logic.

use std::io::{BufRead, Write};

use uniclaw_approval::ApprovalDecision;
use uniclaw_explain::{explain, render_text};
use uniclaw_kernel::Proposal;
use uniclaw_receipt::Receipt;

use crate::router::{ApprovalRouter, RouterError};

/// How many times the CLI router will re-prompt on unparseable input
/// before giving up with `RouterError::InvalidInput`.
const MAX_PROMPT_RETRIES: u8 = 3;

/// Interactive `ApprovalRouter` that prints the pending receipt and
/// reads `y`/`n` from a buffered reader.
///
/// In production, construct with `CliApprovalRouter::stdio()` for the
/// real terminal. In tests, construct with `CliApprovalRouter::new()`
/// and inject `Cursor<Vec<u8>>` for both halves.
pub struct CliApprovalRouter<R: BufRead, W: Write> {
    input: R,
    output: W,
}

impl<R: BufRead, W: Write> core::fmt::Debug for CliApprovalRouter<R, W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliApprovalRouter").finish_non_exhaustive()
    }
}

impl<R: BufRead, W: Write> CliApprovalRouter<R, W> {
    /// Build a router that reads from `input` and writes prompts to `output`.
    pub const fn new(input: R, output: W) -> Self {
        Self { input, output }
    }

    /// Inspect the underlying writer (mostly useful in tests to read what
    /// was printed to the operator).
    pub const fn output(&self) -> &W {
        &self.output
    }
}

impl CliApprovalRouter<std::io::BufReader<std::io::Stdin>, std::io::Stdout> {
    /// Construct a router wired to the process's real stdin and stdout.
    #[must_use]
    pub fn stdio() -> Self {
        Self::new(std::io::BufReader::new(std::io::stdin()), std::io::stdout())
    }
}

impl<R: BufRead, W: Write> ApprovalRouter for CliApprovalRouter<R, W> {
    fn route(
        &mut self,
        pending: &Receipt,
        _original_proposal: &Proposal,
    ) -> Result<ApprovalDecision, RouterError> {
        let exp = explain(pending);
        let rendered = render_text(&exp);

        writeln!(self.output, "═══ Pending action requires your approval ═══")
            .map_err(|e| io_err(&e))?;
        self.output
            .write_all(rendered.as_bytes())
            .map_err(|e| io_err(&e))?;
        writeln!(self.output).map_err(|e| io_err(&e))?;

        for attempt in 0..MAX_PROMPT_RETRIES {
            write!(self.output, "Approve this action? (y/n) ").map_err(|e| io_err(&e))?;
            self.output.flush().map_err(|e| io_err(&e))?;

            let mut line = String::new();
            let n = self.input.read_line(&mut line).map_err(|e| io_err(&e))?;
            if n == 0 {
                // EOF before any input — treat as cancellation.
                return Err(RouterError::Cancelled);
            }
            if let Some(decision) = parse_response(&line) {
                let echo = match decision {
                    ApprovalDecision::Approved => "approved",
                    ApprovalDecision::Denied => "denied",
                };
                writeln!(self.output, "→ {echo}").map_err(|e| io_err(&e))?;
                return Ok(decision);
            }
            let remaining = MAX_PROMPT_RETRIES - 1 - attempt;
            if remaining == 0 {
                return Err(RouterError::InvalidInput(format!(
                    "could not parse {:?} as approve/deny",
                    line.trim_end(),
                )));
            }
            writeln!(
                self.output,
                "Please answer y/yes/n/no ({remaining} attempt(s) left).",
            )
            .map_err(|e| io_err(&e))?;
        }
        // Loop only exits via `return`. This is unreachable but keeps the
        // type-checker happy without `unreachable!()` in production code.
        Err(RouterError::InvalidInput("retry budget exhausted".into()))
    }
}

fn io_err(e: &std::io::Error) -> RouterError {
    RouterError::Io(e.to_string())
}

fn parse_response(line: &str) -> Option<ApprovalDecision> {
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(ApprovalDecision::Approved),
        "n" | "no" => Some(ApprovalDecision::Denied),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use uniclaw_kernel::Proposal;
    use uniclaw_receipt::{
        Action, Decision, Digest, MerkleLeaf, ProvenanceEdge, RECEIPT_FORMAT_VERSION, Receipt,
        ReceiptBody, RuleRef,
    };

    fn dummy_pending() -> Receipt {
        Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body: ReceiptBody {
                schema_version: RECEIPT_FORMAT_VERSION,
                issued_at: "2026-04-27T00:00:00Z".into(),
                action: Action {
                    kind: "shell.exec".into(),
                    target: "git push origin main".into(),
                    input_hash: Digest([0u8; 32]),
                },
                decision: Decision::Pending,
                constitution_rules: vec![RuleRef {
                    id: "solo-dev/git-push-needs-approval".into(),
                    matched: true,
                }],
                provenance: vec![ProvenanceEdge {
                    from: "user".into(),
                    to: "model".into(),
                    kind: "request".into(),
                }],
                redactor_stack_hash: None,
                merkle_leaf: MerkleLeaf {
                    sequence: 0,
                    leaf_hash: Digest([0xAB; 32]),
                    prev_hash: Digest([0u8; 32]),
                },
            },
            issuer: uniclaw_receipt::PublicKey([0xCC; 32]),
            signature: uniclaw_receipt::Signature([0xDD; 64]),
        }
    }

    fn dummy_proposal() -> Proposal {
        Proposal::unbounded(
            dummy_pending().body.action,
            Decision::Allowed,
            vec![],
            vec![],
        )
    }

    fn run(input: &str) -> (Result<ApprovalDecision, RouterError>, String) {
        let mut router = CliApprovalRouter::new(Cursor::new(input.as_bytes().to_vec()), Vec::new());
        let result = router.route(&dummy_pending(), &dummy_proposal());
        let stdout = String::from_utf8(router.output).unwrap();
        (result, stdout)
    }

    #[test]
    fn y_yields_approved_and_prints_pending_context() {
        let (res, stdout) = run("y\n");
        assert_eq!(res, Ok(ApprovalDecision::Approved));
        assert!(stdout.contains("Pending action requires your approval"));
        assert!(stdout.contains("git push origin main"));
        assert!(stdout.contains("Approve this action?"));
        assert!(stdout.contains("→ approved"));
    }

    #[test]
    fn yes_capital_yields_approved() {
        let (res, _stdout) = run("YES\n");
        assert_eq!(res, Ok(ApprovalDecision::Approved));
    }

    #[test]
    fn n_yields_denied() {
        let (res, stdout) = run("n\n");
        assert_eq!(res, Ok(ApprovalDecision::Denied));
        assert!(stdout.contains("→ denied"));
    }

    #[test]
    fn no_yields_denied() {
        let (res, _stdout) = run("no\n");
        assert_eq!(res, Ok(ApprovalDecision::Denied));
    }

    #[test]
    fn invalid_input_then_valid_eventually_succeeds() {
        let (res, stdout) = run("maybe\nya\nyes\n");
        assert_eq!(res, Ok(ApprovalDecision::Approved));
        // Re-prompt message must appear at least twice.
        let prompts = stdout.matches("Please answer y/yes/n/no").count();
        assert_eq!(
            prompts, 2,
            "expected two re-prompts before success; got: {stdout}"
        );
    }

    #[test]
    fn retry_budget_exhausted_yields_invalid_input() {
        let (res, _stdout) = run("a\nb\nc\n");
        assert!(matches!(res, Err(RouterError::InvalidInput(_))));
    }

    #[test]
    fn eof_yields_cancelled() {
        let (res, _stdout) = run("");
        assert_eq!(res, Err(RouterError::Cancelled));
    }
}
