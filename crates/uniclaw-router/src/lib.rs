//! Channel-aware approval routing for Uniclaw.
//!
//! When the kernel mints a `Decision::Pending` receipt, the **router**
//! delivers it to a human operator and turns their response back into a
//! `KernelEvent::ResolveApproval`. v0 ships one concrete implementation —
//! [`CliApprovalRouter`] for terminal use — and one orchestrator helper,
//! [`evaluate_with_routing`], that wires `Kernel`, `ApprovalRouter`, and
//! the `Pending → ResolveApproval` flow together.
//!
//! Master plan §21 #7. The trait surface is **synchronous** by design;
//! an async runtime crate will wrap this trait without changing it.
//!
//! # Adapter scarcity (master plan §24.5)
//!
//! Only **one** router ships in this crate today: the CLI. Slack, email,
//! webhook, mobile-notification, and other backends require ≥ 10
//! GitHub-thumbs of demand before development starts, so the router
//! catalogue stays curated rather than half-quality.
//!
//! # Adopt-don't-copy
//!
//! Pattern inspired by `IronClaw`'s exec-approval flow and `OpenClaw`'s
//! `deny`/`allowlist`/`ask` exec-policy modes. Reimplemented from spec in
//! Rust idioms — no source borrowed from either project.

mod cli;
mod orchestrate;
mod router;

pub use cli::CliApprovalRouter;
pub use orchestrate::{OrchestrationError, evaluate_with_routing};
pub use router::{ApprovalRouter, RouterError};
