//! Uniclaw kernel — the trusted runtime core.
//!
//! The kernel is the **Spine** layer of the Brain/Spine/Hands/Skin/Sense
//! architecture (`UNICLAW_PLAN.md` §9). It coordinates ingress, model
//! proposals, the Constitution check, the policy gate, capability budgets,
//! the approval engine, tool execution, redaction, and the Merkle audit
//! chain — turning all of these into signed, content-addressed receipts.
//!
//! ## Current shape
//!
//! This crate currently ships a **minimal sketch**:
//!
//! 1. Receive a `Proposal` containing a pre-decided action + decision.
//! 2. Compute the Merkle leaf hash.
//! 3. Build a `ReceiptBody` and sign it via the injected `Signer`.
//! 4. Advance kernel state (`sequence` + `prev_hash`).
//!
//! Future steps add Constitution evaluation (so the kernel decides instead
//! of just recording), the policy gate, capability budget algebra, the
//! approval engine, tool execution, sleep stages, and ingress staging.
//!
//! ## Discipline (master plan §24.2)
//!
//! - Every file in this crate stays ≤ 5 KLOC.
//! - Every state-mutating event emits a receipt or carries an explicit
//!   `#[no_receipt]` justification (none yet — the sketch always emits).
//! - No source code copied from any other claw runtime.
//! - One config format (TOML) — kernel takes no config in this sketch.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod event;
mod kernel;
mod leaf;
mod outcome;
mod state;
mod traits;

pub use event::{Approval, KernelEvent, Proposal};
pub use kernel::Kernel;
pub use leaf::compute_leaf_hash;
pub use outcome::{ApprovalRejection, KernelError, KernelOutcome, OutcomeKind};
pub use state::KernelState;
pub use traits::{Clock, Signer};
