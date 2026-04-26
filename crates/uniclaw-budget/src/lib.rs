//! Capability budget algebra for Uniclaw.
//!
//! A `CapabilityLease` is a numeric grant of resources (network bytes, file
//! writes, LLM tokens, wall-clock time, distinct uses). Every consequential
//! agent action **charges** a lease before executing. Two key properties:
//!
//! - **Composes on delegation.** `parent.delegate(child_budget)` reserves a
//!   chunk of the parent's remaining capacity and hands it to a child lease.
//!   A child can never exceed the parent's remaining budget at delegation
//!   time, and the parent is debited upfront — so a child can never escalate
//!   by burning the parent's pool.
//! - **Shrinks with use.** Every `try_charge` deducts from the lease's
//!   remaining capacity. Exhausted leases reject further charges, and the
//!   kernel converts a rejection into a signed `Decision::Denied` receipt.
//!
//! Master plan §11 / §21 #2.
//!
//! # Discipline
//!
//! - Adopt-don't-copy: numeric-bounds capability semantics inspired by
//!   `OpenFang`'s `Capability` enum (`LlmMaxTokens`, `FileRead`, etc.) but
//!   reimplemented from scratch.

#![cfg_attr(not(test), no_std)]

mod budget;
mod error;
mod lease;

pub use budget::{Budget, ResourceUse};
pub use error::BudgetError;
pub use lease::{CapabilityLease, LeaseId};
