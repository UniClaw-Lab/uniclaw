//! Uniclaw Constitution engine.
//!
//! A *constitution* is a deterministic rules engine, **separate from the
//! model**, that judges proposed actions before the policy gate (master plan
//! §11.3). The kernel consults a constitution on every action; matched rules
//! are recorded in the receipt so an auditor can replay the decision tree.
//!
//! ## v0 semantics
//!
//! - Rules are loaded from TOML.
//! - A rule's `match` clause currently supports `kind` (exact match) and
//!   `target_contains` (substring). More expressive matchers (regex, glob,
//!   header inspection) arrive when concrete need surfaces.
//! - A rule's `verdict` is **`deny`** today. `allow` (whitelist) and
//!   `require_approval` arrive with the approval engine.
//! - The constitution can *force* a `Decision::Denied` but never grant
//!   `Decision::Allowed`. **Safe by default**: rules block, they don't
//!   unblock.
//! - All matched rules — regardless of verdict — appear in
//!   `Receipt.body.constitution_rules`.
//!
//! ## Discipline
//!
//! - Adopted-not-copied: rule semantics inspired by `NemoClaw`'s policy
//!   presets pattern but reimplemented in Rust idioms. No source copied.
//! - Every state-affecting decision routes through `Constitution::evaluate`
//!   so the audit trail captures it.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod evaluator;
mod parse;
mod rule;
mod verdict;

pub use evaluator::{EmptyConstitution, InMemoryConstitution};
pub use parse::{ParseError, parse_toml};
pub use rule::{ConstitutionDoc, MatchClause, Rule, RuleVerdict};
pub use verdict::{Constitution, ConstitutionVerdict};
