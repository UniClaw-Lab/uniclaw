//! [`BuildError`] — failures at module construction time.
//!
//! Distinct from runtime [`boardproof_tools::ToolError`] (raised from
//! [`Tool::call`](boardproof_tools::Tool::call)) so callers can tell
//! "this module never loaded" from "this call failed."

use std::fmt;

/// Why constructing a [`crate::WasmTool`] failed.
///
/// Construction can fail because:
/// - The wasm bytes are malformed or use unsupported features.
/// - The module's exports don't match the v0 ABI (missing `memory`,
///   `alloc`, or `call`; wrong signature).
/// - wasmtime's engine setup itself errored.
#[derive(Debug)]
pub enum BuildError {
    /// `wat::parse_str` rejected the input. The string is the
    /// underlying parser's message.
    InvalidWat(String),
    /// `wasmtime::Module::from_binary` rejected the input — the
    /// bytes parsed but failed validation, or use unsupported
    /// features.
    InvalidWasm(String),
    /// wasmtime engine creation failed (typically a feature combo
    /// the platform doesn't support).
    EngineSetup(String),
    /// The module compiled but is missing a required export, or
    /// the export's signature doesn't match the v0 ABI.
    ///
    /// `name` is the missing or mismatched export; `detail` adds
    /// context like the expected vs actual signature.
    MissingExport { name: String, detail: String },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWat(msg) => write!(f, "invalid WAT: {msg}"),
            Self::InvalidWasm(msg) => write!(f, "invalid wasm module: {msg}"),
            Self::EngineSetup(msg) => write!(f, "wasmtime engine setup failed: {msg}"),
            Self::MissingExport { name, detail } => {
                write!(f, "module missing required export '{name}': {detail}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_the_useful_bits() {
        let s = BuildError::InvalidWat("expected '('".into()).to_string();
        assert!(s.contains("WAT"));
        assert!(s.contains("expected"));

        let s = BuildError::MissingExport {
            name: "call".into(),
            detail: "expected (i32, i32) -> i64".into(),
        }
        .to_string();
        assert!(s.contains("call"));
        assert!(s.contains("(i32, i32) -> i64"));
    }
}
