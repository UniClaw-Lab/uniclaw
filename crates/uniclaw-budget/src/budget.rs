//! Numeric resource caps and charges.

use serde::{Deserialize, Serialize};

/// The numeric ceilings a `CapabilityLease` enforces.
///
/// All fields are absolute upper bounds — `net_bytes: 5_242_880` means
/// "5 MiB total, summed across all charges". Zero on a field means that
/// resource is denied entirely.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum total network bytes (request + response combined).
    pub net_bytes: u64,
    /// Maximum file-write operations.
    pub file_writes: u32,
    /// Maximum LLM tokens (input + output combined).
    pub llm_tokens: u32,
    /// Maximum wall-clock milliseconds.
    pub wall_ms: u64,
    /// Maximum distinct uses of the lease.
    pub max_uses: u32,
}

impl Budget {
    /// All-zero budget — useful as a starting point or as a "deny everything"
    /// sentinel.
    pub const ZERO: Self = Self {
        net_bytes: 0,
        file_writes: 0,
        llm_tokens: 0,
        wall_ms: 0,
        max_uses: 0,
    };

    /// Reinterpret a budget as a `ResourceUse`. Same fields, used when
    /// asking "is this whole budget reservable from another budget?".
    #[must_use]
    pub const fn as_use(&self) -> ResourceUse {
        ResourceUse {
            net_bytes: self.net_bytes,
            file_writes: self.file_writes,
            llm_tokens: self.llm_tokens,
            wall_ms: self.wall_ms,
            uses: self.max_uses,
        }
    }
}

/// Resources consumed in one charge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUse {
    /// Network bytes (request + response).
    pub net_bytes: u64,
    /// File writes.
    pub file_writes: u32,
    /// LLM tokens.
    pub llm_tokens: u32,
    /// Wall-clock milliseconds.
    pub wall_ms: u64,
    /// Distinct uses (typically 1 per `try_charge`).
    pub uses: u32,
}

impl ResourceUse {
    /// All-zero charge.
    pub const ZERO: Self = Self {
        net_bytes: 0,
        file_writes: 0,
        llm_tokens: 0,
        wall_ms: 0,
        uses: 0,
    };

    /// Sum two charges, saturating on overflow.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            net_bytes: self.net_bytes.saturating_add(other.net_bytes),
            file_writes: self.file_writes.saturating_add(other.file_writes),
            llm_tokens: self.llm_tokens.saturating_add(other.llm_tokens),
            wall_ms: self.wall_ms.saturating_add(other.wall_ms),
            uses: self.uses.saturating_add(other.uses),
        }
    }

    /// True if every field is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.net_bytes == 0
            && self.file_writes == 0
            && self.llm_tokens == 0
            && self.wall_ms == 0
            && self.uses == 0
    }
}
