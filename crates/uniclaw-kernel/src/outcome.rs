//! Kernel outcome — what flows out of `Kernel::handle()`.

use uniclaw_receipt::Receipt;

/// Result of a kernel event.
///
/// In the current sketch every event produces a receipt. Variants without
/// receipts (e.g. ingress staging, sleep-tick no-ops) will arrive when their
/// events do, each carrying an explicit `#[no_receipt]` justification per
/// master plan §24.2.
#[derive(Debug, Clone)]
pub struct KernelOutcome {
    /// Signed receipt the event produced.
    pub receipt: Receipt,
}
