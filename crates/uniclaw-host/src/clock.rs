//! Wall-clock helpers for the kernel.
//!
//! The kernel takes a `Clock` that returns an ISO-8601 timestamp
//! string for each receipt's `issued_at` field. This module supplies:
//!
//! - [`SystemClock`]: the simplest production clock — `SystemTime::now`
//!   formatted as RFC 3339 / ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ` in UTC).
//! - [`StubClock`]: a deterministic clock for tests, returning a fixed
//!   monotonically-incrementing timestamp.
//!
//! Production should use `SystemClock`. Tests prefer `StubClock` for
//! reproducible receipt bytes.

use core::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use uniclaw_kernel::Clock;

/// Real wall-clock backed by `std::time::SystemTime`.
///
/// Emits RFC 3339 UTC timestamps with second precision:
/// `"2026-05-11T14:23:09Z"`. Falls back to the Unix epoch
/// (`"1970-01-01T00:00:00Z"`) if the system clock is before the
/// Unix epoch — receipts still verify; they just record a
/// pre-epoch timestamp.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_iso8601(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        format_iso8601_seconds(secs)
    }
}

/// Deterministic clock for tests. Each call returns a timestamp
/// `1 second` later than the previous one.
///
/// Construct with [`StubClock::starting_at`] for a specific epoch
/// second; default is `0` (Unix epoch).
#[derive(Debug, Default)]
pub struct StubClock {
    next_secs: Cell<i64>,
}

impl StubClock {
    /// Construct a stub clock whose first call returns the given
    /// number of seconds past the Unix epoch.
    #[must_use]
    pub fn starting_at(secs: i64) -> Self {
        Self {
            next_secs: Cell::new(secs),
        }
    }
}

impl Clock for StubClock {
    fn now_iso8601(&self) -> String {
        let s = self.next_secs.get();
        self.next_secs.set(s.saturating_add(1));
        format_iso8601_seconds(s)
    }
}

/// Format a Unix epoch second-count as RFC 3339 / ISO 8601 UTC.
///
/// Pulled out so both clocks share the same byte-stable formatter,
/// and so the tests below pin the exact output for known instants.
//
// Time-of-day arithmetic is bounded by `rem_euclid(86_400)`, so the
// cast to u32 is always lossless.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn format_iso8601_seconds(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let hour = (tod / 3600) as u32;
    let minute = ((tod / 60) % 60) as u32;
    let second = (tod % 60) as u32;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a count of days since 1970-01-01 into a Gregorian
/// `(year, month, day)` tuple.
///
/// Howard Hinnant's `civil_from_days` algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>), in the
/// public domain. Correct for any 64-bit day count.
//
// All `as u32` casts here are mathematically bounded:
//   - `doe < 146_097`, so it fits.
//   - `d` is in `1..=31` by construction.
//   - `m` is in `1..=12` by construction (`mp` is in `0..=11`).
// Clippy flags them anyway; allow inline since the algorithm is
// well-known and bounded.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year_400 = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = if month <= 2 { year_400 + 1 } else { year_400 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_renders_correctly() {
        assert_eq!(format_iso8601_seconds(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_dates_render_correctly() {
        // 2026-05-09T12:00:00Z
        assert_eq!(
            format_iso8601_seconds(1_778_328_000),
            "2026-05-09T12:00:00Z"
        );
        // 2000-01-01T00:00:00Z
        assert_eq!(format_iso8601_seconds(946_684_800), "2000-01-01T00:00:00Z");
        // 2099-12-31T23:59:59Z
        assert_eq!(
            format_iso8601_seconds(4_102_444_799),
            "2099-12-31T23:59:59Z",
        );
    }

    #[test]
    fn negative_seconds_pre_epoch() {
        // 1969-12-31T23:59:59Z
        assert_eq!(format_iso8601_seconds(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn stub_clock_advances_one_second_per_call() {
        let c = StubClock::starting_at(1_778_328_000);
        assert_eq!(c.now_iso8601(), "2026-05-09T12:00:00Z");
        assert_eq!(c.now_iso8601(), "2026-05-09T12:00:01Z");
        assert_eq!(c.now_iso8601(), "2026-05-09T12:00:02Z");
    }

    #[test]
    fn system_clock_emits_well_formed_rfc3339() {
        let s = SystemClock.now_iso8601();
        // Should be exactly 20 chars: "YYYY-MM-DDTHH:MM:SSZ".
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
    }
}
