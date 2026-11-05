// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines redacted History cursors ordered by decimal magnitude without arithmetic.
//!
//! Cursors retain their validated bytes. Canonical decimal accepts `0`, but
//! rejects leading zeroes on multi-digit input instead of rewriting identity.
//! No increment, subtraction or assumption of contiguous History IDs is exposed.

use std::{cmp::Ordering, fmt};

/// Reports an invalid History cursor without retaining its input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidHistoryCursor;

impl fmt::Display for InvalidHistoryCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid canonical History cursor")
    }
}
impl std::error::Error for InvalidHistoryCursor {}

/// Holds a canonical nonnegative decimal History identifier, never a message ID.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HistoryCursor(String);

impl HistoryCursor {
    /// Maximum accepted decimal digits, a defensive product bound.
    pub const MAX_DIGITS: usize = 32;

    /// Validates a cursor without normalizing or interpreting it arithmetically.
    ///
    /// # Errors
    ///
    /// Rejects empty input, more than 32 bytes, non-ASCII digits, and multi-digit
    /// values beginning with zero. The single digit `0` is valid.
    pub fn new<T: Into<String>>(value: T) -> Result<Self, InvalidHistoryCursor> {
        let value = value.into();
        if value.is_empty()
            || value.len() > Self::MAX_DIGITS
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(InvalidHistoryCursor);
        }
        Ok(Self(value))
    }

    /// Returns the exact validated cursor bytes for trusted persistence or transport.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Ord for HistoryCursor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}
impl PartialOrd for HistoryCursor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Debug for HistoryCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoryCursor([REDACTED])")
    }
}
impl fmt::Display for HistoryCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Contract: canonical decimal identity and numeric ordering beyond machine integers.
    // Regression: lexical ordering, integer overflow or leading-zero normalization.
    #[test]
    fn canonical_identity_and_magnitude_boundaries() {
        for invalid in ["", "00", "01", "+1", "-1", " 1", "1\n", "١", "1.0"] {
            assert_eq!(HistoryCursor::new(invalid), Err(InvalidHistoryCursor));
        }
        assert!(HistoryCursor::new("1".repeat(33)).is_err());
        let ordered = [
            "0",
            "9",
            "10",
            "99",
            "100",
            "99999999999999999999999999999999",
        ];
        let cursors: Vec<_> = ordered
            .iter()
            .map(|s| HistoryCursor::new(*s).expect("valid synthetic value"))
            .collect();
        for (cursor, expected) in cursors.iter().zip(ordered) {
            assert_eq!(cursor.as_str(), expected);
        }
        for pair in cursors.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        let cursor = HistoryCursor::new("826391").expect("valid synthetic value");
        assert_eq!(format!("{cursor:?}"), "HistoryCursor([REDACTED])");
        assert_eq!(cursor.to_string(), "[REDACTED]");
        assert_eq!(
            InvalidHistoryCursor.to_string(),
            "invalid canonical History cursor"
        );
    }
}
