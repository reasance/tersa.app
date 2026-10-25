// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Date formatting in the system time zone.

use std::sync::OnceLock;

use jiff::Timestamp;
use jiff::tz::TimeZone;

fn system() -> &'static TimeZone {
    static ZONE: OnceLock<TimeZone> = OnceLock::new();
    ZONE.get_or_init(TimeZone::system)
}

/// `YYYY-MM-DD HH:MM` in local time.
pub fn format_local(millis: i64) -> String {
    format_in(millis, system(), "%Y-%m-%d %H:%M")
}

/// A compact list date: the time today, the day this year, else the year.
pub fn short(millis: i64, now_millis: i64) -> String {
    short_in(millis, now_millis, system())
}

/// A full date for message headers, such as `Tue 21 Oct 2026 14:05`.
pub fn long(millis: i64) -> String {
    format_in(millis, system(), "%a %-d %b %Y %H:%M")
}

fn format_in(millis: i64, zone: &TimeZone, pattern: &str) -> String {
    match Timestamp::from_millisecond(millis) {
        Ok(instant) => instant.to_zoned(zone.clone()).strftime(pattern).to_string(),
        Err(_) => "?".to_owned(),
    }
}

fn short_in(millis: i64, now_millis: i64, zone: &TimeZone) -> String {
    let (Ok(instant), Ok(now)) = (
        Timestamp::from_millisecond(millis),
        Timestamp::from_millisecond(now_millis),
    ) else {
        return "?".to_owned();
    };
    let (instant, now) = (instant.to_zoned(zone.clone()), now.to_zoned(zone.clone()));
    let pattern = if instant.date() == now.date() {
        "%H:%M"
    } else if instant.year() == now.year() {
        "%-d %b"
    } else {
        "%Y"
    };
    instant.strftime(pattern).to_string()
}

#[cfg(test)]
mod tests {
    use jiff::tz::TimeZone;

    use super::{format_in, short_in};

    const OCT_21_2026_1405_UTC: i64 = 1_792_591_500_000;

    #[test]
    fn formats_known_instants() {
        let utc = TimeZone::UTC;
        assert_eq!(format_in(0, &utc, "%Y-%m-%d %H:%M"), "1970-01-01 00:00");
        assert_eq!(
            format_in(951_782_400_000, &utc, "%Y-%m-%d %H:%M"),
            "2000-02-29 00:00"
        );
        assert_eq!(
            format_in(OCT_21_2026_1405_UTC, &utc, "%a %-d %b %Y %H:%M"),
            "Wed 21 Oct 2026 14:05"
        );
        assert_eq!(format_in(i64::MAX, &utc, "%Y"), "?");
    }

    #[test]
    fn short_dates_depend_on_distance() {
        let utc = TimeZone::UTC;
        let now = OCT_21_2026_1405_UTC;
        assert_eq!(short_in(now - 3_600_000, now, &utc), "13:05");
        assert_eq!(short_in(now - 86_400_000 * 20, now, &utc), "1 Oct");
        assert_eq!(short_in(now - 86_400_000 * 400, now, &utc), "2025");
    }

    #[test]
    fn the_zone_shifts_the_wall_clock() {
        let rome = TimeZone::fixed(jiff::tz::offset(2));
        assert_eq!(format_in(OCT_21_2026_1405_UTC, &rome, "%H:%M"), "16:05");
    }
}
