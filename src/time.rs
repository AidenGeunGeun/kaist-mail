//! Instants as Unix seconds: Dooray's RFC 3339 timestamps and the CLI's date
//! bounds. KAIST accounts use Korea time, so dates without a time are read,
//! and instants sent to Dooray are written, at +09:00.

use std::ops::RangeInclusive;

const KOREA: i64 = 9 * 3600;

/// Instants kaist-mail accepts: those a second either side of which still
/// has a four-digit year in Korea time, so a widened bound stays writable.
pub const RANGE: RangeInclusive<i64> =
    (-62_167_219_200 - KOREA + 1)..=(253_402_300_799 - KOREA - 1);

/// Unix seconds of `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` within [`RANGE`];
/// a fraction is dropped.
pub fn parse_rfc3339(value: &str) -> Option<i64> {
    let (date, rest) = value.split_once('T')?;
    let (clock, offset) = match rest.strip_suffix('Z') {
        Some(clock) => (clock, 0),
        None => {
            let (clock, offset) = rest.split_at(rest.rfind(['+', '-'])?);
            let (hours, minutes) = offset[1..].split_once(':')?;
            let seconds = number(hours, 0..=23)? * 3600 + number(minutes, 0..=59)? * 60;
            (
                clock,
                if offset.starts_with('-') {
                    -seconds
                } else {
                    seconds
                },
            )
        }
    };
    let clock = match clock.split_once('.') {
        Some((clock, fraction)) if digits(fraction) => clock,
        Some(_) => return None,
        None => clock,
    };
    let mut parts = clock.split(':');
    let (hour, minute, second) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let seconds =
        number(hour, 0..=23)? * 3600 + number(minute, 0..=59)? * 60 + number(second, 0..=59)?;
    Some(day(date)? * 86_400 + seconds - offset).filter(|instant| RANGE.contains(instant))
}

/// A `--since`/`--before` value: `YYYY-MM-DD` (midnight, Korea time) or RFC
/// 3339 in whole seconds, the precision Dooray reports received times in.
pub fn parse_bound(value: &str) -> Result<i64, String> {
    let midnight = || Some(day(value)? * 86_400 - KOREA).filter(|instant| RANGE.contains(instant));
    let instant = || parse_rfc3339(value).filter(|_| !value.contains('.'));
    midnight().or_else(instant).ok_or_else(|| {
        "expected YYYY-MM-DD (Korea time) or RFC 3339 in whole seconds such as 2026-11-12T09:00:00+09:00".into()
    })
}

/// RFC 3339 in Korea time, the form sent to Dooray.
pub fn format_korea(seconds: i64) -> String {
    let local = seconds + KOREA;
    let (year, month, day) = civil(local.div_euclid(86_400));
    let clock = local.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+09:00",
        clock / 3600,
        clock % 3600 / 60,
        clock % 60
    )
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn number(value: &str, range: std::ops::RangeInclusive<i64>) -> Option<i64> {
    if value.len() != 2 || !digits(value) {
        return None;
    }
    let value = value.parse().ok()?;
    range.contains(&value).then_some(value)
}

/// Days since 1970-01-01 of an existing `YYYY-MM-DD` date.
fn day(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || year.len() != 4 || !digits(year) {
        return None;
    }
    let date = (
        year.parse().ok()?,
        number(month, 1..=12)?,
        number(day, 1..=31)?,
    );
    let days = days_from_civil(date);
    (civil(days) == date).then_some(days)
}

// Howard Hinnant's proleptic Gregorian conversions.
fn days_from_civil((year, month, day): (i64, i64, i64)) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = (shifted_month + 2) % 12 + 1;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_match_independently_computed_unix_seconds() {
        for (value, seconds) in [
            ("2026-11-12T09:41:07+09:00", 1_794_444_067),
            ("1969-12-31T23:59:59-05:00", 17_999),
            ("2024-02-29T12:00:00.250Z", 1_709_208_000),
        ] {
            assert_eq!(parse_rfc3339(value), Some(seconds), "{value}");
        }
        assert_eq!(parse_bound("2026-11-01"), Ok(1_793_458_800));
        assert_eq!(format_korea(1_794_444_067), "2026-11-12T09:41:07+09:00");
        assert_eq!(format_korea(-1), "1970-01-01T08:59:59+09:00");
        assert_eq!(format_korea(RANGE.start() - 1), "0000-01-01T00:00:00+09:00");
        assert_eq!(format_korea(RANGE.end() + 1), "9999-12-31T23:59:59+09:00");
        for invalid in [
            "2026-02-29",
            "2026-11-12T24:00:00+09:00",
            "2026-11-12T09:41+09:00",
            "2026-11-12 09:41:07+09:00",
            "26-11-12",
            "2026-11-12T12:00:00.5+09:00",
            "0000-01-01",
            "9999-12-31T23:59:59+09:00",
        ] {
            assert!(parse_bound(invalid).is_err(), "{invalid}");
        }
    }
}
