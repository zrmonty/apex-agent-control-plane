use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

pub(crate) const MAX_COMMAND_ID_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
pub(crate) const MAX_COMMAND_ID_AGE_MS: u64 = 24 * 60 * 60 * 1_000;

/// Extracts the embedded 48-bit millisecond Unix timestamp from a canonical
/// lowercase UUIDv7.
pub(crate) fn uuidv7_unix_millis(command_id: &str) -> Option<u64> {
    let uuid = Uuid::parse_str(command_id).ok()?;
    if uuid.get_version_num() != 7 || uuid.hyphenated().to_string() != command_id {
        return None;
    }
    let (secs, nanos) = uuid.get_timestamp()?.to_unix();
    u64::try_from((secs as u128) * 1_000 + (nanos as u128) / 1_000_000).ok()
}

pub(crate) fn command_millis_within_acceptance_window(
    command_millis: u64,
    now_millis: u64,
) -> bool {
    if command_millis > now_millis {
        command_millis - now_millis <= MAX_COMMAND_ID_FUTURE_SKEW_MS
    } else {
        now_millis - command_millis <= MAX_COMMAND_ID_AGE_MS
    }
}

/// Wall-clock milliseconds since the Unix epoch.
pub(crate) fn now_unix_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

pub(crate) fn rfc3339_from_uuidv7(command_id: &str) -> Option<String> {
    uuidv7_unix_millis(command_id).map(|millis| format_rfc3339_micros(u128::from(millis) * 1_000))
}

pub(crate) fn format_rfc3339_micros(total_micros: u128) -> String {
    let secs = (total_micros / 1_000_000) as i64;
    let micros = (total_micros % 1_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

/// Howard Hinnant's civil-date conversion relative to the Unix epoch.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
