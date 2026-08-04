use std::time::{SystemTime, UNIX_EPOCH};

use super::error::FindingError;

pub(crate) fn now_ms() -> Result<u64, FindingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| FindingError::clock_unavailable())
}

pub(crate) fn uuid7() -> Result<String, FindingError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| FindingError::entropy_unavailable())?;

    // UUIDv7: a big-endian 48-bit Unix-millisecond timestamp, version 7,
    // and 74 cryptographically random bits. The random tail is deliberately
    // not sequence-derived or process-seeded, so IDs remain unpredictable
    // across restarts and concurrent producers.
    let timestamp = now_ms()? & 0x0000_ffff_ffff_ffff;
    bytes[..6].copy_from_slice(&timestamp.to_be_bytes()[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}
