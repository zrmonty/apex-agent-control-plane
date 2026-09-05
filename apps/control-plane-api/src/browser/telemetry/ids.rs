//! Fallible OS entropy, not UUID bits or caller-supplied trace context.
use super::InitError;

pub(super) fn random_hex<const N: usize>() -> Result<String, InitError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| InitError::Entropy)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(InitError::Entropy);
    }
    let mut result = String::with_capacity(N * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(result)
}

pub(super) fn request_id(unix_us: u64) -> Result<String, InitError> {
    let millis = unix_us / 1_000;
    if millis >= (1_u64 << 48) {
        return Err(InitError::Clock);
    }
    let mut random = [0; 10];
    getrandom::fill(&mut random).map_err(|_| InitError::Entropy)?;
    // The library sets the UUIDv7 version/variant. Its timestamp is an ID aid,
    // never the source of measured elapsed time; W3C IDs use separate entropy.
    Ok(uuid::Builder::from_unix_timestamp_millis(millis, &random)
        .into_uuid()
        .to_string())
}
