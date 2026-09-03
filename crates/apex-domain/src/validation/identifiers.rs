pub fn is_lowercase_uuidv7(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().get(8) == Some(&b'-')
        && value.as_bytes().get(13) == Some(&b'-')
        && value.as_bytes().get(18) == Some(&b'-')
        && value.as_bytes().get(23) == Some(&b'-')
        && value.as_bytes().get(14) == Some(&b'7')
        && matches!(value.as_bytes().get(19), Some(b'8' | b'9' | b'a' | b'b'))
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        })
}

pub(crate) fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn is_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 27
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[26] != b'Z'
    {
        return false;
    }
    if !bytes[..4]
        .iter()
        .chain(&bytes[5..7])
        .chain(&bytes[8..10])
        .chain(&bytes[11..13])
        .chain(&bytes[14..16])
        .chain(&bytes[17..19])
        .chain(&bytes[20..26])
        .all(u8::is_ascii_digit)
    {
        return false;
    }
    let month = two_digits(&bytes[5..7]);
    let day = two_digits(&bytes[8..10]);
    let hour = two_digits(&bytes[11..13]);
    let minute = two_digits(&bytes[14..16]);
    let second = two_digits(&bytes[17..19]);
    let year = four_digits(&bytes[..4]);
    // Python's datetime (used by the reference SDK) and common SQL timestamp
    // types do not represent year zero. Reject it at the ingress boundary so
    // clients cannot produce an event that is valid in Rust but unportable to
    // the rest of the project.
    if year == 0 {
        return false;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    };
    (1..=days_in_month).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

fn two_digits(value: &[u8]) -> u32 {
    u32::from(value[0] - b'0') * 10 + u32::from(value[1] - b'0')
}

fn four_digits(value: &[u8]) -> u32 {
    u32::from(value[0] - b'0') * 1_000
        + u32::from(value[1] - b'0') * 100
        + u32::from(value[2] - b'0') * 10
        + u32::from(value[3] - b'0')
}

pub fn is_scope_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

