use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FINDING_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static FINDING_SEED: OnceLock<u64> = OnceLock::new();

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn uuid7() -> String {
    let time = now_ms();
    let seq = FINDING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let seed = *FINDING_SEED.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos() as u64)
    });
    let entropy = seed.wrapping_add(seq.rotate_left(17));
    format!(
        "{:08x}-{:04x}-7{:03x}-8{:03x}-{:012x}",
        time >> 16,
        time & 0xffff,
        entropy & 0xfff,
        (entropy >> 12) & 0xfff,
        entropy & 0xffffffffffff
    )
}
