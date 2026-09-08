use std::cell::Cell;

// Private caller-thread seam; no environment flag or shared cross-test state.
thread_local! {
    static REMAINING: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) struct Refusal(Option<usize>);

pub(super) fn after(successful_spawns: usize) -> Refusal {
    Refusal(REMAINING.replace(Some(successful_spawns)))
}

impl Drop for Refusal {
    fn drop(&mut self) {
        REMAINING.set(self.0);
    }
}

pub(in super::super) fn refuse_spawn() -> bool {
    REMAINING.with(|remaining| match remaining.get() {
        None => false,
        Some(0) => true,
        Some(count) => {
            remaining.set(Some(count - 1));
            false
        }
    })
}
