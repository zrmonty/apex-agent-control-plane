//! Private deterministic scheduling only: all IO and authorization remain real.
use std::{
    cell::RefCell,
    sync::{Arc, Mutex, mpsc},
    time::Instant,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Point {
    Preflight,
    Spawn,
    NetworkSpawn,
    NetworkChild,
    NetworkCommandReturned,
    NetworkIntent,
    NetworkCreated,
    ProofIntent,
    StageIntent,
    StageFile,
    Sealed,
    CreateIntent,
    Created,
    RemoveIntent,
    Removed,
    StageUnlink,
}
pub(crate) struct Gate {
    pub reached: tokio::sync::oneshot::Receiver<Option<Instant>>,
    release: Option<mpsc::Sender<bool>>,
}
impl Gate {
    pub fn release(mut self, fail: bool) {
        self.release.take().unwrap().send(fail).unwrap();
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        if let Some(s) = self.release.take() {
            let _ = s.send(true);
        }
    }
}
type Schedule = (
    Point,
    tokio::sync::oneshot::Sender<Option<Instant>>,
    mpsc::Receiver<bool>,
);
#[derive(Default)]
pub(crate) struct Hooks {
    schedule: Mutex<Option<Schedule>>,
    trace: Mutex<Vec<Point>>,
}
impl Hooks {
    pub fn arm(&self, point: Point) -> Gate {
        let (sent, reached) = tokio::sync::oneshot::channel();
        let (release, received) = mpsc::channel();
        assert!(
            self.schedule
                .lock()
                .unwrap()
                .replace((point, sent, received))
                .is_none()
        );
        Gate {
            reached,
            release: Some(release),
        }
    }
    pub fn count(&self, point: Point) -> usize {
        self.trace
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == point)
            .count()
    }
}
thread_local! { static CURRENT: RefCell<Option<Arc<Hooks>>> = const { RefCell::new(None) }; }
pub(super) struct Scope(Option<Arc<Hooks>>);
pub(super) fn enter(hooks: &Arc<Hooks>) -> Scope {
    Scope(CURRENT.replace(Some(Arc::clone(hooks))))
}
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.set(self.0.take());
    }
}
pub(crate) fn at(point: Point, deadline: Option<Instant>) -> Result<(), &'static str> {
    let hooks = CURRENT.with_borrow(Clone::clone);
    let Some(hooks) = hooks else { return Ok(()) };
    let mut trace = hooks.trace.lock().unwrap();
    assert!(trace.len() < 8192, "bounded acceptance trace");
    trace.push(point);
    drop(trace);
    let mut schedule = hooks.schedule.lock().unwrap();
    if schedule.as_ref().is_some_and(|s| s.0 == point) {
        let (_, sent, received) = schedule.take().unwrap();
        drop(schedule);
        let _ = sent.send(deadline);
        if received.recv().unwrap_or(true) {
            return Err("RUNTIME_TEST_BOUNDARY_INTERRUPTED");
        }
    }
    Ok(())
}
