use super::*;
use std::{
    future::poll_fn,
    pin::Pin,
    sync::atomic::AtomicU64,
    task::{Context, Poll, Waker},
};

// Only the external wait and clock are controlled. The real provider workflow,
// OAuth request builder, signed fixtures, and access/ID validation still run.
#[derive(Clone)]
struct ManualClock {
    origin: Instant,
    millis: Arc<AtomicU64>,
}
impl ManualClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            millis: Arc::new(AtomicU64::new(0)),
        }
    }
    fn set(&self, millis: u64) {
        self.millis.store(millis, Ordering::SeqCst);
    }
}
impl MonotonicClock for ManualClock {
    fn now(&self) -> Instant {
        self.origin
            .checked_add(Duration::from_millis(self.millis.load(Ordering::SeqCst)))
            .expect("bounded fixture clock offset")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Discovery,
    Jwks,
    Token,
}

struct StagedHttp {
    inner: Fixture,
    stage: Stage,
    released: AtomicBool,
    clock: ManualClock,
    ready_at: Option<u64>,
}
impl StagedHttp {
    async fn wait(&self, stage: Stage) {
        if stage != self.stage {
            return;
        }
        // Tests explicitly poll after changing readiness: no wall-clock sleep,
        // scheduler race, or background task supplies the boundary condition.
        poll_fn(|_| {
            if self.released.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        if let Some(millis) = self.ready_at {
            self.clock.set(millis);
        }
    }
}
impl ProviderSource for StagedHttp {
    async fn discovery(&self) -> Result<Vec<u8>, BrowserError> {
        let value = self.inner.discovery().await?;
        self.wait(Stage::Discovery).await;
        Ok(value)
    }
    async fn jwks(&self) -> Result<Vec<u8>, BrowserError> {
        let value = self.inner.jwks().await?;
        self.wait(Stage::Jwks).await;
        Ok(value)
    }
}
impl ProviderHttp for StagedHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BrowserError> {
        let value = self.inner.send(request).await?;
        self.wait(Stage::Token).await;
        Ok(value)
    }
}

fn staged(stage: Stage, ready_at: Option<u64>) -> ProviderCore<StagedHttp, ManualClock> {
    let clock = ManualClock::new();
    let http = StagedHttp {
        inner: Fixture::new(),
        stage,
        released: AtomicBool::new(false),
        clock: clock.clone(),
        ready_at,
    };
    ProviderCore::with_clock(Arc::new(config()), http, Arc::new(resolver()), clock).unwrap()
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn exchange(
    core: &ProviderCore<StagedHttp, ManualClock>,
) -> impl Future<Output = Result<VerifiedProviderTokens, BrowserError>> + '_ {
    core.exchange(
        TokenRequest::Code {
            code: "one-use-code",
            pkce: NONCE,
        },
        IdTokenExpectation::Login { nonce: NONCE },
    )
}

fn closed(result: Poll<Result<VerifiedProviderTokens, BrowserError>>) {
    match result {
        Poll::Ready(Err(error)) => assert_eq!(error, BrowserError::Unavailable),
        other => panic!("expired exchange must finish closed, got {other:?}"),
    }
}

#[tokio::test]
async fn late_unpolled_discovery_cannot_start_jwks_or_token_and_recovers_permit() {
    let core = staged(Stage::Discovery, None);
    let mut operation = Box::pin(exchange(&core));
    assert!(poll_once(operation.as_mut()).is_pending());
    assert_eq!(core.slots.available_permits(), 7);
    core.clock.set(11_000);
    core.http.released.store(true, Ordering::SeqCst);
    closed(poll_once(operation.as_mut()));
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(*core.http.inner.calls.lock().unwrap(), ["discovery"]);
}

#[tokio::test]
async fn late_unpolled_jwks_at_exact_deadline_cannot_start_token_and_recovers_permit() {
    let core = staged(Stage::Jwks, None);
    let mut operation = Box::pin(exchange(&core));
    assert!(poll_once(operation.as_mut()).is_pending());
    assert_eq!(
        *core.http.inner.calls.lock().unwrap(),
        ["discovery", "jwks"]
    );
    core.clock.set(10_000);
    core.http.released.store(true, Ordering::SeqCst);
    closed(poll_once(operation.as_mut()));
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(
        *core.http.inner.calls.lock().unwrap(),
        ["discovery", "jwks"]
    );
}

#[tokio::test]
async fn deadline_crossed_inside_ready_discovery_cannot_start_the_next_stage() {
    let core = staged(Stage::Discovery, Some(10_000));
    core.http.released.store(true, Ordering::SeqCst);
    let mut operation = Box::pin(exchange(&core));
    closed(poll_once(operation.as_mut()));
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(*core.http.inner.calls.lock().unwrap(), ["discovery"]);
}

#[tokio::test]
async fn deadline_crossed_inside_ready_jwks_cannot_start_token() {
    let core = staged(Stage::Jwks, Some(10_001));
    core.http.released.store(true, Ordering::SeqCst);
    let mut operation = Box::pin(exchange(&core));
    closed(poll_once(operation.as_mut()));
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(
        *core.http.inner.calls.lock().unwrap(),
        ["discovery", "jwks"]
    );
}

#[tokio::test]
async fn ready_jwks_just_before_deadline_can_finish_once_without_reanchoring() {
    let core = staged(Stage::Jwks, None);
    let mut operation = Box::pin(exchange(&core));
    assert!(poll_once(operation.as_mut()).is_pending());
    core.clock.set(9_999);
    core.http.released.store(true, Ordering::SeqCst);
    match poll_once(operation.as_mut()) {
        Poll::Ready(Ok(tokens)) => assert_eq!(tokens.subject, "subject-123"),
        other => panic!("still-live exchange must succeed, got {other:?}"),
    }
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(
        *core.http.inner.calls.lock().unwrap(),
        ["discovery", "jwks", "token"]
    );
}

#[tokio::test]
async fn late_ready_token_result_is_rejected_and_its_permit_is_recovered() {
    let core = staged(Stage::Token, None);
    let mut operation = Box::pin(exchange(&core));
    assert!(poll_once(operation.as_mut()).is_pending());
    core.clock.set(10_001);
    core.http.released.store(true, Ordering::SeqCst);
    closed(poll_once(operation.as_mut()));
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(
        *core.http.inner.calls.lock().unwrap(),
        ["discovery", "jwks", "token"]
    );
}

#[tokio::test]
async fn ready_token_result_that_crosses_deadline_in_one_poll_is_rejected() {
    let core = staged(Stage::Token, Some(10_001));
    core.http.released.store(true, Ordering::SeqCst);
    let mut operation = Box::pin(exchange(&core));
    closed(poll_once(operation.as_mut()));
    drop(operation);
    assert_eq!(core.slots.available_permits(), 8);
    assert_eq!(
        *core.http.inner.calls.lock().unwrap(),
        ["discovery", "jwks", "token"]
    );
}

#[tokio::test]
async fn dropping_each_pending_stage_recovers_permits_without_starting_more_work() {
    for (stage, expected) in [
        (Stage::Discovery, vec!["discovery"]),
        (Stage::Jwks, vec!["discovery", "jwks"]),
        (Stage::Token, vec!["discovery", "jwks", "token"]),
    ] {
        let core = staged(stage, None);
        let mut operation = Box::pin(exchange(&core));
        assert!(poll_once(operation.as_mut()).is_pending());
        assert_eq!(core.slots.available_permits(), 7);
        drop(operation);
        assert_eq!(core.slots.available_permits(), 8);
        assert_eq!(*core.http.inner.calls.lock().unwrap(), expected);
    }
}
