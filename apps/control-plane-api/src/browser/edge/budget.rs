use super::BrowserError;
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

/// One monotonic budget for the entire HTTP request, including body reads.
#[derive(Clone, Copy)]
pub(super) struct Budget(Instant);
impl Budget {
    pub fn new(timeout: Duration) -> Result<Self, BrowserError> {
        Instant::now()
            .checked_add(timeout)
            .map(Self)
            .ok_or(BrowserError::Unavailable)
    }
    pub fn check(self) -> Result<(), BrowserError> {
        if Instant::now() >= self.0 {
            Err(BrowserError::Unavailable)
        } else {
            Ok(())
        }
    }
    pub async fn run<T>(self, future: impl Future<Output = T>) -> Result<T, BrowserError> {
        let mut future = pin!(future);
        let guarded = poll_fn(|cx| {
            if let Err(error) = self.check() {
                return Poll::Ready(Err(error));
            }
            let result = future.as_mut().poll(cx);
            if let Err(error) = self.check() {
                return Poll::Ready(Err(error));
            }
            result.map(Ok)
        });
        tokio::time::timeout_at(self.0, guarded)
            .await
            .map_err(|_| BrowserError::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        future::poll_fn,
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test(start_paused = true)]
    async fn overdue_request_is_not_polled_into_a_new_side_effect() {
        let budget = Budget::new(Duration::from_secs(15)).unwrap();
        let ready = Cell::new(false);
        let calls = Cell::new(0);
        let operation = async {
            poll_fn(|_| {
                if ready.get() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            calls.set(calls.get() + 1);
        };
        let mut operation = Box::pin(budget.run(operation));
        assert!(poll(operation.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(15)).await;
        ready.set(true);
        assert!(matches!(
            poll(operation.as_mut()),
            Poll::Ready(Err(BrowserError::Unavailable))
        ));
        assert_eq!(
            calls.get(),
            0,
            "expired request must not run its next side effect"
        );
    }
    #[tokio::test(start_paused = true)]
    async fn already_expired_admission_never_polls_the_inner_operation() {
        let budget = Budget::new(Duration::ZERO).unwrap();
        let calls = Cell::new(0);
        let result = budget.run(async { calls.set(1) }).await;
        assert!(matches!(result, Err(BrowserError::Unavailable)));
        assert_eq!(calls.get(), 0);
    }
    #[tokio::test(start_paused = true)]
    async fn live_completion_and_explicit_stage_checks_share_the_original_deadline() {
        let budget = Budget::new(Duration::from_secs(15)).unwrap();
        tokio::time::advance(Duration::from_secs(14)).await;
        assert_eq!(budget.run(async { 7 }).await, Ok(7));
        assert_eq!(budget.check(), Ok(()));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(budget.check(), Err(BrowserError::Unavailable));
    }
}
