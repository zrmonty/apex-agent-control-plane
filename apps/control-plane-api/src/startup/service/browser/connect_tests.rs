use super::connect_until_shutdown;
use apex_control_plane_api::GatewayShutdown;
use std::{cell::Cell, task::Poll, time::Duration};

#[tokio::test]
async fn already_requested_shutdown_never_polls_connection() {
    let shutdown = GatewayShutdown::default();
    shutdown.request();
    let polled = Cell::new(false);
    let result = connect_until_shutdown(&shutdown, std::future::poll_fn(|_| {
        polled.set(true);
        Poll::Ready(Err::<(), _>("connection failed"))
    })).await;
    assert_eq!(result, Ok(None));
    assert!(!polled.get());
}

#[tokio::test(start_paused = true)]
async fn pending_connection_is_dropped_when_shutdown_arrives() {
    let shutdown = GatewayShutdown::default();
    let polled = Cell::new(false);
    let dropped = Cell::new(false);
    struct Guard<'a>(&'a Cell<bool>);
    impl Drop for Guard<'_> { fn drop(&mut self) { self.0.set(true); } }
    let guard = Guard(&dropped);
    let operation = async {
        let _guard = guard;
        polled.set(true);
        shutdown.request();
        std::future::pending::<Result<(), &'static str>>().await
    };
    let result = tokio::time::timeout(Duration::from_millis(10), connect_until_shutdown(&shutdown, operation)).await;
    assert_eq!(result, Ok(Ok(None)), "normal stop must cancel pending startup, not await its deadline");
    assert!(polled.get() && dropped.get());
}

#[tokio::test]
async fn genuine_connection_failure_is_preserved() {
    let shutdown = GatewayShutdown::default();
    assert_eq!(connect_until_shutdown(&shutdown, async { Err::<(), _>("failed") }).await, Err("failed"));
}

#[tokio::test]
async fn successful_connection_is_returned_without_shutdown() {
    let shutdown = GatewayShutdown::default();
    assert_eq!(connect_until_shutdown(&shutdown, async { Ok::<_, ()>(7) }).await, Ok(Some(7)));
}
