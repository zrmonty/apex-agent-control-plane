//! Owned server tasks and bounded drain. Dropping a JoinSet aborts its members;
//! the synchronous caller retains blocking resource owners beyond runtime drop.
use apex_control_plane_api::GatewayShutdown;
use std::{future::Future, io, time::Duration};
use tokio::task::JoinSet;

pub(super) struct StopOnDrop(pub GatewayShutdown);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.request();
    }
}

pub(super) async fn wait(
    servers: &mut JoinSet<io::Result<()>>,
    signal: impl Future<Output = ()>,
    shutdown: &GatewayShutdown,
) -> io::Result<()> {
    tokio::select! {
        biased;
        _ = shutdown.wait() => Ok(()),
        _ = signal => Ok(()),
        completed = servers.join_next() => match completed {
            Some(Ok(Err(error))) => Err(error),
            _ => Err(io::Error::other("control or browser listener stopped unexpectedly")),
        }
    }
}

pub(super) async fn drain(servers: &mut JoinSet<io::Result<()>>) -> io::Result<()> {
    let drained = tokio::time::timeout(Duration::from_secs(65), async {
        let mut failed = false;
        while let Some(result) = servers.join_next().await {
            failed |= !matches!(result, Ok(Ok(())));
        }
        failed
    })
    .await;
    match drained {
        Ok(false) => Ok(()),
        Ok(true) => Err(io::Error::other(
            "control or browser listener shutdown failed",
        )),
        Err(_) => {
            servers.abort_all();
            while servers.join_next().await.is_some() {}
            Err(io::Error::other(
                "control or browser listener drain timed out",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    #[tokio::test]
    async fn signal_and_drop_guard_stop_without_waiting_for_a_server_exit() {
        let shutdown = GatewayShutdown::default();
        let guard = StopOnDrop(shutdown.clone());
        let mut servers = JoinSet::new();
        let stopping = shutdown.clone();
        servers.spawn(async move {
            stopping.wait().await;
            Ok(())
        });
        assert!(wait(&mut servers, async {}, &shutdown).await.is_ok());
        drop(guard);
        assert!(shutdown.is_requested());
        assert!(drain(&mut servers).await.is_ok());
        assert!(servers.is_empty());
    }

    #[tokio::test]
    async fn an_unexpected_clean_exit_or_failed_task_is_not_healthy_serving() {
        for fails in [false, true] {
            let mut servers = JoinSet::new();
            servers.spawn(async move {
                if fails {
                    Err(io::Error::other("fixture-failure"))
                } else {
                    Ok(())
                }
            });
            assert!(
                wait(&mut servers, pending(), &GatewayShutdown::default())
                    .await
                    .is_err()
            );
            assert!(servers.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_server_drain_aborts_and_joins_the_owned_task() {
        struct ObservedDrop(Arc<AtomicBool>);
        impl Drop for ObservedDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let owner = ObservedDrop(Arc::clone(&dropped));
        let mut servers = JoinSet::new();
        servers.spawn(async move {
            let _owner = owner;
            pending::<io::Result<()>>().await
        });
        assert!(drain(&mut servers).await.is_err());
        assert!(servers.is_empty());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn drain_reports_failure_after_joining_every_remaining_server() {
        let mut servers = JoinSet::new();
        servers.spawn(async { Err(io::Error::other("fixture-error")) });
        servers.spawn(async { Ok(()) });
        assert!(drain(&mut servers).await.is_err());
        assert!(servers.is_empty());
    }
}
