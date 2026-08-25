//! [`crate::inbox::ControlInboxBackend`] tests: the single-mutex
//! serialization guarantee across concurrent callers.

use crate::inbox::*;
use crate::errors::{CommandError, CommandErrorCode};

use super::support::*;

/// A restarted or duplicated agent process polling concurrently must not
/// both receive the same command. The backend's single mutex is what makes
/// that true, so this drives it through the backend rather than the raw
/// inbox.
#[test]
fn concurrent_polls_never_hand_one_command_to_two_callers() {
    use std::sync::Arc;

    let backend = Arc::new(ControlInboxBackend::new(Box::new(
        InMemoryCommandInbox::new(64, 64),
    )));
    backend
        .with_lock(|inbox| inbox.record(&command("cmd-1", "agent-a")))
        .unwrap()
        .unwrap();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let backend = Arc::clone(&backend);
        handles.push(std::thread::spawn(move || {
            backend
                .with_lock(|inbox| {
                    inbox.claim(
                        &target("agent-a"),
                        &acme_prod(),
                        DeliveryPolicy::default(),
                        5_000,
                    )
                })
                .unwrap()
                .unwrap()
                .len()
        }));
    }
    let total: usize = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .sum();
    assert_eq!(
        total, 1,
        "exactly one concurrent poll may receive the command"
    );
}

struct FailingDiagnosticInbox {
    inner: InMemoryCommandInbox,
}

impl CommandInbox for FailingDiagnosticInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        self.inner.record(command)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        self.inner.claim(target, scopes, policy, now_millis)
    }

    fn undelivered_count(&mut self) -> usize {
        self.inner.undelivered_count()
    }

    fn pending_count(&mut self) -> usize {
        self.inner.pending_count()
    }

    fn try_undelivered_count(&mut self) -> Result<usize, CommandError> {
        Err(CommandError::internal())
    }

    fn try_pending_count(&mut self) -> Result<usize, CommandError> {
        Err(CommandError::internal())
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        self.inner
            .acknowledge(target, key, delivery_attempt, now_millis)
    }

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        self.inner.status(key, max_attempts)
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        self.inner.list_commands(query)
    }

    fn cancel(
        &mut self,
        key: &InboxKey,
        now_millis: u64,
    ) -> Result<CancelResult, CommandError> {
        self.inner.cancel(key, now_millis)
    }
}

#[test]
fn diagnostic_count_failures_are_not_reported_as_zero() {
    let backend = ControlInboxBackend::new(Box::new(FailingDiagnosticInbox {
        inner: InMemoryCommandInbox::new(4, 4),
    }));
    assert_eq!(
        backend.pending_count().unwrap_err().code,
        CommandErrorCode::Internal
    );
    assert_eq!(
        backend.undelivered_count().unwrap_err().code,
        CommandErrorCode::Internal
    );
}
