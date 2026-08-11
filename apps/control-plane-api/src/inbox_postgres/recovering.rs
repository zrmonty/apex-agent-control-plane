use crate::errors::{CommandError, CommandErrorCode};
use crate::inbox::{
    AckResult, CancelResult, CommandInbox, DeliveryPolicy, DeliveryStatus, InboxKey,
    ListCommandsPage, ListCommandsQuery, PendingCommand, PollTarget, RecordResult, ScopeAuthorizer,
};

use super::PostgresCommandInbox;

/// Reconnects a Postgres inbox slot after a transport-level failure. A poll
/// may be redelivered after an ambiguous transaction outcome, which is already
/// part of the inbox's at-least-once contract; losing the slot until restart
/// is not.
pub struct RecoveringPostgresCommandInbox {
    connection_string: String,
    capacity: usize,
    scope_quota: usize,
    inner: PostgresCommandInbox,
}

impl RecoveringPostgresCommandInbox {
    pub fn connect(
        connection_string: &str,
        capacity: usize,
        scope_quota: usize,
    ) -> Result<Self, CommandError> {
        let inner = PostgresCommandInbox::connect(connection_string, capacity, scope_quota)?;
        Ok(Self {
            connection_string: connection_string.to_owned(),
            capacity,
            scope_quota,
            inner,
        })
    }

    fn with_retry<T>(
        &mut self,
        mut operation: impl FnMut(&mut PostgresCommandInbox) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        match operation(&mut self.inner) {
            Ok(value) => Ok(value),
            Err(error) if error.code == CommandErrorCode::Internal => {
                let replacement = PostgresCommandInbox::connect(
                    &self.connection_string,
                    self.capacity,
                    self.scope_quota,
                )?;
                self.inner = replacement;
                operation(&mut self.inner)
            }
            Err(error) => Err(error),
        }
    }
}

impl CommandInbox for RecoveringPostgresCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        self.with_retry(|inner| inner.record(command))
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        self.with_retry(|inner| inner.claim(target, scopes, policy, now_millis))
    }

    fn undelivered_count(&mut self) -> usize {
        self.inner.undelivered_count()
    }

    fn pending_count(&mut self) -> usize {
        self.inner.pending_count()
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        self.with_retry(|inner| inner.acknowledge(target, key, delivery_attempt, now_millis))
    }

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        self.with_retry(|inner| inner.status(key, max_attempts))
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        self.with_retry(|inner| inner.list_commands(query))
    }

    fn cancel(
        &mut self,
        key: &InboxKey,
        now_millis: u64,
    ) -> Result<CancelResult, CommandError> {
        self.with_retry(|inner| inner.cancel(key, now_millis))
    }

    fn maintain(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
        max_attempts: u32,
    ) -> Result<(), CommandError> {
        self.with_retry(|inner| inner.maintain(now_millis, retention_millis, max_attempts))
    }
}
