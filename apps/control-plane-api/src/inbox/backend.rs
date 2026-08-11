use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// Serialises file and in-memory inbox operations behind one lock. Postgres
/// uses a bounded set of independent connections so concurrent gateway work
/// can use row-level locking without sharing one process mutex.
pub struct ControlInboxBackend {
    inner: InboxBackendInner,
}

enum InboxBackendInner {
    Single(Mutex<Box<dyn CommandInbox + Send>>),
    Pool {
        connections: Vec<Mutex<Box<dyn CommandInbox + Send>>>,
        next: AtomicUsize,
    },
}

impl ControlInboxBackend {
    pub fn new(inbox: Box<dyn CommandInbox + Send>) -> Self {
        Self {
            inner: InboxBackendInner::Single(Mutex::new(inbox)),
        }
    }

    pub fn new_pool(inboxes: Vec<Box<dyn CommandInbox + Send>>) -> Result<Self, CommandError> {
        if inboxes.is_empty() {
            return Err(CommandError::internal());
        }
        Ok(Self {
            inner: InboxBackendInner::Pool {
                connections: inboxes.into_iter().map(Mutex::new).collect(),
                next: AtomicUsize::new(0),
            },
        })
    }

    pub fn with_lock<T>(
        &self,
        f: impl FnOnce(&mut Box<dyn CommandInbox + Send>) -> T,
    ) -> Result<T, CommandError> {
        match &self.inner {
            InboxBackendInner::Single(inner) => {
                let mut guard = inner.lock().map_err(|_| CommandError::internal())?;
                Ok(f(&mut guard))
            }
            InboxBackendInner::Pool { connections, next } => {
                let index = next.fetch_add(1, Ordering::Relaxed) % connections.len();
                let mut guard = connections[index]
                    .lock()
                    .map_err(|_| CommandError::internal())?;
                Ok(f(&mut guard))
            }
        }
    }

    pub fn pending_count(&self) -> Result<u64, CommandError> {
        let count = self.with_lock(|inbox| inbox.pending_count())?;
        u64::try_from(count).map_err(|_| CommandError::internal())
    }

    pub fn undelivered_count(&self) -> Result<u64, CommandError> {
        let count = self.with_lock(|inbox| inbox.undelivered_count())?;
        u64::try_from(count).map_err(|_| CommandError::internal())
    }

    pub fn acknowledge(
        &self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        self.with_lock(|inbox| inbox.acknowledge(target, key, delivery_attempt, now_millis))?
    }

    pub fn status(
        &self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        self.with_lock(|inbox| inbox.status(key, max_attempts))?
    }

    pub fn list_commands(
        &self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        self.with_lock(|inbox| inbox.list_commands(query))?
    }

    pub fn cancel(&self, key: &InboxKey, now_millis: u64) -> Result<CancelResult, CommandError> {
        self.with_lock(|inbox| inbox.cancel(key, now_millis))?
    }
}
