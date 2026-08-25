use std::collections::HashMap;

use super::*;

/// In-memory delivery state, shared by both backends.
///
/// `FileCommandInbox` is this plus a journal: every mutation is appended and
/// fsynced before the in-memory state changes, and startup replays the journal
/// into it. Keeping the decision logic in one place means the file backend
/// cannot drift from the in-memory one on the question that matters -- which
/// commands a given caller is entitled to see.
// `InboxState`/`Entry` and most of their fields and methods are `pub(super)`
// (visible to `inbox` and its descendants) rather than private: `FileCommandInbox`
// (`inbox::file`) is, by design, this plus a durable journal wrapped around it --
// see this type's own doc -- and reaches into these internals directly rather
// than through a narrower interface, so the file backend's replay/rollback logic
// cannot drift from the in-memory decision logic here.
#[derive(Debug, Clone, Default)]
pub(super) struct InboxState {
    /// Insertion order, so a poll returns oldest-first without sorting.
    pub(super) order: Vec<InboxKey>,
    pub(super) entries: HashMap<InboxKey, Entry>,
    /// Settled command identities retained for the idempotency window.
    pub(super) retired: HashMap<InboxKey, u64>,
    capacity: usize,
    /// Per-`(workspace_id, namespace_id)` ceiling, enforced in *addition* to
    /// `capacity`. See [`DEFAULT_INBOX_SCOPE_QUOTA`] for why this exists.
    scope_quota: usize,
    /// Live per-scope count of tracked commands -- `entries` plus `retired`,
    /// the same two buckets `capacity` counts globally -- kept incrementally
    /// so enforcing `scope_quota` in `record` never has to scan the whole
    /// inbox.
    scope_counts: HashMap<(String, String), usize>,
    /// Monotonically increasing identity assigned to each command at
    /// `record` time, purely for `list`'s cursor pagination. Never reused --
    /// not even when a retired command's key is later reused, since a fresh
    /// `record` always draws the next value -- so a page token issued before
    /// a retirement can never be confused with a later, unrelated command.
    /// This is the in-memory/file counterpart to `PostgresCommandInbox`'s
    /// `sequence` column (`BIGSERIAL`), which starts at 1 for the same
    /// reason this starts at 1: `0` is left free to mean "from the start".
    next_sequence: u64,
}

#[derive(Debug, Clone)]
pub(super) struct Entry {
    pub(super) command: PendingCommand,
    pub(super) attempts: u32,
    pub(super) last_delivered_millis: Option<u64>,
    pub(super) acknowledged: bool,
    pub(super) sequence: u64,
    /// Set by `cancel`. Mutually exclusive with `acknowledged` by
    /// construction: cancellation only ever succeeds while `attempts == 0`,
    /// and `acknowledge` requires `attempts >= 1`.
    pub(super) cancelled: bool,
    /// When cancellation became terminal. Unlike delivery, cancellation has
    /// no `last_delivered_millis`, so retention must use this timestamp.
    pub(super) cancelled_at_millis: Option<u64>,
}

impl InboxState {
    pub(super) fn new(capacity: usize, scope_quota: usize) -> Self {
        Self {
            order: Vec::new(),
            entries: HashMap::new(),
            retired: HashMap::new(),
            capacity,
            scope_quota,
            scope_counts: HashMap::new(),
            next_sequence: 1,
        }
    }

    fn key(command: &PendingCommand) -> InboxKey {
        InboxKey {
            workspace_id: command.workspace_id.clone(),
            namespace_id: command.namespace_id.clone(),
            command_id: command.command_id.clone(),
        }
    }

    fn scope(command: &PendingCommand) -> (String, String) {
        (command.workspace_id.clone(), command.namespace_id.clone())
    }

    /// Checks whether `command` may be recorded, without mutating any state.
    ///
    /// `Ok(Some(result))` means there is nothing left to do -- `command` is
    /// already present, so recording it is a no-op. `Ok(None)` means `command`
    /// is new and passed every admission check, so [`Self::insert_recorded`]
    /// is guaranteed to succeed. `Err` means it was refused.
    ///
    /// Split out from the insert step specifically so a caller with a durable
    /// journal (`FileCommandInbox`) can run this check *before* writing to
    /// that journal. A rejected command must never reach the journal: replay
    /// re-runs this same check against a `Command` journal entry via
    /// `load()`, and because that check depends on how full the scope already
    /// is, a phantom entry for a command that was refused for capacity would
    /// very likely still be over-quota at replay time -- and since `load()`
    /// deliberately fails closed on an admission failure rather than silently
    /// dropping it (the same rule this crate applies to every malformed
    /// credential-table entry), a single rejected write could otherwise make
    /// the journal permanently unreplayable until an operator hand-edited the
    /// file. Checking first is what keeps a rejected command out of the
    /// journal in the first place, so replay never has a reason to see one.
    pub(super) fn check_recordable(
        &self,
        command: &PendingCommand,
    ) -> Result<Option<RecordResult>, CommandError> {
        let key = Self::key(command);
        if self.entries.contains_key(&key) || self.retired.contains_key(&key) {
            return Ok(Some(RecordResult::AlreadyRecorded));
        }
        if self.entries.len().saturating_add(self.retired.len()) >= self.capacity {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        let scope = Self::scope(command);
        // Enforced in *addition* to the global ceiling above. This is what
        // stops one workspace/namespace from filling the entire shared inbox
        // and blocking delivery -- including an emergency `stop` -- to every
        // other tenant. See [`DEFAULT_INBOX_SCOPE_QUOTA`].
        if self.scope_counts.get(&scope).copied().unwrap_or(0) >= self.scope_quota {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "This workspace/namespace has reached its share of the durable command inbox. Retry after operator remediation.",
            ));
        }
        Ok(None)
    }

    /// Unconditionally inserts a command that [`Self::check_recordable`] has
    /// already admitted. Never call this without having just checked --
    /// nothing here re-validates capacity, scope quota, or duplication.
    pub(super) fn insert_recorded(&mut self, command: &PendingCommand) {
        let key = Self::key(command);
        let scope = Self::scope(command);
        // A tombstone that has just expired may still have its old key in the
        // insertion-order vector. Remove it before reusing the identity so a
        // later compaction cannot emit the command twice.
        self.order.retain(|existing| existing != &key);
        self.order.push(key.clone());
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.entries.insert(
            key,
            Entry {
                command: command.clone(),
                attempts: 0,
                last_delivered_millis: None,
                acknowledged: false,
                sequence,
                cancelled: false,
                cancelled_at_millis: None,
            },
        );
        *self.scope_counts.entry(scope).or_insert(0) += 1;
    }

    pub(super) fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        if let Some(result) = self.check_recordable(command)? {
            return Ok(result);
        }
        self.insert_recorded(command);
        Ok(RecordResult::Recorded)
    }

    /// Applies a replayed delivery record. Never widens state: an unknown key
    /// is ignored rather than synthesised, so a truncated or reordered journal
    /// cannot invent a command.
    pub(super) fn apply_delivery(&mut self, key: &InboxKey, attempt: u32, at_millis: u64) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.attempts = entry.attempts.max(attempt);
            entry.last_delivered_millis = Some(
                entry
                    .last_delivered_millis
                    .map_or(at_millis, |previous| previous.max(at_millis)),
            );
        }
    }

    /// Which stored commands `target` is entitled to receive right now.
    ///
    /// Every clause here is a server-derived predicate. There is no branch on
    /// anything a caller supplied except `limit`, which can only shorten the
    /// result.
    pub(super) fn deliverable(
        &self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Vec<InboxKey> {
        let mut selected = Vec::new();
        for key in &self.order {
            if selected.len() >= target.limit {
                break;
            }
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            // Target identity, then scope. Both are answered by the caller's
            // own credential; there is no path by which a request field
            // reaches either comparison.
            if entry.command.agent_id != target.agent_id {
                continue;
            }
            if !scopes.allows(&entry.command.workspace_id, &entry.command.namespace_id) {
                continue;
            }
            if entry.attempts >= policy.max_attempts {
                continue;
            }
            if entry.acknowledged {
                continue;
            }
            if entry.cancelled {
                continue;
            }
            let visible = match entry.last_delivered_millis {
                None => true,
                Some(delivered_at) => {
                    now_millis.saturating_sub(delivered_at)
                        >= policy.redelivery_after.as_millis() as u64
                }
            };
            if visible {
                selected.push(key.clone());
            }
        }
        selected
    }

    pub(super) fn mark_delivered(&mut self, key: &InboxKey, now_millis: u64) -> Option<PendingCommand> {
        let entry = self.entries.get_mut(key)?;
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_delivered_millis = Some(now_millis);
        let mut command = entry.command.clone();
        command.delivery_attempt = entry.attempts;
        Some(command)
    }

    pub(super) fn undelivered_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.attempts == 0 && !entry.cancelled)
            .count()
    }

    pub(super) fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
    ) -> AckResult {
        let Some(entry) = self.entries.get_mut(key) else {
            return AckResult::NotFound;
        };
        if entry.command.agent_id != target.agent_id
            || delivery_attempt == 0
            || delivery_attempt > entry.attempts
        {
            return AckResult::NotFound;
        }
        if entry.acknowledged {
            return AckResult::AlreadyAcknowledged;
        }
        entry.acknowledged = true;
        AckResult::Acknowledged
    }

    /// Retracts a never-delivered command. See `CommandInbox::cancel` for the
    /// full contract.
    pub(super) fn cancel(
        &mut self,
        key: &InboxKey,
        now_millis: u64,
    ) -> Result<CancelResult, CommandError> {
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.cancelled {
                return Ok(CancelResult::AlreadyCancelled);
            }
            if entry.attempts > 0 {
                return Err(CommandError::already_delivered());
            }
            entry.cancelled = true;
            entry.cancelled_at_millis = Some(now_millis);
            return Ok(CancelResult::Cancelled);
        }
        if self.retired.contains_key(key) {
            // `retire` (called only from `maintain`) only ever tombstones an
            // entry that was `acknowledged` or hit the attempt ceiling --
            // both imply at least one delivery -- so a key found here was
            // necessarily delivered before its state was cleaned up.
            return Err(CommandError::already_delivered());
        }
        Ok(CancelResult::NotFound)
    }

    pub(super) fn status(&self, key: &InboxKey, max_attempts: u32) -> Option<(DeliveryStatus, u32)> {
        let entry = self.entries.get(key)?;
        let status = resolve_delivery_status(
            entry.cancelled,
            entry.acknowledged,
            entry.attempts,
            max_attempts,
        );
        Some((status, entry.attempts))
    }

    /// Enumerates stored commands for `ListCommands`, oldest-first by the
    /// sequence assigned at `record` time -- the same identity `order`
    /// already preserves insertion order by, made explicit here so a caller
    /// can resume after the last-seen entry rather than by a position that
    /// shifts under concurrent inserts and retirements.
    ///
    /// Every clause is a server-derived or caller-narrowing predicate, the
    /// same shape `deliverable` already follows: `workspace_id`/
    /// `namespace_id` come from a scope the caller was already authorized
    /// against before this was called (`service.rs`), and `agent_id`/`state`
    /// can only ever narrow the result further.
    pub(super) fn list(&self, query: &ListCommandsQuery<'_>) -> (Vec<CommandSummary>, bool) {
        let mut collected = Vec::with_capacity(query.limit.min(64));
        let mut has_more = false;
        for key in &self.order {
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            if entry.sequence <= query.after_sequence {
                continue;
            }
            if entry.command.workspace_id != query.workspace_id
                || entry.command.namespace_id != query.namespace_id
            {
                continue;
            }
            if let Some(agent_id) = query.agent_id
                && entry.command.agent_id != agent_id
            {
                continue;
            }
            let status = resolve_delivery_status(
                entry.cancelled,
                entry.acknowledged,
                entry.attempts,
                query.max_attempts,
            );
            if let Some(filter) = query.state
                && filter != status
            {
                continue;
            }
            if collected.len() >= query.limit {
                has_more = true;
                break;
            }
            collected.push(CommandSummary {
                command_id: entry.command.command_id.clone(),
                agent_id: entry.command.agent_id.clone(),
                action: entry.command.action.clone(),
                state: status,
                delivery_attempt: entry.attempts,
                issued_at: entry.command.issued_at.clone(),
                sequence: entry.sequence,
            });
        }
        (collected, has_more)
    }

    pub(super) fn retire(&mut self, key: &InboxKey, retired_at_millis: u64) {
        self.entries.remove(key);
        self.retired.insert(key.clone(), retired_at_millis);
    }

    pub(super) fn remove_expired_retired(&mut self, cutoff_millis: u64) -> bool {
        let before = self.retired.len();
        // Collect first, mutate `scope_counts` after: `retired`'s own borrow
        // inside `retain`'s closure must not overlap a mutable borrow of a
        // different field being updated from within it.
        let mut expired_scopes: Vec<(String, String)> = Vec::new();
        self.retired.retain(|key, retired_at| {
            let expired = *retired_at <= cutoff_millis;
            if expired {
                expired_scopes.push((key.workspace_id.clone(), key.namespace_id.clone()));
            }
            !expired
        });
        // The identity is leaving the inbox entirely here (not merely being
        // retired), so this -- not `retire` -- is where its scope's share is
        // freed back up.
        for scope in expired_scopes {
            if let Some(count) = self.scope_counts.get_mut(&scope) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.scope_counts.remove(&scope);
                }
            }
        }
        before != self.retired.len()
    }
}

/// Non-durable inbox for unit tests and embedded use.
#[derive(Debug)]
pub struct InMemoryCommandInbox {
    state: InboxState,
}

impl InMemoryCommandInbox {
    /// `scope_quota` is the same per-`(workspace_id, namespace_id)` ceiling
    /// `FileCommandInbox` and `PostgresCommandInbox` enforce; both are clamped
    /// to at least 1 rather than rejected outright, matching this type's role
    /// as the permissive test/embedding backend -- strict startup validation
    /// (reject zero, reject over capacity) lives on the durable backends'
    /// `Result`-returning constructors instead.
    pub fn new(capacity: usize, scope_quota: usize) -> Self {
        Self {
            state: InboxState::new(capacity.max(1), scope_quota.max(1)),
        }
    }
}

impl Default for InMemoryCommandInbox {
    fn default() -> Self {
        Self::new(DEFAULT_INBOX_CAPACITY, DEFAULT_INBOX_SCOPE_QUOTA)
    }
}

impl CommandInbox for InMemoryCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        self.state.record(command)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        let keys = self.state.deliverable(target, scopes, policy, now_millis);
        Ok(keys
            .iter()
            .filter_map(|key| self.state.mark_delivered(key, now_millis))
            .collect())
    }

    fn undelivered_count(&mut self) -> usize {
        self.state.undelivered_count()
    }

    fn pending_count(&mut self) -> usize {
        self.state.entries.len()
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &InboxKey,
        delivery_attempt: u32,
        _now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        Ok(self.state.acknowledge(target, key, delivery_attempt))
    }

    fn status(
        &mut self,
        key: &InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(DeliveryStatus, u32)>, CommandError> {
        Ok(self.state.status(key, max_attempts))
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        let (commands, has_more) = self.state.list(query);
        Ok(ListCommandsPage { commands, has_more })
    }

    fn cancel(&mut self, key: &InboxKey, now_millis: u64) -> Result<CancelResult, CommandError> {
        self.state.cancel(key, now_millis)
    }
}
