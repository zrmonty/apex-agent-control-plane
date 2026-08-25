use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use super::state::InboxState;
use super::*;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum InboxRecord {
    Command(PendingCommand),
    Delivered {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        attempt: u32,
        at_millis: u64,
    },
    Acknowledged {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        at_millis: u64,
    },
    Retired {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        retired_at_millis: u64,
    },
    /// Durable record of an operator cancellation. Its timestamp is the
    /// retention clock because a cancelled command has never been delivered.
    Cancelled {
        workspace_id: String,
        namespace_id: String,
        command_id: String,
        at_millis: u64,
    },
}

/// Append-only, fsync-backed delivery journal.
///
/// Deliberately the same shape and the same disciplines as
/// `apex_event_ingest::FileOutbox`: confined beneath an operator-owned base
/// directory, symlinks refused, bounded record and file sizes, an exclusive
/// writer lock held for the process lifetime, and a startup replay that fails
/// closed on malformed data rather than silently dropping a pending command.
#[derive(Debug)]
pub struct FileCommandInbox {
    file: Option<File>,
    path: std::path::PathBuf,
    // Held for the process lifetime: file journals are single-writer only.
    _writer_lock: File,
    state: InboxState,
    delivery_records_since_compaction: usize,
}

impl FileCommandInbox {
    pub fn open(
        path: &Path,
        base: &Path,
        capacity: usize,
        scope_quota: usize,
    ) -> Result<Self, CommandError> {
        if capacity == 0 || capacity > DEFAULT_INBOX_CAPACITY {
            return Err(configuration_error());
        }
        // Same fail-loud discipline as `capacity` immediately above: a
        // misconfigured per-scope quota (zero, or wider than the global
        // ceiling it is supposed to sit inside of) is a startup error, not a
        // value to silently clamp.
        if scope_quota == 0 || scope_quota > capacity {
            return Err(configuration_error());
        }
        let canonical_base = base.canonicalize().map_err(|_| configuration_error())?;
        let parent = path.parent().ok_or_else(configuration_error)?;
        let canonical_parent = parent.canonicalize().map_err(|_| configuration_error())?;
        if !canonical_parent.starts_with(&canonical_base)
            || path.file_name().is_none()
            || (path.exists() && path.is_symlink())
        {
            return Err(configuration_error());
        }
        if path.exists() {
            let metadata = fs::metadata(path).map_err(|_| configuration_error())?;
            if !metadata.is_file() || metadata.len() > MAX_INBOX_FILE_BYTES {
                return Err(configuration_error());
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|_| configuration_error())?;
        let lock_path = path.with_extension(format!(
            "{}.lock",
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or("journal")
        ));
        let writer_lock = OpenOptions::new()
            .create(true)
            // The lock file's content is never read; only its exclusive-lock
            // state is meaningful. `truncate(false)` keeps any existing bytes
            // rather than discarding them on reopen -- the same lint fix
            // `FileOutbox` already carries.
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| configuration_error())?;
        fs2::FileExt::try_lock_exclusive(&writer_lock).map_err(|_| configuration_error())?;
        let mut inbox = Self {
            file: Some(file),
            path: path.to_owned(),
            _writer_lock: writer_lock,
            state: InboxState::new(capacity, scope_quota),
            delivery_records_since_compaction: 0,
        };
        inbox.load()?;
        Ok(inbox)
    }

    fn load(&mut self) -> Result<(), CommandError> {
        let reader = BufReader::new(
            self.file
                .as_ref()
                .ok_or_else(configuration_error)?
                .try_clone()
                .map_err(|_| configuration_error())?,
        );
        for line in reader.lines() {
            let line = line.map_err(|_| configuration_error())?;
            if line.len() > MAX_INBOX_RECORD_BYTES {
                return Err(configuration_error());
            }
            let record: InboxRecord =
                serde_json::from_str(&line).map_err(|_| configuration_error())?;
            match record {
                InboxRecord::Command(command) => {
                    // A replayed record is re-validated rather than trusted:
                    // the journal lives on a mounted volume, and a command
                    // whose target identifiers do not satisfy the same grammar
                    // the accept path enforced could otherwise be introduced
                    // by editing a file.
                    if !is_recordable(&command) {
                        return Err(configuration_error());
                    }
                    self.state.record(&command)?;
                }
                InboxRecord::Delivered {
                    workspace_id,
                    namespace_id,
                    command_id,
                    attempt,
                    at_millis,
                } => {
                    self.state.apply_delivery(
                        &InboxKey {
                            workspace_id,
                            namespace_id,
                            command_id,
                        },
                        attempt,
                        at_millis,
                    );
                }
                InboxRecord::Acknowledged {
                    workspace_id,
                    namespace_id,
                    command_id,
                    ..
                } => {
                    if let Some(entry) = self.state.entries.get_mut(&InboxKey {
                        workspace_id,
                        namespace_id,
                        command_id,
                    }) {
                        entry.acknowledged = true;
                    }
                }
                InboxRecord::Retired {
                    workspace_id,
                    namespace_id,
                    command_id,
                    retired_at_millis,
                } => {
                    self.state.retire(
                        &InboxKey {
                            workspace_id,
                            namespace_id,
                            command_id,
                        },
                        retired_at_millis,
                    );
                }
                InboxRecord::Cancelled {
                    workspace_id,
                    namespace_id,
                    command_id,
                    at_millis,
                } => {
                    if let Some(entry) = self.state.entries.get_mut(&InboxKey {
                        workspace_id,
                        namespace_id,
                        command_id,
                    }) {
                        entry.cancelled = true;
                        entry.cancelled_at_millis = Some(at_millis);
                    }
                }
            }
        }
        Ok(())
    }

    fn append(&mut self, record: &InboxRecord) -> Result<(), CommandError> {
        self.append_batch(std::slice::from_ref(record))
    }

    fn encode_records(records: &[InboxRecord]) -> Result<Vec<u8>, CommandError> {
        let mut encoded = Vec::new();
        for record in records {
            let mut record_bytes =
                serde_json::to_vec(record).map_err(|_| CommandError::internal())?;
            record_bytes.push(b'\n');
            if record_bytes.len() > MAX_INBOX_RECORD_BYTES {
                return Err(CommandError::new(
                    CommandErrorCode::Capacity,
                    "The durable command inbox is at capacity. Retry after operator remediation.",
                ));
            }
            encoded.extend_from_slice(&record_bytes);
        }
        if encoded.len() as u64 > MAX_INBOX_FILE_BYTES {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        Ok(encoded)
    }

    /// Append a group of journal records with one durability barrier.
    ///
    /// A poll claims several commands at once. Fsyncing after every delivery
    /// record made the file backend's latency scale with the poll size even
    /// though the records are one atomic claim from the caller's perspective.
    /// The state is still mutated only after the complete batch is durable.
    fn append_batch(&mut self, records: &[InboxRecord]) -> Result<(), CommandError> {
        if records.is_empty() {
            return Ok(());
        }
        let encoded = Self::encode_records(records)?;
        let current = self
            .file
            .as_ref()
            .ok_or_else(configuration_error)?
            .metadata()
            .map_err(|_| configuration_error())?
            .len();
        if current.saturating_add(encoded.len() as u64) > MAX_INBOX_FILE_BYTES {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }
        self.file
            .as_mut()
            .ok_or_else(configuration_error)?
            .write_all(&encoded)
            .and_then(|_| {
                self.file
                    .as_ref()
                    .ok_or(std::io::Error::other("inbox journal is closed"))?
                    .sync_data()
            })
            .map_err(|_| CommandError::internal())
    }

    fn snapshot_records(&self) -> Vec<InboxRecord> {
        let mut records = Vec::with_capacity(self.state.entries.len() * 2);
        for key in &self.state.order {
            let Some(entry) = self.state.entries.get(key) else {
                continue;
            };
            records.push(InboxRecord::Command(entry.command.clone()));
            if entry.attempts > 0 {
                records.push(InboxRecord::Delivered {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    attempt: entry.attempts,
                    at_millis: entry.last_delivered_millis.unwrap_or_default(),
                });
            }
            if entry.acknowledged {
                records.push(InboxRecord::Acknowledged {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    at_millis: entry.last_delivered_millis.unwrap_or_default(),
                });
            }
            if entry.cancelled {
                // A cancelled entry is always undelivered (`attempts == 0`),
                // so its own terminal timestamp is the retention clock.
                records.push(InboxRecord::Cancelled {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    at_millis: entry.cancelled_at_millis.unwrap_or_default(),
                });
            }
        }
        for (key, retired_at_millis) in &self.state.retired {
            records.push(InboxRecord::Retired {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                command_id: key.command_id.clone(),
                retired_at_millis: *retired_at_millis,
            });
        }
        records
    }

    /// Rewrites the journal to one command record plus the latest delivery
    /// record per command. The snapshot is fully durable before the old file
    /// is replaced, and the writer lock remains held throughout the swap.
    pub(super) fn compact(&mut self) -> Result<(), CommandError> {
        let encoded = Self::encode_records(&self.snapshot_records())?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(configuration_error)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| configuration_error())?
            .as_nanos();
        let temp_path = self.path.with_file_name(format!(
            ".{file_name}.compact-{}-{nonce}",
            std::process::id()
        ));
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|_| CommandError::internal())?;
        let result = temp
            .write_all(&encoded)
            .and_then(|_| temp.sync_data())
            .map_err(|_| CommandError::internal());
        if result.is_err() {
            drop(temp);
            let _ = fs::remove_file(&temp_path);
            return result;
        }
        drop(temp);

        // Closing the old handle is required on Windows before rename can
        // replace the journal path. The replacement is already durable, so a
        // failure here can reopen the original and leave it authoritative.
        let old = self.file.take().ok_or_else(configuration_error)?;
        drop(old);
        if let Err(error) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(&self.path)
                    .map_err(|_| configuration_error())?,
            );
            let _ = error;
            return Err(CommandError::internal());
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)
                .map_err(|_| configuration_error())?,
        );
        self.state
            .order
            .retain(|key| self.state.entries.contains_key(key));
        // Directory fsync is not supported uniformly on Windows; the file
        // snapshot and rename are still durable enough for the next replay.
        self.delivery_records_since_compaction = 0;
        Ok(())
    }

    fn compact_if_needed(&mut self) {
        let Ok(size) = self
            .file
            .as_ref()
            .ok_or_else(configuration_error)
            .and_then(|file| file.metadata().map_err(|_| configuration_error()))
            .map(|metadata| metadata.len())
        else {
            return;
        };
        if size < INBOX_COMPACTION_THRESHOLD_BYTES
            || self.delivery_records_since_compaction < INBOX_COMPACTION_DELIVERY_RECORDS
        {
            return;
        }
        let _ = self.compact();
    }
}

impl CommandInbox for FileCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        if !is_recordable(command) {
            return Err(CommandError::new(
                CommandErrorCode::InvalidCommand,
                "The command was malformed: check target identifiers, action, and required parameters for the requested action.",
            ));
        }
        // Checked before the journal write, not after: a command this inbox
        // is about to refuse (a duplicate, or one over the global/per-scope
        // capacity) must never reach the journal at all. See
        // `InboxState::check_recordable` for why -- a phantom journal entry
        // for a refused command could otherwise poison every future replay.
        let Some(result) = self.state.check_recordable(command)? else {
            // Journal first, then mutate memory: a crash between the two
            // leaves a record that replays into the same state, never a
            // delivery the journal cannot account for. Safe to journal
            // unconditionally from here: `check_recordable` just confirmed
            // `insert_recorded` cannot fail.
            self.append(&InboxRecord::Command(command.clone()))?;
            self.state.insert_recorded(command);
            return Ok(RecordResult::Recorded);
        };
        Ok(result)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        let keys = self.state.deliverable(target, scopes, policy, now_millis);

        let records: Vec<_> = keys
            .iter()
            .map(|key| {
                let attempt = self
                    .state
                    .entries
                    .get(key)
                    .map_or(0, |entry| entry.attempts)
                    .saturating_add(1);
                InboxRecord::Delivered {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    command_id: key.command_id.clone(),
                    attempt,
                    at_millis: now_millis,
                }
            })
            .collect();

        // Durable *before* any command is handed back. One sync for the poll
        // keeps the same crash semantics while avoiding one fsync per command.
        self.append_batch(&records)?;

        let mut delivered = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(command) = self.state.mark_delivered(&key, now_millis) {
                delivered.push(command);
            }
        }
        self.delivery_records_since_compaction = self
            .delivery_records_since_compaction
            .saturating_add(records.len());
        self.compact_if_needed();
        Ok(delivered)
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
        now_millis: u64,
    ) -> Result<AckResult, CommandError> {
        let result = self.state.acknowledge(target, key, delivery_attempt);
        if matches!(result, AckResult::Acknowledged)
            && let Err(error) = self.append(&InboxRecord::Acknowledged {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                command_id: key.command_id.clone(),
                at_millis: now_millis,
            })
        {
            if let Some(entry) = self.state.entries.get_mut(key) {
                entry.acknowledged = false;
            }
            return Err(error);
        }
        Ok(result)
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
        let result = self.state.cancel(key, now_millis)?;
        // Journal after the in-memory mutation, mirroring `acknowledge`: if
        // the append fails, the in-memory flag is rolled back so the two
        // never disagree about whether this command is cancelled.
        if matches!(result, CancelResult::Cancelled)
            && let Err(error) = self.append(&InboxRecord::Cancelled {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                command_id: key.command_id.clone(),
                at_millis: now_millis,
            })
        {
            if let Some(entry) = self.state.entries.get_mut(key) {
                entry.cancelled = false;
                entry.cancelled_at_millis = None;
            }
            return Err(error);
        }
        Ok(result)
    }

    fn maintain(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
        max_attempts: u32,
    ) -> Result<(), CommandError> {
        let cutoff_millis = now_millis.saturating_sub(retention_millis);
        let previous = self.state.clone();
        let settled: Vec<(InboxKey, u64)> = self
            .state
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                if entry.cancelled {
                    return entry
                        .cancelled_at_millis
                        .filter(|cancelled_at| *cancelled_at <= cutoff_millis)
                        .map(|cancelled_at| (key.clone(), cancelled_at));
                }
                ((entry.acknowledged || entry.attempts >= max_attempts)
                    && entry
                        .last_delivered_millis
                        .is_some_and(|delivered_at| delivered_at <= cutoff_millis))
                .then_some((key.clone(), now_millis))
            })
            .collect();
        for (key, retired_at_millis) in &settled {
            self.state.retire(key, *retired_at_millis);
        }
        // Do not short-circuit this expression: a command can become
        // settled and already be past retention in the same sweep (notably a
        // cancellation), so the tombstone cleanup must still run now.
        let expired_retired = self.state.remove_expired_retired(cutoff_millis);
        let changed = !settled.is_empty() || expired_retired;
        if !changed {
            return Ok(());
        }
        if let Err(error) = self.compact() {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }
}
