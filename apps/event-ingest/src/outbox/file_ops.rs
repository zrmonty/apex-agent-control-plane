use super::*;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

impl FileOutbox {
    fn compact_journal(&mut self) -> Result<(), GatewayError> {
        let mut records = Vec::with_capacity(self.pending.len() + self.complete.len());
        for (key, event) in &self.pending {
            records.push(FileOutboxRecord::Pending {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope: event.envelope.clone(),
                next_attempt_at_millis: self.next_attempt_at_millis.get(key).copied(),
                attempts: self.attempts.get(key).copied(),
            });
        }
        for (key, fingerprint) in &self.complete {
            records.push(FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope_sha256: fingerprint.map(hex_fingerprint),
                completed_at_millis: self.completed_at_millis.get(key).copied(),
                envelope: self
                    .complete_events
                    .get(key)
                    .map(|event| event.envelope.clone()),
            });
        }
        for (key, event) in &self.quarantined {
            records.push(FileOutboxRecord::Quarantined {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope: event.envelope.clone(),
                reason: "replay_attempts_exhausted".to_owned(),
                quarantined_at_millis: now_millis(),
            });
        }
        let mut encoded = Vec::new();
        for record in records {
            let mut bytes = serde_json::to_vec(&record)
                .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))?;
            bytes.push(b'\n');
            encoded.extend_from_slice(&bytes);
        }
        if encoded.len() as u64 > MAX_OUTBOX_FILE_BYTES {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(GatewayError::invalid_outbox_configuration)?;
        let temp_path = self.path.with_file_name(format!(
            ".{name}.compact-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal))?;
        let result = temp
            .write_all(&encoded)
            .and_then(|_| temp.sync_data())
            .map_err(|_| GatewayError::new(crate::GatewayErrorCode::Internal));
        if result.is_err() {
            drop(temp);
            let _ = fs::remove_file(&temp_path);
            return result;
        }
        drop(temp);
        drop(
            self.file
                .take()
                .ok_or_else(GatewayError::invalid_outbox_configuration)?,
        );
        if fs::rename(&temp_path, &self.path).is_err() {
            let _ = fs::remove_file(&temp_path);
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(&self.path)
                    .map_err(|_| GatewayError::invalid_outbox_configuration())?,
            );
            return Err(GatewayError::new(crate::GatewayErrorCode::Internal));
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)
                .map_err(|_| GatewayError::invalid_outbox_configuration())?,
        );
        Ok(())
    }
}

impl EventOutbox for FileOutbox {
    fn enqueue(&mut self, event: &IngestRequest) -> Result<EnqueueResult, GatewayError> {
        let key = OutboxKey {
            workspace_id: event.workspace_id.clone(),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
        };
        if let Some(fingerprint) = self.complete.get(&key) {
            return match fingerprint {
                Some(stored) if *stored == payload_fingerprint(&event.envelope) => {
                    Ok(EnqueueResult::AlreadyComplete)
                }
                Some(_) => Err(GatewayError::idempotency_conflict()),
                // Legacy record with no journalled content: a conflict cannot
                // be proven, so preserve the historical accept-as-done result.
                None => Ok(EnqueueResult::AlreadyComplete),
            };
        }
        if let Some(existing) = self.quarantined.get(&key) {
            if existing.envelope == event.envelope {
                return Ok(EnqueueResult::AlreadyPending);
            }
            return Err(GatewayError::idempotency_conflict());
        }
        if let Some(existing) = self.pending.get(&key) {
            if existing.envelope == event.envelope {
                return Ok(EnqueueResult::AlreadyPending);
            }
            return Err(GatewayError::idempotency_conflict());
        }
        if self.pending.len() + self.complete.len() + self.quarantined.len() >= self.capacity {
            return Err(GatewayError::new(
                crate::GatewayErrorCode::IdempotencyCapacity,
            ));
        }
        self.append(&FileOutboxRecord::Pending {
            workspace_id: key.workspace_id.clone(),
            namespace_id: key.namespace_id.clone(),
            event_id: key.event_id.clone(),
            envelope: event.envelope.clone(),
            next_attempt_at_millis: None,
            attempts: None,
        })?;
        self.pending.insert(key, event.clone());
        Ok(EnqueueResult::Enqueued)
    }

    fn mark_complete(&mut self, key: &OutboxKey) -> Result<(), GatewayError> {
        if !self.pending.contains_key(key) && !self.complete.contains_key(key) {
            return Err(GatewayError::internal());
        }
        if !self.complete.contains_key(key) {
            let fingerprint = self
                .pending
                .get(key)
                .map(|event| payload_fingerprint(&event.envelope));
            let event = self.pending.get(key).cloned();
            let completed_at_millis = now_millis();
            self.append(&FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope_sha256: fingerprint.map(hex_fingerprint),
                completed_at_millis: Some(completed_at_millis),
                envelope: event.as_ref().map(|event| event.envelope.clone()),
            })?;
            self.pending.remove(key);
            self.complete.insert(key.clone(), fingerprint);
            if let Some(event) = event {
                self.complete_events.insert(key.clone(), event);
            }
            self.completed_at_millis
                .insert(key.clone(), completed_at_millis);
            self.next_attempt_at_millis.remove(key);
            self.attempts.remove(key);
        }
        Ok(())
    }

    fn mark_complete_many(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        let mut records = Vec::new();
        let mut completed = Vec::new();
        for key in keys {
            if self.complete.contains_key(key) {
                continue;
            }
            let Some(event) = self.pending.get(key).cloned() else {
                return Err(GatewayError::internal());
            };
            let completed_at_millis = now_millis();
            records.push(FileOutboxRecord::Complete {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope_sha256: Some(hex_fingerprint(payload_fingerprint(&event.envelope))),
                completed_at_millis: Some(completed_at_millis),
                envelope: Some(event.envelope.clone()),
            });
            completed.push((key.clone(), event, completed_at_millis));
        }
        self.append_batch(&records)?;
        for (key, event, completed_at_millis) in completed {
            self.pending.remove(&key);
            let fingerprint = payload_fingerprint(&event.envelope);
            self.complete.insert(key.clone(), Some(fingerprint));
            self.complete_events.insert(key.clone(), event);
            self.completed_at_millis
                .insert(key.clone(), completed_at_millis);
            self.next_attempt_at_millis.remove(&key);
            self.attempts.remove(&key);
        }
        Ok(())
    }

    fn pending(&mut self) -> Vec<IngestRequest> {
        self.pending.values().cloned().collect()
    }

    fn pending_batch(&mut self, limit: usize) -> Result<Vec<IngestRequest>, GatewayError> {
        let now = now_millis();
        Ok(self
            .pending
            .iter()
            .filter(|(key, _)| self.next_attempt_at_millis.get(key).copied().unwrap_or(0) <= now)
            .take(limit)
            .map(|(_, event)| event.clone())
            .collect())
    }

    fn pending_count(&mut self) -> Result<u64, GatewayError> {
        Ok(self.pending.len() as u64)
    }

    fn recent_completed_batch(
        &mut self,
        since_millis: u64,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        Ok(self
            .completed_at_millis
            .iter()
            .filter(|(_, completed_at)| **completed_at >= since_millis)
            .filter_map(|(key, _)| self.complete_events.get(key).cloned())
            .take(limit)
            .collect())
    }

    fn pending_reconciliation_batch(
        &mut self,
        limit: usize,
    ) -> Result<Vec<IngestRequest>, GatewayError> {
        Ok(self.pending.values().take(limit).cloned().collect())
    }

    fn reschedule(
        &mut self,
        keys: &[OutboxKey],
        after: std::time::Duration,
    ) -> Result<(), GatewayError> {
        let now = now_millis();
        let next = now.saturating_add(after.as_millis().min(u128::from(u64::MAX)) as u64);
        let mut records = Vec::new();
        let mut quarantine_keys = Vec::new();
        for key in keys {
            let Some(event) = self.pending.get(key).cloned() else {
                continue;
            };
            let attempts = self
                .attempts
                .get(key)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            if attempts >= MAX_PERSISTED_ATTEMPTS {
                quarantine_keys.push(key.clone());
                continue;
            }
            self.next_attempt_at_millis.insert(key.clone(), next);
            self.attempts.insert(key.clone(), attempts);
            records.push(FileOutboxRecord::Pending {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope: event.envelope,
                next_attempt_at_millis: Some(next),
                attempts: Some(attempts),
            });
        }
        for key in &quarantine_keys {
            if let Some(event) = self.pending.get(key) {
                records.push(FileOutboxRecord::Quarantined {
                    workspace_id: key.workspace_id.clone(),
                    namespace_id: key.namespace_id.clone(),
                    event_id: key.event_id.clone(),
                    envelope: event.envelope.clone(),
                    reason: "replay_attempts_exhausted".to_owned(),
                    quarantined_at_millis: now,
                });
            }
        }
        self.append_batch(&records)?;
        for key in quarantine_keys {
            if let Some(event) = self.pending.remove(&key) {
                self.next_attempt_at_millis.remove(&key);
                self.attempts.remove(&key);
                self.quarantined.insert(key, event);
            }
        }
        Ok(())
    }

    fn quarantine(&mut self, keys: &[OutboxKey], reason: &'static str) -> Result<(), GatewayError> {
        let now = now_millis();
        let mut records = Vec::new();
        for key in keys {
            let Some(event) = self.pending.get(key).cloned() else {
                continue;
            };
            records.push(FileOutboxRecord::Quarantined {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope: event.envelope.clone(),
                reason: reason.to_owned(),
                quarantined_at_millis: now,
            });
        }
        self.append_batch(&records)?;
        for key in keys {
            if let Some(event) = self.pending.remove(key) {
                self.next_attempt_at_millis.remove(key);
                self.attempts.remove(key);
                self.quarantined.insert(key.clone(), event);
            }
        }
        Ok(())
    }

    fn quarantined_batch(&mut self, limit: usize) -> Result<Vec<OutboxKey>, GatewayError> {
        Ok(self.quarantined.keys().take(limit).cloned().collect())
    }

    fn quarantined_count(&mut self) -> Result<u64, GatewayError> {
        Ok(self.quarantined.len() as u64)
    }

    fn requeue_quarantined(&mut self, keys: &[OutboxKey]) -> Result<(), GatewayError> {
        let mut records = Vec::new();
        for key in keys {
            let Some(event) = self.quarantined.get(key) else {
                continue;
            };
            records.push(FileOutboxRecord::Pending {
                workspace_id: key.workspace_id.clone(),
                namespace_id: key.namespace_id.clone(),
                event_id: key.event_id.clone(),
                envelope: event.envelope.clone(),
                next_attempt_at_millis: None,
                attempts: None,
            });
        }
        self.append_batch(&records)?;
        for key in keys {
            if let Some(event) = self.quarantined.remove(key) {
                self.pending.insert(key.clone(), event);
            }
        }
        Ok(())
    }

    fn maintain(&mut self, now_millis: u64, retention_millis: u64) -> Result<(), GatewayError> {
        let cutoff = now_millis.saturating_sub(retention_millis);
        let previous_complete = self.complete.clone();
        let previous_complete_events = self.complete_events.clone();
        let previous_completed_at = self.completed_at_millis.clone();
        let expired: Vec<_> = self
            .completed_at_millis
            .iter()
            .filter_map(|(key, completed_at)| (*completed_at <= cutoff).then_some(key.clone()))
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        for key in &expired {
            self.complete.remove(key);
            self.complete_events.remove(key);
            self.completed_at_millis.remove(key);
        }
        if let Err(error) = self.compact_journal() {
            self.complete = previous_complete;
            self.complete_events = previous_complete_events;
            self.completed_at_millis = previous_completed_at;
            return Err(error);
        }
        Ok(())
    }
}
