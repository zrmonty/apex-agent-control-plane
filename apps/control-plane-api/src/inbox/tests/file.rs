//! `FileCommandInbox` tests: the durable journal plus replay on top of the
//! shared in-memory decision logic (see `super::state`).

use std::time::Duration;

use crate::errors::CommandErrorCode;
use crate::inbox::*;

use super::support::*;

/// Settlement frees a scope's share back up: once a command's tombstone
/// expires past the retention window, the identity leaves the inbox
/// entirely and the scope is no longer counted against its quota.
#[test]
fn expiring_a_retired_command_frees_its_scope_quota() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-scope-quota-retire-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    let policy = DeliveryPolicy {
        redelivery_after: Duration::ZERO,
        max_attempts: 1,
    };
    let mut inbox = FileCommandInbox::open(&path, &dir, 16, 1).unwrap();
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    assert_eq!(
        inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 1)
            .unwrap()
            .len(),
        1
    );
    let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::Capacity);

    // Settle and expire the tombstone.
    inbox.maintain(1_000, 100, 1).unwrap();
    inbox.maintain(2_000, 100, 1).unwrap();

    assert_eq!(
        inbox.record(&command("cmd-2", "agent-a")).unwrap(),
        RecordResult::Recorded,
        "once the settled command's identity fully expires, its scope's \
         quota must be freed for a new command"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression test for a command that is *refused* -- for global capacity
/// or, as exercised here, per-scope quota -- never reaching the journal.
///
/// Before this was fixed, `FileCommandInbox::record` journaled every
/// command before checking whether it could actually be admitted, so a
/// rejected command still left a durable `Command` entry behind. Replay
/// re-runs the same admission check against every journaled `Command`,
/// and fails closed (propagates the error rather than silently dropping
/// the entry) on a check that does not pass -- so a single
/// rejected-for-quota write could poison every future restart: the
/// gateway would fail to come back up at all until an operator
/// hand-edited the journal file to remove the phantom line. This test
/// proves the fix by actually restarting the inbox from disk after a
/// rejection, which is the exact step that used to be able to fail.
#[test]
fn a_command_refused_for_scope_quota_is_never_journaled_and_does_not_poison_replay() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-refused-not-journaled-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 1).unwrap();
        assert_eq!(
            inbox.record(&command("cmd-1", "agent-a")).unwrap(),
            RecordResult::Recorded
        );
        let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
        assert_eq!(
            error.code,
            CommandErrorCode::Capacity,
            "the second command must be refused: the scope is already at its quota of 1"
        );
    }
    // The regression: reopening (replaying the journal from a cold start,
    // exactly what a restarted gateway does) must succeed, and must see
    // only the one command that was actually admitted. If `cmd-2` had
    // been journaled despite being refused, replay would hit the same
    // over-quota check on it -- still failing, since nothing freed the
    // scope's one slot in between -- and this `unwrap()` would panic
    // instead of the gateway ever coming back up.
    let mut reopened = FileCommandInbox::open(&path, &dir, 64, 1)
        .expect("a rejected command must never leave a journal entry that fails replay");
    assert_eq!(
        reopened.pending_count(),
        1,
        "only the admitted command should have survived the restart"
    );
    // The scope is still at its quota after restart -- state.record()
    // recomputes quota from what actually replayed, not from anything
    // the rejected write might have left behind -- so a third command in
    // the same scope is refused exactly as it was before the restart.
    let error = reopened.record(&command("cmd-3", "agent-a")).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::Capacity);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_inbox_open_rejects_an_invalid_scope_quota() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-scope-quota-cfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(
        FileCommandInbox::open(&dir.join("zero.jsonl"), &dir, 64, 0).is_err(),
        "a zero per-scope quota must be refused, not treated as unlimited"
    );
    assert!(
        FileCommandInbox::open(&dir.join("over.jsonl"), &dir, 64, 65).is_err(),
        "a per-scope quota wider than the global capacity must be refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_inbox_survives_a_restart_with_its_delivery_state_intact() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        inbox.record(&command("cmd-2", "agent-a")).unwrap();
        let claimed = inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                10_000,
            )
            .unwrap();
        assert_eq!(claimed.len(), 2);
    }
    {
        // Reopened: both commands are known and both are inside the
        // redelivery window, so a restarted gateway does not immediately
        // re-serve a command the agent already has.
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        assert_eq!(inbox.undelivered_count(), 0);
        assert!(
            inbox
                .claim(
                    &target("agent-a"),
                    &acme_prod(),
                    DeliveryPolicy::default(),
                    12_000
                )
                .unwrap()
                .is_empty()
        );
        // ... and past the window they come back, attempt count preserved.
        let again = inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                41_000,
            )
            .unwrap();
        assert_eq!(again.len(), 2);
        assert!(again.iter().all(|command| command.delivery_attempt == 2));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_inbox_persists_an_acknowledgement_across_restart() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-ack-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-ack".to_owned(),
    };
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        inbox.record(&command("cmd-ack", "agent-a")).unwrap();
        inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                10_000,
            )
            .unwrap();
        assert_eq!(
            inbox
                .acknowledge(&target("agent-a"), &key, 1, 11_000)
                .unwrap(),
            AckResult::Acknowledged
        );
    }
    let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
    assert_eq!(
        reopened.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS),
        Ok(Some((DeliveryStatus::Acknowledged, 1)))
    );
    assert!(
        reopened
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                41_000
            )
            .unwrap()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mirrors `file_inbox_persists_an_acknowledgement_across_restart`: a
/// cancellation is journaled the same way an acknowledgement is, so a
/// query for the command's status after a restart must still say
/// `Cancelled` rather than falling back to "not found" -- which would be
/// indistinguishable from a command_id that was never issued at all, a
/// real audit-trail regression for a security-relevant control plane.
#[test]
fn file_inbox_persists_a_cancellation_across_restart() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-cancel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-cancel".to_owned(),
    };
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        inbox.record(&command("cmd-cancel", "agent-a")).unwrap();
        assert_eq!(inbox.cancel(&key, 5_000).unwrap(), CancelResult::Cancelled);
    }
    let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
    assert_eq!(
        reopened.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS),
        Ok(Some((DeliveryStatus::Cancelled, 0))),
        "a cancelled command's status must survive a restart, not silently become \
         indistinguishable from a command_id that was never issued"
    );
    // Still never deliverable after the restart.
    assert!(
        reopened
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                6_000
            )
            .unwrap()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The refusal path (not just the success path) has to hold for the file
/// backend too: a command already delivered once must never be
/// cancellable, and the journal must show no `Cancelled` record for it --
/// which this proves by reopening and checking `Delivered` survives.
#[test]
fn file_inbox_refuses_to_cancel_an_already_delivered_command() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-cancel-refused-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-cancel-refused".to_owned(),
    };
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        inbox
            .record(&command("cmd-cancel-refused", "agent-a"))
            .unwrap();
        let delivered = inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                1_000,
            )
            .unwrap();
        assert_eq!(delivered.len(), 1);
        let error = inbox.cancel(&key, 2_000).unwrap_err();
        assert_eq!(error.code, CommandErrorCode::AlreadyDelivered);
    }
    let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
    assert_eq!(
        reopened.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS),
        Ok(Some((DeliveryStatus::Delivered, 1))),
        "a refused cancellation must not have journaled anything"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_inbox_compaction_preserves_latest_delivery_state() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-compact-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    let policy = DeliveryPolicy {
        redelivery_after: Duration::ZERO,
        max_attempts: 8,
    };
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        for attempt in 0..8 {
            assert_eq!(
                inbox
                    .claim(&target("agent-a"), &acme_prod(), policy, attempt)
                    .unwrap()
                    .len(),
                1
            );
        }
        let before = std::fs::metadata(&path).unwrap().len();
        inbox.compact().unwrap();
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(after < before, "compaction must shrink repeated deliveries");
    }
    let mut reopened = FileCommandInbox::open(&path, &dir, 64, 64).unwrap();
    assert_eq!(reopened.undelivered_count(), 0);
    assert!(
        reopened
            .claim(&target("agent-a"), &acme_prod(), policy, 1_000)
            .unwrap()
            .is_empty(),
        "compaction must preserve the settled attempt ceiling"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_inbox_retention_preserves_then_expires_command_idempotency() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-retention-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("inbox.jsonl");
    let policy = DeliveryPolicy {
        redelivery_after: Duration::ZERO,
        max_attempts: 1,
    };
    {
        let mut inbox = FileCommandInbox::open(&path, &dir, 2, 2).unwrap();
        inbox.record(&command("cmd-1", "agent-a")).unwrap();
        assert_eq!(
            inbox
                .claim(&target("agent-a"), &acme_prod(), policy, 1)
                .unwrap()
                .len(),
            1
        );

        // Settlement removes the payload but retains the identity, so a
        // duplicate submission during the retention window is still a no-op.
        inbox.maintain(1_000, 100, 1).unwrap();
    }
    let mut inbox = FileCommandInbox::open(&path, &dir, 2, 2).unwrap();
    assert_eq!(
        inbox.record(&command("cmd-1", "agent-a")).unwrap(),
        RecordResult::AlreadyRecorded
    );

    // Once the tombstone itself expires, the identity can be reused and
    // is treated as a new command delivery.
    inbox.maintain(2_000, 100, 1).unwrap();
    assert_eq!(
        inbox.record(&command("cmd-1", "agent-a")).unwrap(),
        RecordResult::Recorded
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_inbox_refuses_a_path_outside_its_base() {
    let dir = std::env::temp_dir().join(format!("apex-inbox-base-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let outside = std::env::temp_dir().join("apex-inbox-escape.jsonl");
    assert!(FileCommandInbox::open(&outside, &dir, 64, 64).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_command_with_an_out_of_grammar_identifier_is_refused() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-grammar-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut inbox = FileCommandInbox::open(&dir.join("inbox.jsonl"), &dir, 64, 64).unwrap();
    let mut bad = command("cmd-1", "agent a");
    bad.action = "stop".to_owned();
    assert!(inbox.record(&bad).is_err());
    let mut bad_action = command("cmd-2", "agent-a");
    bad_action.action = "self_destruct".to_owned();
    assert!(inbox.record(&bad_action).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `resolve_hold` is the sixth cooperative action, added on top of the
/// same delivery mechanism `stop`/`pause`/`resume`/`inject`/`set_budget`
/// already use. `is_recordable` (exercised here through
/// `FileCommandInbox::record`, the only backend that enforces it) must
/// accept it exactly like the other five, and a poll must deliver it like
/// any other pending command.
#[test]
fn a_resolve_hold_command_is_recordable_and_deliverable() {
    let dir = std::env::temp_dir().join(format!(
        "apex-inbox-resolve-hold-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut inbox = FileCommandInbox::open(&dir.join("inbox.jsonl"), &dir, 64, 64).unwrap();
    let mut resolve = command("cmd-resolve-1", "agent-a");
    resolve.action = "resolve_hold".to_owned();
    assert_eq!(
        inbox.record(&resolve).unwrap(),
        RecordResult::Recorded,
        "a well-formed resolve_hold command must be recordable like any other action"
    );
    let delivered = inbox
        .claim(&target("agent-a"), &acme_prod(), DeliveryPolicy::default(), 1_000)
        .unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].command_id, "cmd-resolve-1");
    assert_eq!(delivered[0].action, "resolve_hold");
    let _ = std::fs::remove_dir_all(&dir);
}
