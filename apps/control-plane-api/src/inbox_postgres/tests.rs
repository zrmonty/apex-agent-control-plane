use std::sync::{Arc, Barrier};
use std::thread;

use super::*;
use crate::errors::CommandErrorCode;
use crate::inbox::{CancelResult, DeliveryStatus, ExactScope, InboxKey};

fn url() -> Option<String> {
    std::env::var("APEX_CONTROL_POSTGRES_URL")
        .ok()
        .filter(|value| !value.is_empty())
}

/// Distinguishes test runs against a database that is not dropped between
/// runs, the same reason `event-ingest`'s postgres tests mint unique
/// event ids rather than reusing fixed ones.
fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// A fresh UUIDv7 per call, so repeated runs against a database that
/// retains prior rows (this module never truncates the table) never
/// collide with a previous run's command identity.
fn fresh_command_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

fn command(
    command_id: &str,
    workspace_id: &str,
    namespace_id: &str,
    agent_id: &str,
) -> PendingCommand {
    PendingCommand {
        command_id: command_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        agent_id: agent_id.to_owned(),
        run_id: "run-1".to_owned(),
        trace_id: "trace-1".to_owned(),
        action: "stop".to_owned(),
        reason_code: Some("operator.request".to_owned()),
        parameters: Vec::new(),
        issued_at: "2026-08-08T00:00:00.000000Z".to_owned(),
        delivery_attempt: 0,
    }
}

fn acme_prod() -> ExactScope {
    ExactScope {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
    }
}

#[test]
fn postgres_inbox_connect_rejects_an_invalid_scope_quota() {
    let Some(url) = url() else {
        eprintln!("skip postgres inbox: set APEX_CONTROL_POSTGRES_URL");
        return;
    };
    assert!(
        PostgresCommandInbox::connect(&url, 1_000, 0).is_err(),
        "a zero per-scope quota must be refused, not treated as unlimited"
    );
    assert!(
        PostgresCommandInbox::connect(&url, 1_000, 1_001).is_err(),
        "a per-scope quota wider than the global capacity must be refused"
    );
}

/// The actual regression test for the multi-tenant-fairness finding, at
/// the Postgres backend: one workspace/namespace filling its own
/// per-scope quota must never block a *different* scope from recording.
#[test]
fn postgres_inbox_scope_at_its_quota_never_blocks_a_different_scope() {
    let Some(url) = url() else {
        eprintln!("skip postgres inbox: set APEX_CONTROL_POSTGRES_URL");
        return;
    };
    let mut inbox = PostgresCommandInbox::connect(&url, 100_000, 1).expect("connect");
    let suffix = unique_suffix();
    let scope_a = format!("scope-a-{suffix}");
    let scope_b = format!("scope-b-{suffix}");

    inbox
        .record(&command("cmd-1", &scope_a, "ns", "agent-a"))
        .unwrap();
    let error = inbox
        .record(&command("cmd-2", &scope_a, "ns", "agent-a"))
        .unwrap_err();
    assert_eq!(
        error.code,
        CommandErrorCode::Capacity,
        "scope A must be refused once it is at its own quota"
    );

    assert_eq!(
        inbox
            .record(&command("cmd-3", &scope_b, "ns", "agent-b"))
            .unwrap(),
        RecordResult::Recorded,
        "scope B must not be blocked by scope A's exhausted quota"
    );
}

/// Concurrency regression for the scoped-advisory-lock fix: many
/// concurrent `record()` calls against the SAME scope, each on its own
/// connection, racing the count-check-then-insert window that used to
/// have nothing serialising it under READ COMMITTED. Modelled on
/// `event-ingest`'s
/// `postgres_outbox_pending_is_claimed_not_merely_listed` and this
/// crate's own `concurrent_polls_never_hand_one_command_to_two_callers`:
/// a `Barrier` lines every writer up on its own connection and releases
/// them together, so the race window is actually exercised rather than
/// serialised by accident through connection setup time.
#[test]
fn postgres_inbox_scope_quota_holds_under_concurrent_writers_to_one_scope() {
    let Some(url) = url() else {
        eprintln!("skip postgres inbox: set APEX_CONTROL_POSTGRES_URL");
        return;
    };
    const WRITERS: usize = 12;
    const QUOTA: usize = 5;
    let scope = format!("concurrency-scope-{}", unique_suffix());

    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for index in 0..WRITERS {
        let url = url.clone();
        let scope = scope.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || -> Result<RecordResult, CommandError> {
            let mut inbox =
                PostgresCommandInbox::connect(&url, 100_000, QUOTA).expect("connect");
            let command = command(&format!("cmd-{index}"), &scope, "ns", "agent");
            barrier.wait();
            inbox.record(&command)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("writer thread"))
        .collect();

    let recorded = results
        .iter()
        .filter(|result| matches!(result, Ok(RecordResult::Recorded)))
        .count();
    assert_eq!(
        recorded, QUOTA,
        "the scoped advisory lock must serialise the count-check-then-insert \
         race so exactly {QUOTA} of {WRITERS} concurrent writers to one scope \
         are admitted -- never more, which is exactly the overshoot the \
         unlocked TOCTOU window used to allow"
    );
    for result in &results {
        match result {
            Ok(RecordResult::Recorded) => {}
            Err(error) => assert_eq!(error.code, CommandErrorCode::Capacity),
            Ok(other) => panic!("unexpected result: {other:?}"),
        }
    }
}

#[test]
fn postgres_cancel_of_an_undelivered_command_succeeds_and_it_is_never_polled() {
    let Some(url) = url() else {
        eprintln!("skip postgres inbox: set APEX_CONTROL_POSTGRES_URL");
        return;
    };
    let mut inbox = PostgresCommandInbox::connect(&url, 64, 64).expect("connect");
    let command_id = fresh_command_id();
    inbox
        .record(&command(&command_id, "acme", "prod", "pg-cancel-agent-a"))
        .unwrap();
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id.clone(),
    };
    assert_eq!(inbox.cancel(&key, 1_000).unwrap(), CancelResult::Cancelled);
    // Idempotent: a retried cancellation must not error.
    assert_eq!(
        inbox.cancel(&key, 1_500).unwrap(),
        CancelResult::AlreadyCancelled
    );
    assert_eq!(
        inbox
            .status(&key, crate::inbox::DEFAULT_MAX_DELIVERY_ATTEMPTS)
            .unwrap(),
        Some((DeliveryStatus::Cancelled, 0))
    );

    let target = PollTarget {
        agent_id: "pg-cancel-agent-a".to_owned(),
        limit: crate::inbox::MAX_COMMANDS_PER_POLL,
    };
    let claimed = inbox
        .claim(&target, &acme_prod(), DeliveryPolicy::default(), 2_000)
        .unwrap();
    assert!(
        claimed
            .iter()
            .all(|claimed| claimed.command_id != command_id),
        "a cancelled command must never reach a poll"
    );
}

#[test]
fn postgres_cancel_of_an_already_delivered_command_is_refused() {
    let Some(url) = url() else {
        eprintln!("skip postgres inbox: set APEX_CONTROL_POSTGRES_URL");
        return;
    };
    let mut inbox = PostgresCommandInbox::connect(&url, 64, 64).expect("connect");
    let command_id = fresh_command_id();
    inbox
        .record(&command(&command_id, "acme", "prod", "pg-cancel-agent-b"))
        .unwrap();
    let target = PollTarget {
        agent_id: "pg-cancel-agent-b".to_owned(),
        limit: crate::inbox::MAX_COMMANDS_PER_POLL,
    };
    let delivered = inbox
        .claim(&target, &acme_prod(), DeliveryPolicy::default(), 1_000)
        .unwrap();
    assert!(
        delivered
            .iter()
            .any(|claimed| claimed.command_id == command_id)
    );

    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id.clone(),
    };
    let error = inbox.cancel(&key, 2_000).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::AlreadyDelivered);
    assert_eq!(
        inbox
            .status(&key, crate::inbox::DEFAULT_MAX_DELIVERY_ATTEMPTS)
            .unwrap(),
        Some((DeliveryStatus::Delivered, 1)),
        "a refused cancellation must leave delivery state untouched"
    );
}

#[test]
fn postgres_cancel_of_an_unknown_command_id_is_reported_as_not_found() {
    let Some(url) = url() else {
        eprintln!("skip postgres inbox: set APEX_CONTROL_POSTGRES_URL");
        return;
    };
    let mut inbox = PostgresCommandInbox::connect(&url, 64, 64).expect("connect");
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: fresh_command_id(),
    };
    assert_eq!(inbox.cancel(&key, 1_000).unwrap(), CancelResult::NotFound);
}
