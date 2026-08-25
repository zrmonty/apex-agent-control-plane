//! `InboxState`/`InMemoryCommandInbox` tests: the shared in-memory delivery
//! decision logic, and `ListCommands` enumeration/pagination over it.

use std::time::Duration;

use crate::errors::CommandErrorCode;
use crate::inbox::*;

use super::support::*;

#[test]
fn a_recorded_command_is_delivered_once_then_suppressed_for_the_window() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    let policy = DeliveryPolicy::default();

    let first = inbox
        .claim(&target("agent-a"), &acme_prod(), policy, 1_000)
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].command_id, "cmd-1");
    assert_eq!(first[0].delivery_attempt, 1);

    // Inside the window: suppressed.
    let second = inbox
        .claim(&target("agent-a"), &acme_prod(), policy, 1_500)
        .unwrap();
    assert!(second.is_empty());

    // Past the window: visible again, because a response that never
    // arrived must not silently lose an operator's stop.
    let third = inbox
        .claim(&target("agent-a"), &acme_prod(), policy, 1_000 + 30_000)
        .unwrap();
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].delivery_attempt, 2);
}

/// The isolation claim, at the storage layer. Agent B's poll must not see
/// agent A's command even though both are in the same workspace and
/// namespace and the store holds both.
#[test]
fn a_command_is_never_delivered_to_another_agent() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox.record(&command("cmd-a", "agent-a")).unwrap();
    inbox.record(&command("cmd-b", "agent-b")).unwrap();
    let policy = DeliveryPolicy::default();

    let for_b = inbox
        .claim(&target("agent-b"), &acme_prod(), policy, 1_000)
        .unwrap();
    assert_eq!(for_b.len(), 1);
    assert_eq!(for_b[0].command_id, "cmd-b");

    let for_a = inbox
        .claim(&target("agent-a"), &acme_prod(), policy, 1_000)
        .unwrap();
    assert_eq!(for_a.len(), 1);
    assert_eq!(for_a[0].command_id, "cmd-a");
}

#[test]
fn a_command_is_never_delivered_across_a_workspace_or_namespace_boundary() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    let policy = DeliveryPolicy::default();
    for (workspace, namespace) in [("other", "prod"), ("acme", "staging"), ("other", "staging")]
    {
        let claimed = inbox
            .claim(
                &target("agent-a"),
                &scope(workspace, namespace),
                policy,
                1_000,
            )
            .unwrap();
        assert!(
            claimed.is_empty(),
            "a credential scoped to {workspace}/{namespace} must not receive acme/prod's command"
        );
    }
}

#[test]
fn recording_the_same_command_twice_is_idempotent() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    assert_eq!(
        inbox.record(&command("cmd-1", "agent-a")).unwrap(),
        RecordResult::Recorded
    );
    assert_eq!(
        inbox.record(&command("cmd-1", "agent-a")).unwrap(),
        RecordResult::AlreadyRecorded
    );
    let claimed = inbox
        .claim(
            &target("agent-a"),
            &acme_prod(),
            DeliveryPolicy::default(),
            1,
        )
        .unwrap();
    assert_eq!(
        claimed.len(),
        1,
        "a resubmitted command must not queue twice"
    );
}

#[test]
fn redelivery_is_bounded_by_the_attempt_ceiling() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    let policy = DeliveryPolicy {
        redelivery_after: Duration::from_secs(1),
        max_attempts: 3,
    };
    let mut delivered = 0;
    for tick in 0..10u64 {
        delivered += inbox
            .claim(&target("agent-a"), &acme_prod(), policy, tick * 5_000)
            .unwrap()
            .len();
    }
    assert_eq!(
        delivered, 3,
        "a command whose target never returns must stop being redelivered"
    );
}

#[test]
fn acknowledging_a_delivery_is_idempotent_and_suppresses_redelivery() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox.record(&command("cmd-ack", "agent-a")).unwrap();
    let policy = DeliveryPolicy {
        redelivery_after: Duration::ZERO,
        max_attempts: 3,
    };
    let delivered = inbox
        .claim(&target("agent-a"), &acme_prod(), policy, 1)
        .unwrap();
    assert_eq!(delivered[0].delivery_attempt, 1);
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-ack".to_owned(),
    };
    assert_eq!(
        inbox.acknowledge(&target("agent-a"), &key, 1, 2).unwrap(),
        AckResult::Acknowledged
    );
    assert_eq!(
        inbox.acknowledge(&target("agent-a"), &key, 1, 3).unwrap(),
        AckResult::AlreadyAcknowledged
    );
    assert!(
        inbox
            .claim(&target("agent-a"), &acme_prod(), policy, 4)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inbox.status(&key, 3).unwrap(),
        Some((DeliveryStatus::Acknowledged, 1))
    );
}

#[test]
fn cancelling_an_undelivered_command_succeeds_and_it_is_never_polled() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox.record(&command("cmd-cancel", "agent-a")).unwrap();
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-cancel".to_owned(),
    };
    assert_eq!(inbox.cancel(&key, 1_000).unwrap(), CancelResult::Cancelled);
    // Idempotent: a retried cancellation (lost response, operator
    // double-click) must not error.
    assert_eq!(
        inbox.cancel(&key, 1_500).unwrap(),
        CancelResult::AlreadyCancelled
    );
    assert_eq!(
        inbox.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS).unwrap(),
        Some((DeliveryStatus::Cancelled, 0))
    );
    assert_eq!(
        inbox.undelivered_count(),
        0,
        "cancellation is terminal and must not remain in the never-delivered diagnostic"
    );
    // The whole point: a cancelled command must never reach a poll.
    assert!(
        inbox
            .claim(
                &target("agent-a"),
                &acme_prod(),
                DeliveryPolicy::default(),
                2_000
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cancelling_an_already_delivered_command_is_refused() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    inbox
        .record(&command("cmd-cancel-late", "agent-a"))
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
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-cancel-late".to_owned(),
    };
    let error = inbox.cancel(&key, 2_000).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::AlreadyDelivered);
    // Refused, not silently no-op'd: the command must still be exactly
    // as deliverable/acknowledgeable as it was before the refused call.
    assert_eq!(
        inbox.status(&key, DEFAULT_MAX_DELIVERY_ATTEMPTS).unwrap(),
        Some((DeliveryStatus::Delivered, 1))
    );
}

#[test]
fn cancelling_an_unknown_command_id_is_reported_as_not_found() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    let key = InboxKey {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: "cmd-never-issued".to_owned(),
    };
    assert_eq!(inbox.cancel(&key, 1_000).unwrap(), CancelResult::NotFound);
}

#[test]
fn the_limit_only_ever_narrows_a_result_set() {
    let mut inbox = InMemoryCommandInbox::new(16, 16);
    for index in 0..5 {
        inbox
            .record(&command(&format!("cmd-{index}"), "agent-a"))
            .unwrap();
    }
    let mut narrow = target("agent-a");
    narrow.limit = 2;
    let claimed = inbox
        .claim(&narrow, &acme_prod(), DeliveryPolicy::default(), 1_000)
        .unwrap();
    assert_eq!(claimed.len(), 2);
    // Oldest first, so a poll cannot starve the earliest command.
    assert_eq!(claimed[0].command_id, "cmd-0");
    assert_eq!(claimed[1].command_id, "cmd-1");
}

#[test]
fn capacity_is_refused_rather_than_silently_dropping_a_command() {
    let mut inbox = InMemoryCommandInbox::new(1, 1);
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::Capacity);
}

/// The actual regression test for the multi-tenant-fairness finding: one
/// workspace/namespace filling its own per-scope quota must never block a
/// *different* scope from recording -- including, in production, an
/// emergency `stop`. The global ceiling (16) is left far from binding so
/// only the per-scope quota (1) can be responsible for either outcome
/// below.
#[test]
fn a_scope_at_its_quota_never_blocks_a_different_scope_from_recording() {
    let mut inbox = InMemoryCommandInbox::new(16, 1);
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    let error = inbox.record(&command("cmd-2", "agent-a")).unwrap_err();
    assert_eq!(
        error.code,
        CommandErrorCode::Capacity,
        "acme/prod must be refused once it is at its own quota"
    );

    let mut other = command("cmd-other", "agent-b");
    other.workspace_id = "other-workspace".to_owned();
    other.namespace_id = "other-ns".to_owned();
    assert_eq!(
        inbox.record(&other).unwrap(),
        RecordResult::Recorded,
        "a scope with room left must not be refused because a different \
         scope exhausted its own quota"
    );
}

/// The per-scope ceiling is enforced on its own terms, distinct from the
/// global capacity: a generous global ceiling (100) does not save a
/// scope from its own tight quota (2).
#[test]
fn the_scope_quota_is_enforced_independently_of_the_global_capacity() {
    let mut inbox = InMemoryCommandInbox::new(100, 2);
    inbox.record(&command("cmd-1", "agent-a")).unwrap();
    inbox.record(&command("cmd-2", "agent-a")).unwrap();
    let error = inbox.record(&command("cmd-3", "agent-a")).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::Capacity);
    assert_eq!(
        inbox.pending_count(),
        2,
        "the global inbox is nowhere near its own ceiling; only the scope quota fired"
    );
}

// --- ListCommands ----------------------------------------------------

fn list_query(after_sequence: u64, limit: usize) -> ListCommandsQuery<'static> {
    ListCommandsQuery {
        workspace_id: "acme",
        namespace_id: "prod",
        agent_id: None,
        state: None,
        after_sequence,
        limit,
        max_attempts: DEFAULT_MAX_DELIVERY_ATTEMPTS,
    }
}

/// A second page requested with the first page's cursor must return the
/// *next* commands, not a repeat, and `has_more` must accurately track
/// whether a further page exists.
#[test]
fn list_commands_pages_through_results_without_repeats_or_gaps() {
    let mut inbox = InMemoryCommandInbox::new(64, 64);
    for index in 0..5 {
        inbox
            .record(&command(&format!("cmd-{index}"), "agent-a"))
            .unwrap();
    }

    let first = inbox.list_commands(&list_query(0, 2)).unwrap();
    assert_eq!(
        first
            .commands
            .iter()
            .map(|c| c.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd-0", "cmd-1"]
    );
    assert!(first.has_more);

    let cursor = first.commands.last().unwrap().sequence;
    let second = inbox.list_commands(&list_query(cursor, 2)).unwrap();
    assert_eq!(
        second
            .commands
            .iter()
            .map(|c| c.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd-2", "cmd-3"]
    );
    assert!(second.has_more);
    assert_ne!(second.commands[0].command_id, first.commands[0].command_id);
    assert_ne!(second.commands[0].command_id, first.commands[1].command_id);

    let cursor = second.commands.last().unwrap().sequence;
    let third = inbox.list_commands(&list_query(cursor, 2)).unwrap();
    assert_eq!(third.commands.len(), 1);
    assert_eq!(third.commands[0].command_id, "cmd-4");
    assert!(
        !third.has_more,
        "the last page must not claim more are available"
    );
}

#[test]
fn list_commands_filters_by_agent_id_and_by_state_and_can_combine_both() {
    let mut inbox = InMemoryCommandInbox::new(64, 64);
    inbox.record(&command("cmd-a", "agent-a")).unwrap();
    inbox.record(&command("cmd-b", "agent-b")).unwrap();
    // Deliver cmd-a so it is no longer Pending; cmd-b stays Pending.
    inbox
        .claim(
            &target("agent-a"),
            &acme_prod(),
            DeliveryPolicy::default(),
            1_000,
        )
        .unwrap();

    let agent_a_only = inbox
        .list_commands(&ListCommandsQuery {
            agent_id: Some("agent-a"),
            ..list_query(0, 16)
        })
        .unwrap();
    assert_eq!(agent_a_only.commands.len(), 1);
    assert_eq!(agent_a_only.commands[0].command_id, "cmd-a");
    assert_eq!(agent_a_only.commands[0].state, DeliveryStatus::Delivered);

    let pending_only = inbox
        .list_commands(&ListCommandsQuery {
            state: Some(DeliveryStatus::Pending),
            ..list_query(0, 16)
        })
        .unwrap();
    assert_eq!(pending_only.commands.len(), 1);
    assert_eq!(pending_only.commands[0].command_id, "cmd-b");

    // Combined: agent-a AND Delivered matches cmd-a; agent-a AND Pending
    // matches nothing, proving the two filters are ANDed, not ORed.
    let combined_match = inbox
        .list_commands(&ListCommandsQuery {
            agent_id: Some("agent-a"),
            state: Some(DeliveryStatus::Delivered),
            ..list_query(0, 16)
        })
        .unwrap();
    assert_eq!(combined_match.commands.len(), 1);
    assert_eq!(combined_match.commands[0].command_id, "cmd-a");

    let combined_empty = inbox
        .list_commands(&ListCommandsQuery {
            agent_id: Some("agent-a"),
            state: Some(DeliveryStatus::Pending),
            ..list_query(0, 16)
        })
        .unwrap();
    assert!(combined_empty.commands.is_empty());
}

#[test]
fn list_commands_is_scoped_to_workspace_and_namespace() {
    let mut inbox = InMemoryCommandInbox::new(64, 64);
    inbox.record(&command("cmd-1", "agent-a")).unwrap(); // acme/prod, via `command()`.
    for (workspace_id, namespace_id) in
        [("other", "prod"), ("acme", "staging"), ("other", "staging")]
    {
        let page = inbox
            .list_commands(&ListCommandsQuery {
                workspace_id,
                namespace_id,
                ..list_query(0, 16)
            })
            .unwrap();
        assert!(
            page.commands.is_empty(),
            "a query scoped to {workspace_id}/{namespace_id} must not see acme/prod's command"
        );
    }
}
