// Agent polling tests for rate limits.

/// An agent polling aggressively must be bounded, or one workload can
/// degrade the control channel for every other workload sharing the
/// gateway.
#[tokio::test]
async fn poll_is_rate_limited_per_agent_after_the_ceiling() {
    let service = service_with_two_agents();
    for _ in 0..DEFAULT_MAX_POLLS_PER_WINDOW {
        service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .expect("polls inside the ceiling must succeed");
    }
    let status = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .expect_err("the poll ceiling must be enforced");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);

    // ... and the ceiling is per agent: a second workload is unaffected by
    // the first one's behaviour, or one noisy agent becomes an outage for
    // everybody.
    service
        .poll_commands(poll_request("agent-b-token-abcdefgh", peer(0xbb)))
        .await
        .expect("a different agent must have its own budget");
}

/// Same defect, same fix, as `admission.rs`'s equivalent test for the
/// operator ceiling: `accelerator_slots` is a purely local concurrency
/// limiter on the shared store, not a signal about the polling agent. A
/// saturated limiter must fall back to the local poll ceiling, not reject a
/// poll the local ceiling would have allowed.
#[tokio::test]
async fn a_saturated_accelerator_concurrency_limit_falls_back_to_the_local_poll_ceiling() {
    let store: SharedEphemeralStore = Arc::new(Mutex::new(Box::new(
        apex_auth::InMemoryEphemeralStore::new(),
    )));
    let service = service_with_two_agents().with_ephemeral_store(store);
    let _permits = service
        .accelerator_slots
        .clone()
        .try_acquire_many_owned(MAX_ACCELERATOR_OPERATIONS as u32)
        .expect("nothing else has acquired a permit yet");
    for _ in 0..DEFAULT_MAX_POLLS_PER_WINDOW {
        service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .expect(
                "polls within the local ceiling must succeed even while the \
                 accelerator's concurrency limiter is saturated",
            );
    }
    let status = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .expect_err("the local poll ceiling itself must still apply");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

/// `AckCommand` shares `PollCommands`' per-agent `admit_poll` ceiling and the
/// gateway's shared `storage_slots` pool with every other RPC. Without its
/// own admission check, an agent could spend an unbounded number of
/// `AckCommand` calls against that shared pool -- starving `PollCommands`,
/// and every operator's `SubmitCommand`, for everyone else on the process.
/// The command_id here is deliberately never recorded: admission is charged
/// before the inbox is ever consulted, so an unknown command_id still counts
/// against the ceiling exactly like a real one would.
#[tokio::test]
async fn ack_command_is_rate_limited_per_agent_after_the_ceiling() {
    let service = service_with_two_agents();
    let ack_request = |token: &str, peer_id: u8| {
        let mut request = tonic::Request::new(proto::AckCommandRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "does-not-exist".to_owned(),
            delivery_attempt: 1,
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request.extensions_mut().insert(peer(peer_id));
        request
    };
    for _ in 0..DEFAULT_MAX_POLLS_PER_WINDOW {
        service
            .ack_command(ack_request("agent-a-token-abcdefgh", 0xaa))
            .await
            .expect("acks inside the ceiling must succeed");
    }
    let status = service
        .ack_command(ack_request("agent-a-token-abcdefgh", 0xaa))
        .await
        .expect_err("the poll ceiling must be enforced on AckCommand too");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);

    // ... and the ceiling is per agent, same as PollCommands'.
    service
        .ack_command(ack_request("agent-b-token-abcdefgh", 0xbb))
        .await
        .expect("a different agent must have its own budget");
}

#[test]
fn the_poll_rate_limit_key_is_disjoint_from_the_operator_one() {
    let subject = "spiffe://apex/workload/agent-a";
    let poll = control_poll_rate_limit_key(subject);
    let operator = control_admission_rate_limit_key(subject);
    // Same namespace on purpose (see the key function's own comment: a
    // second namespace would fall outside the deployment's Valkey ACL
    // pattern and the shared ceiling would silently stop applying) ...
    assert_eq!(poll.namespace, operator.namespace);
    // ... and disjoint buckets, so an agent's polls can never consume an
    // operator's command budget or vice versa.
    assert_ne!(poll.bucket, operator.bucket);
    assert!(!poll.bucket.contains("agent-a"));
    // Both must satisfy the store's own key grammar, or every
    // check_rate_limit call errors and the shared ceiling never applies.
    let mut store = apex_auth::InMemoryEphemeralStore::new();
    assert!(
        store
            .check_rate_limit(&poll, 1, Duration::from_secs(1))
            .is_ok()
    );
}
