//! Real Controller TLS -> test agent -> production client -> Agent mTLS callback.
//! Callback snapshots contain synthetic DB timestamps; main owns real PG proof.

#[path = "runtime_authority_client/lifetime_tests.rs"]
mod lifetime_tests;
#[path = "runtime_peer_pair/pki.rs"]
mod pki;
#[path = "runtime_authority_client/server.rs"]
mod server;
#[path = "runtime_authority_client/support.rs"]
mod support;
#[path = "runtime_authority_client/transport_tests.rs"]
mod transport_tests;

use apex_proxy_runtime_agent::{
    authority::{AuthorityClientError as Error, AuthorityOperation},
    proto,
};
use pki::{AGENT, CONTROLLER, OTHER, Pki};
use server::Fixture;
use std::{sync::atomic::Ordering, time::Duration};
use support::*;

#[tokio::test]
async fn exact_snapshot_and_actual_controller_leaf_survive_two_real_tls_hops() {
    // Catches bypassing production check, caller-supplied attestation and token forwarding.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut controller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let response = within(controller.check_runtime_authority(query()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response, snapshot());
    let sent = fixture.state.request.lock().unwrap().clone().unwrap();
    assert_eq!(sent.target, Some(target()));
    assert_eq!(sent.operation_id, "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05");
    assert_eq!(sent.command_id, "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06");
    assert_eq!(
        sent.observed_controller_certificate_sha256,
        pki.pin(CONTROLLER)
    );
    assert!(!fixture.state.leaked_metadata.load(Ordering::SeqCst));
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    drop(controller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn missing_tls_wrong_role_unknown_leaf_and_spoofed_metadata_dispatch_nothing() {
    // Catches trusting metadata/claimed role instead of actual request TLS evidence.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let local = query();
    let policy = policy(&pki, "client-policy", false);
    let target = target();
    let result = fixture
        .client
        .check(
            &local,
            &policy,
            AuthorityOperation {
                target: &target,
                operation_id: &local.get_ref().operation_id,
                command_id: &local.get_ref().command_id,
                config_hash: HASH,
            },
            BUDGET,
        )
        .await;
    assert_eq!(result.unwrap_err(), Error::Unauthenticated);
    for (leaf, error) in [
        (None, Error::Unauthenticated),
        (Some(AGENT), Error::Denied),
        (Some(OTHER), Error::Denied),
    ] {
        let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, leaf).await;
        assert_error(
            within(caller.check_runtime_authority(query()))
                .await
                .unwrap_err(),
            error,
        );
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn current_caller_policy_is_used_on_every_check_and_exact_scope_is_required() {
    // Catches caching the initial policy or using workspace/namespace Cartesian grants.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    within(caller.check_runtime_authority(query()))
        .await
        .unwrap();
    for workspace in [true, false] {
        let mut request = query();
        let target = request.get_mut().target.as_mut().unwrap();
        if workspace {
            target.workspace_id = "other-work".into();
        } else {
            target.namespace_id = "other-ns".into();
        }
        assert_error(
            within(caller.check_runtime_authority(request))
                .await
                .unwrap_err(),
            Error::Denied,
        );
    }
    fixture.incoming.settings.lock().unwrap().policy = policy(&pki, "policy-revoked", true);
    assert_error(
        within(caller.check_runtime_authority(query()))
            .await
            .unwrap_err(),
        Error::Denied,
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    fixture.incoming.settings.lock().unwrap().policy = policy(&pki, "policy-next", false);
    fixture.state.snapshot.lock().unwrap().peer_policy_version = "policy-next".into();
    within(caller.check_runtime_authority(query()))
        .await
        .unwrap();
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn invalid_claims_and_zero_budget_are_refused_before_callback() {
    // Catches copying/network dispatch before lexical and signed SQL range validation.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let mutations: &[fn(&mut proto::CheckRuntimeAuthorityRequest)] = &[
        |r| r.target.as_mut().unwrap().workspace_id = "..".into(),
        |r| r.target.as_mut().unwrap().namespace_id = "a".repeat(257),
        |r| r.target.as_mut().unwrap().proxy_id = "not-uuid".into(),
        |r| r.target.as_mut().unwrap().revision_id = "not-uuid".into(),
        |r| r.target.as_mut().unwrap().generation = 0,
        |r| r.target.as_mut().unwrap().generation = 9_223_372_036_854_775_808,
        |r| r.target.as_mut().unwrap().fencing_token = 0,
        |r| r.target.as_mut().unwrap().fencing_token = u64::MAX,
        |r| r.operation_id = r.operation_id.to_uppercase(),
        |r| r.command_id.replace_range(14..15, "4"),
    ];
    for mutate in mutations {
        let mut request = query();
        mutate(request.get_mut());
        assert_error(
            within(caller.check_runtime_authority(request))
                .await
                .unwrap_err(),
            Error::InvalidInput,
        );
    }
    for hash in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
        fixture.incoming.settings.lock().unwrap().config_hash = hash;
        assert_error(
            within(caller.check_runtime_authority(query()))
                .await
                .unwrap_err(),
            Error::InvalidInput,
        );
    }
    fixture.incoming.settings.lock().unwrap().config_hash = HASH.into();
    fixture.incoming.settings.lock().unwrap().budget = Duration::ZERO;
    assert_error(
        within(caller.check_runtime_authority(query()))
            .await
            .unwrap_err(),
        Error::Deadline,
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn every_snapshot_binding_enum_timestamp_and_oversized_reply_is_refused_over_tls() {
    // Catches returning a well-formed but unrelated snapshot or unchecked protobuf defaults.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    within(caller.check_runtime_authority(query()))
        .await
        .unwrap();
    let mutations: &[fn(&mut proto::RuntimeAuthoritySnapshot)] = &[
        |s| s.schema_version = 0,
        |s| s.action = 0,
        |s| s.action = 99,
        |s| s.target = None,
        |s| s.target.as_mut().unwrap().workspace_id = "other".into(),
        |s| s.target.as_mut().unwrap().namespace_id = "other".into(),
        |s| s.target.as_mut().unwrap().proxy_id.replace_range(35.., "9"),
        |s| {
            s.target
                .as_mut()
                .unwrap()
                .revision_id
                .replace_range(35.., "9")
        },
        |s| s.target.as_mut().unwrap().generation += 1,
        |s| s.target.as_mut().unwrap().fencing_token += 1,
        |s| s.target.as_mut().unwrap().generation = u64::MAX,
        |s| s.target.as_mut().unwrap().fencing_token = u64::MAX,
        |s| s.operation_id.replace_range(35.., "9"),
        |s| s.command_id.replace_range(35.., "9"),
        |s| s.installation_id.replace_range(35.., "9"),
        |s| s.agent_identity_id = "other-agent".into(),
        |s| s.observed_controller_identity_id = "other-controller".into(),
        |s| s.peer_policy_version = "other-policy".into(),
        |s| s.enrollment_version = "other-enrollment".into(),
        |s| s.host_policy_version = "other-host".into(),
        |s| s.config_hash = "b".repeat(64),
        |s| s.desired_state = 0,
        |s| s.desired_state = 99,
        |s| s.observed_state = 0,
        |s| s.observed_state = -1,
        |s| s.checked_at_unix_us = 0,
        |s| s.lease_expires_at_unix_us = 0,
        |s| s.lease_expires_at_unix_us = s.checked_at_unix_us,
        |s| s.lease_expires_at_unix_us = s.checked_at_unix_us - 1,
        |s| s.checked_at_unix_us = u64::MAX,
        |s| s.lease_expires_at_unix_us = 9_223_372_036_854_775_808,
        |s| s.config_hash = CANARY.repeat(240),
    ];
    for mutate in mutations {
        let mut value = snapshot();
        mutate(&mut value);
        *fixture.state.snapshot.lock().unwrap() = value;
        let error = within(caller.check_runtime_authority(query()))
            .await
            .unwrap_err();
        assert!(error.message().starts_with("RUNTIME_AUTHORITY_CLIENT_"));
        assert!(!format!("{error:?}").contains(CANARY));
    }
    assert_eq!(
        fixture.state.calls.load(Ordering::SeqCst),
        mutations.len() + 1
    );
    *fixture.state.snapshot.lock().unwrap() = snapshot();
    within(caller.check_runtime_authority(query()))
        .await
        .unwrap();
    drop(caller);
    fixture.shutdown().await;
}
