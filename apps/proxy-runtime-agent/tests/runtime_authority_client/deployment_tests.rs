//! Real TLS resolution coverage through the production client; synthetic DB time.

use super::{
    pki::{AGENT, CONTROLLER, OTHER, Pki},
    server::{Fixture, deployment_snapshot},
    support::*,
};
use apex_proxy_runtime_agent::{
    authority::{AuthorityClientError as Error, AuthorityOperation},
    proto::{self, runtime_deployment_service_client::RuntimeDeploymentServiceClient},
};
use std::{sync::atomic::Ordering, time::Duration};
use tokio::task::JoinSet;
use tonic::{
    Code,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

async fn caller(
    pki: &Pki,
    endpoint: &str,
    leaf: Option<&str>,
) -> RuntimeDeploymentServiceClient<Channel> {
    let mut tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")));
    if let Some(leaf) = leaf {
        tls = tls.identity(pki.identity("trusted-host", leaf));
    }
    let channel = within(
        Endpoint::from_shared(endpoint.to_owned())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .buffer_size(8)
            .connect_timeout(BUDGET)
            .connect(),
    )
    .await
    .unwrap();
    RuntimeDeploymentServiceClient::new(channel)
        .max_encoding_message_size(4096)
        .max_decoding_message_size(270_336)
}

#[tokio::test]
async fn resolution_preserves_independent_configuration_and_observed_controller_without_forwarding()
{
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let actual = within(caller.resolve_runtime_deployment(query()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(actual, deployment_snapshot());
    let configuration = actual.configuration.unwrap();
    assert_eq!(configuration.generation, 9_007_199_254_740_993);
    assert_eq!(configuration.config_hash, HASH);
    assert_eq!(configuration.resource_url, "https://proxy.apex.test/mcp");
    assert_eq!(actual.deployment_bindings_version, "bindings-1");
    let sent = fixture.state.request.lock().unwrap().clone().unwrap();
    assert_eq!(sent.target, Some(target()));
    assert_eq!(sent.operation_id, query().get_ref().operation_id);
    assert_eq!(sent.command_id, query().get_ref().command_id);
    assert_eq!(sent.installation_id, INSTALL);
    assert_eq!(
        sent.observed_controller_certificate_sha256,
        pki.pin(CONTROLLER)
    );
    assert!(!fixture.state.leaked_metadata.load(Ordering::SeqCst));
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.resolve_calls.load(Ordering::SeqCst), 1);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn resolution_missing_tls_wrong_role_unknown_leaf_and_spoofed_attestation_never_dispatch() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let request = query();
    let target = target();
    let current = policy(&pki, "client-policy", false);
    let error = fixture
        .client
        .resolve(
            &request,
            &current,
            AuthorityOperation {
                target: &target,
                operation_id: &request.get_ref().operation_id,
                command_id: &request.get_ref().command_id,
                config_hash: HASH,
            },
            BUDGET,
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::Unauthenticated);
    for (leaf, expected) in [
        (None, Error::Unauthenticated),
        (Some(AGENT), Error::Denied),
        (Some(OTHER), Error::Denied),
    ] {
        let mut caller = caller(&pki, &fixture.ingress.endpoint, leaf).await;
        assert_error(
            within(caller.resolve_runtime_deployment(query()))
                .await
                .unwrap_err(),
            expected,
        );
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.resolve_calls.load(Ordering::SeqCst), 0);
    // A valid request on these listeners prevents an inert fixture passing.
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    assert_eq!(
        within(caller.resolve_runtime_deployment(query()))
            .await
            .unwrap()
            .into_inner(),
        deployment_snapshot()
    );
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn resolution_rejects_missing_fields_modified_configuration_and_invalid_version_over_tls() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let mutations: &[fn(&mut proto::RuntimeDeploymentSnapshot)] = &[
        |r| r.schema_version = 0,
        |r| r.authority = None,
        |r| r.configuration = None,
        |r| r.deployment_bindings_version.clear(),
        |r| r.deployment_bindings_version = "x".repeat(129),
        |r| r.deployment_bindings_version = "../private-canary".into(),
        |r| r.configuration.as_mut().unwrap().generation += 1,
        |r| r.configuration.as_mut().unwrap().workspace_id = "other-work".into(),
        |r| r.configuration.as_mut().unwrap().runtime_manifest_hash = "b".repeat(64),
        |r| r.configuration.as_mut().unwrap().pid_limit += 1,
        |r| {
            r.configuration
                .as_mut()
                .unwrap()
                .secret_refs
                .push(format!("secret://{CANARY}/token"))
        },
        |r| {
            r.configuration
                .as_mut()
                .unwrap()
                .spec
                .as_mut()
                .unwrap()
                .upstreams[0]
                .endpoint_or_command_ref = format!("https://{CANARY}.example/mcp")
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut response = deployment_snapshot();
        mutate(&mut response);
        *fixture.state.deployment.lock().unwrap() = response;
        assert_error(
            within(caller.resolve_runtime_deployment(query()))
                .await
                .unwrap_err(),
            Error::InvalidSnapshot,
        );
        assert_eq!(
            fixture.state.resolve_calls.load(Ordering::SeqCst),
            index + 1
        );
    }
    *fixture.state.deployment.lock().unwrap() = deployment_snapshot();
    assert_eq!(
        within(caller.resolve_runtime_deployment(query()))
            .await
            .unwrap()
            .into_inner(),
        deployment_snapshot()
    );
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn resolution_oversized_wire_reply_is_redacted_by_decoder_and_channel_recovers() {
    use prost::Message;
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let mut oversized = deployment_snapshot();
    let configuration = oversized.configuration.as_mut().unwrap();
    configuration.resource_url = format!("https://{CANARY}.invalid/{}", "x".repeat(270_337));
    configuration.runtime_manifest_hash =
        apex_proxy_runtime_agent::runtime_manifest_hash(configuration).unwrap();
    assert!(oversized.encoded_len() > 270_336 && oversized.encoded_len() < 540_672);
    *fixture.state.deployment.lock().unwrap() = oversized;
    // RemoteRefusal distinguishes tonic's bounded decoder from parse's InvalidSnapshot.
    assert_error(
        within(caller.resolve_runtime_deployment(query()))
            .await
            .unwrap_err(),
        Error::RemoteRefusal,
    );
    *fixture.state.deployment.lock().unwrap() = deployment_snapshot();
    assert_eq!(
        within(caller.resolve_runtime_deployment(query()))
            .await
            .unwrap()
            .into_inner(),
        deployment_snapshot()
    );
    assert_eq!(fixture.state.resolve_calls.load(Ordering::SeqCst), 2);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn self_consistent_resolution_still_must_match_original_operation_and_tls_identity() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    for case in [
        "scope",
        "generation",
        "hash",
        "controller",
        "operation",
        "enrollment",
        "fence",
    ] {
        let mut response = deployment_snapshot();
        let authority = response.authority.as_mut().unwrap();
        let configuration = response.configuration.as_mut().unwrap();
        match case {
            "scope" => {
                authority.target.as_mut().unwrap().namespace_id = "other-ns".into();
                configuration.namespace_id = "other-ns".into();
            }
            "generation" => {
                authority.target.as_mut().unwrap().generation += 1;
                configuration.generation += 1;
            }
            "hash" => {
                authority.config_hash = "c".repeat(64);
                configuration.config_hash = "c".repeat(64);
            }
            "controller" => authority.observed_controller_identity_id = "other-controller".into(),
            "operation" => authority.operation_id.replace_range(35.., "9"),
            "enrollment" => authority.enrollment_version = "other-enrollment".into(),
            "fence" => authority.target.as_mut().unwrap().fencing_token += 1,
            _ => unreachable!(),
        }
        configuration.runtime_manifest_hash =
            apex_proxy_runtime_agent::runtime_manifest_hash(configuration).unwrap();
        *fixture.state.deployment.lock().unwrap() = response;
        assert_error(
            within(caller.resolve_runtime_deployment(query()))
                .await
                .unwrap_err(),
            Error::MismatchedSnapshot,
        );
    }
    assert_eq!(fixture.state.resolve_calls.load(Ordering::SeqCst), 7);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn resolution_remote_refusals_are_redacted_classified_and_not_retried() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    for (index, (remote, expected)) in [
        (Code::PermissionDenied, Error::Denied),
        (Code::Unauthenticated, Error::Unauthenticated),
        (Code::Unavailable, Error::Unavailable),
        (Code::DeadlineExceeded, Error::Deadline),
        (Code::Internal, Error::RemoteRefusal),
        (Code::ResourceExhausted, Error::RemoteRefusal),
    ]
    .into_iter()
    .enumerate()
    {
        *fixture.state.refusal.lock().unwrap() = Some(remote);
        assert_error(
            within(caller.resolve_runtime_deployment(query()))
                .await
                .unwrap_err(),
            expected,
        );
        assert_eq!(
            fixture.state.resolve_calls.load(Ordering::SeqCst),
            index + 1
        );
    }
    *fixture.state.refusal.lock().unwrap() = None;
    assert_eq!(
        within(caller.resolve_runtime_deployment(query()))
            .await
            .unwrap()
            .into_inner(),
        deployment_snapshot()
    );
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn resolution_deadline_cancels_held_callback_and_recovers_capacity() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    fixture.incoming.settings.lock().unwrap().budget = Duration::from_millis(300);
    fixture.state.hold.store(true, Ordering::SeqCst);
    let (result, ()) = tokio::join!(
        within(caller.resolve_runtime_deployment(query())),
        fixture.state.wait_entered(1),
    );
    assert_error(result.unwrap_err(), Error::Deadline);
    fixture.state.wait_departed(1).await;
    assert_eq!(fixture.state.active.load(Ordering::SeqCst), 0);
    fixture.state.hold.store(false, Ordering::SeqCst);
    fixture.incoming.settings.lock().unwrap().budget = BUDGET;
    assert_eq!(
        within(caller.resolve_runtime_deployment(query()))
            .await
            .unwrap()
            .into_inner(),
        deployment_snapshot()
    );
    assert_eq!(fixture.state.resolve_calls.load(Ordering::SeqCst), 2);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn mixed_check_and_resolve_share_eight_slots_and_cancellation_recovers_the_full_ceiling() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    fixture.incoming.settings.lock().unwrap().budget = Duration::from_secs(5);
    fixture.state.hold.store(true, Ordering::SeqCst);
    let check = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let resolve = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let mut calls = JoinSet::new();
    for round in 0..2 {
        // Every caller is owned by JoinSet, which aborts outstanding tasks on drop.
        for _ in 0..4 {
            let mut check = check.clone();
            calls.spawn(async move {
                let reply = check.check_runtime_authority(query()).await?;
                assert_eq!(reply.into_inner(), snapshot());
                Ok::<(), tonic::Status>(())
            });
            let mut resolve = resolve.clone();
            calls.spawn(async move {
                let reply = resolve.resolve_runtime_deployment(query()).await?;
                assert_eq!(reply.into_inner(), deployment_snapshot());
                Ok::<(), tonic::Status>(())
            });
        }
        fixture.state.wait_entered(8).await;
        assert_eq!(fixture.state.active.load(Ordering::SeqCst), 8);
        assert_eq!(
            fixture.state.resolve_calls.load(Ordering::SeqCst),
            4 * (round + 1)
        );
        if round == 0 {
            let mut ninth_check = check.clone();
            let mut ninth_resolve = resolve.clone();
            assert_error(
                within(ninth_check.check_runtime_authority(query()))
                    .await
                    .unwrap_err(),
                Error::Overloaded,
            );
            assert_error(
                within(ninth_resolve.resolve_runtime_deployment(query()))
                    .await
                    .unwrap_err(),
                Error::Overloaded,
            );
            assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 8);
            fixture.incoming.cancel.notify_waiters();
        } else {
            fixture.state.release.add_permits(8);
        }
        while let Some(result) = within(calls.join_next()).await {
            let result = result.unwrap();
            if round == 0 {
                assert_eq!(result.unwrap_err().code(), Code::Cancelled);
            } else {
                result.unwrap();
            }
        }
        fixture.state.wait_departed(8).await;
        assert_eq!(fixture.state.active.load(Ordering::SeqCst), 0);
    }
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 16);
    drop(check);
    drop(resolve);
    fixture.shutdown().await;
}
