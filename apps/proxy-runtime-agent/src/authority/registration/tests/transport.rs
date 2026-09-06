use super::{server::Fixture, support::*, *};
use std::sync::atomic::Ordering;

#[tokio::test]
#[ignore = "requires existing APEX_BROWSER_TEST_PKI_DIR; explicit real TLS fixture"]
async fn actual_controller_tls_to_pinned_agent_callback_returns_exact_original_receipt() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let first = within(caller.register_deployment(query()))
        .await
        .unwrap()
        .into_inner();
    let retry = within(caller.register_deployment(query()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first, receipt());
    assert_eq!(retry, first);
    let sent = fixture.state.sent.lock().unwrap().clone().unwrap();
    assert_eq!(sent.attestation, Some(attestation()));
    let current = sent.authority.unwrap();
    assert_eq!(current.target, Some(target()));
    assert_eq!(current.installation_id, INSTALL);
    assert_eq!(current.operation_id, OPERATION);
    assert_eq!(current.command_id, COMMAND);
    assert_eq!(
        current.observed_controller_certificate_sha256,
        pki.pin(CONTROLLER)
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
#[ignore = "requires existing APEX_BROWSER_TEST_PKI_DIR; explicit real TLS fixture"]
async fn missing_tls_wrong_role_bounds_and_shared_eight_slots_dispatch_nothing() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    assert_eq!(
        fixture
            .client
            .register(
                &query(),
                &policy(&pki, Duration::from_secs(60), false),
                operation(&target()),
                &attestation(),
                BUDGET
            )
            .await
            .unwrap_err(),
        Error::Unauthenticated
    );
    for (leaf, error) in [
        (None, Error::Unauthenticated),
        (Some(AGENT), Error::Denied),
        (Some(OTHER), Error::Denied),
    ] {
        let mut caller = caller(&pki, &fixture.ingress.endpoint, leaf).await;
        assert_eq!(
            within(caller.register_deployment(query()))
                .await
                .unwrap_err()
                .message(),
            error.code()
        );
    }
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let slots = fixture.client.slots.try_acquire_many(8).unwrap();
    assert_eq!(
        within(caller.register_deployment(query()))
            .await
            .unwrap_err()
            .message(),
        Error::Overloaded.code()
    );
    drop(slots);
    let mut oversized = query();
    oversized
        .get_mut()
        .attestation
        .as_mut()
        .unwrap()
        .staged_manifest_sha256 = CANARY.repeat(1024);
    assert_eq!(
        within(caller.register_deployment(oversized))
            .await
            .unwrap_err()
            .message(),
        Error::InvalidInput.code()
    );
    fixture.settings.lock().unwrap().budget = Duration::ZERO;
    assert_eq!(
        within(caller.register_deployment(query()))
            .await
            .unwrap_err()
            .message(),
        Error::Deadline.code()
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
    fixture.settings.lock().unwrap().budget = BUDGET;
    within(caller.register_deployment(query())).await.unwrap();
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
#[ignore = "requires existing APEX_BROWSER_TEST_PKI_DIR; explicit real TLS fixture"]
async fn mismatched_oversized_and_remote_refusal_responses_are_redacted() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    for changed in [
        proto::RuntimeDeploymentRegistrationReceipt {
            attestation_sha256: "b".repeat(64),
            ..receipt()
        },
        proto::RuntimeDeploymentRegistrationReceipt {
            authority: None,
            ..receipt()
        },
        proto::RuntimeDeploymentRegistrationReceipt {
            attestation_sha256: CANARY.repeat(1024),
            ..receipt()
        },
    ] {
        *fixture.state.reply.lock().unwrap() = changed;
        let error = within(caller.register_deployment(query()))
            .await
            .unwrap_err();
        assert!(error.message().starts_with("RUNTIME_AUTHORITY_CLIENT_"));
        assert!(!format!("{error:?}").contains(CANARY));
    }
    *fixture.state.reply.lock().unwrap() = receipt();
    for (code, expected) in [
        (tonic::Code::PermissionDenied, Error::Denied),
        (tonic::Code::Unavailable, Error::Unavailable),
        (tonic::Code::InvalidArgument, Error::RemoteRefusal),
    ] {
        *fixture.state.refusal.lock().unwrap() = Some(code);
        let error = within(caller.register_deployment(query()))
            .await
            .unwrap_err();
        assert_eq!(error.message(), expected.code());
        assert!(!format!("{error:?}").contains(CANARY));
    }
    *fixture.state.refusal.lock().unwrap() = None;
    within(caller.register_deployment(query())).await.unwrap();
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
#[ignore = "requires existing APEX_BROWSER_TEST_PKI_DIR; explicit real TLS fixture"]
async fn deadline_cancellation_and_post_rpc_policy_expiry_release_capacity() {
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = caller(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    fixture.state.hold.store(true, Ordering::SeqCst);
    fixture.settings.lock().unwrap().budget = Duration::from_millis(100);
    assert_eq!(
        within(caller.register_deployment(query()))
            .await
            .unwrap_err()
            .message(),
        Error::Deadline.code()
    );
    assert_eq!(fixture.client.slots.available_permits(), 8);
    fixture.state.entered.acquire().await.unwrap().forget();
    fixture.settings.lock().unwrap().budget = BUDGET;
    let mut other = caller.clone();
    let call = tokio::spawn(async move { other.register_deployment(query()).await });
    within(fixture.state.entered.acquire())
        .await
        .unwrap()
        .forget();
    fixture.cancel.notify_waiters();
    assert_eq!(
        within(call).await.unwrap().unwrap_err().code(),
        tonic::Code::Cancelled
    );
    assert_eq!(fixture.client.slots.available_permits(), 8);
    fixture.settings.lock().unwrap().policy = policy(&pki, Duration::from_millis(300), false);
    let mut other = caller.clone();
    let call = tokio::spawn(async move { other.register_deployment(query()).await });
    within(fixture.state.entered.acquire())
        .await
        .unwrap()
        .forget();
    tokio::time::sleep(Duration::from_millis(350)).await;
    fixture.state.release.add_permits(8);
    assert_eq!(
        within(call).await.unwrap().unwrap_err().message(),
        Error::Denied.code()
    );
    assert_eq!(fixture.client.slots.available_permits(), 8);
    fixture.state.hold.store(false, Ordering::SeqCst);
    fixture.settings.lock().unwrap().policy = policy(&pki, Duration::from_secs(60), false);
    within(caller.register_deployment(query())).await.unwrap();
    drop(caller);
    fixture.shutdown().await;
}
