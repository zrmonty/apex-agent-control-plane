//! Real file revocation/recovery on an already established actual TLS channel.
use crate::{
    callback::request,
    material::Materials,
    operation::Fixture,
    pki::{self, Pki},
    transport,
};
use apex_control_plane_api::proto::{
    CheckRuntimeAuthorityRequest, runtime_authority_service_client::RuntimeAuthorityServiceClient,
};
use std::time::{Duration, Instant};
use tonic::{Code, transport::Channel};

pub(super) async fn wait_for_refusal(
    client: &mut RuntimeAuthorityServiceClient<Channel>,
    request: &CheckRuntimeAuthorityRequest,
    code: Code,
    detail: &str,
) {
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        let outcome = transport::within(client.check_runtime_authority(request.clone())).await;
        if let Err(error) = outcome {
            if error.code() == code && error.message() == detail {
                return;
            }
            // Publication may briefly race an immutable-generation handoff.
            assert!(
                matches!(error.code(), Code::Unavailable | Code::FailedPrecondition),
                "unexpected application refusal during refresh: {:?}",
                error.code()
            );
        }
        assert!(
            Instant::now() < until,
            "expected policy refusal never arrived"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub(super) async fn wait_for_version(
    client: &mut RuntimeAuthorityServiceClient<Channel>,
    request: &CheckRuntimeAuthorityRequest,
    version: &str,
) {
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        if let Ok(response) =
            transport::within(client.check_runtime_authority(request.clone())).await
            && response.get_ref().enrollment_version == version
        {
            return;
        }
        assert!(
            Instant::now() < until,
            "healthy new enrollment version never arrived"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[test]
fn enrollment_revocation_missing_and_malformed_files_fail_closed_on_existing_tls_channel() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let before = fixture.bytes();
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    let mut owner = materials.owner(&fixture.database.url);
    let service = owner.start().unwrap();
    let query = request(&fixture, &pki);
    let path = materials.enrollment_path();
    let mut document = materials.enrollment.clone();
    transport::exercise(service, &pki, move |endpoint| async move {
        let pki = Pki::require();
        let mut client = transport::client(&pki, &endpoint, pki::AGENT).await;
        transport::within(client.check_runtime_authority(query.clone()))
            .await
            .expect("healthy before revocation");
        document["version"] = "live-enrollment-2".into();
        document["installations"][0]["revoked"] = true.into();
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        wait_for_refusal(
            &mut client,
            &query,
            Code::PermissionDenied,
            "RUNTIME_AUTHORITY_ENROLLMENT_DENIED",
        )
        .await;
        document["version"] = "live-enrollment-3".into();
        document["installations"][0]["revoked"] = false.into();
        let restored = serde_json::to_vec(&document).unwrap();
        std::fs::write(&path, &restored).unwrap();
        wait_for_version(&mut client, &query, "live-enrollment-3").await;
        for (missing, version) in [(true, "live-enrollment-4"), (false, "live-enrollment-5")] {
            if missing {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::write(&path, b"{malformed PRIVATE-METADATA-CANARY").unwrap();
            }
            // Keep the source broken beyond maximum policy age. A single
            // healthy-refresh lock-contention refusal cannot satisfy this test.
            tokio::time::sleep(Duration::from_millis(2200)).await;
            let until = Instant::now() + Duration::from_millis(300);
            loop {
                let error = transport::within(client.check_runtime_authority(query.clone()))
                    .await
                    .expect_err("broken source must not produce a snapshot");
                assert_eq!(error.code(), Code::Unavailable);
                assert_eq!(error.message(), "RUNTIME_AUTHORITY_UNAVAILABLE");
                if Instant::now() >= until {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            document["version"] = version.into();
            std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            wait_for_version(&mut client, &query, version).await;
        }
    });
    assert!(owner.shutdown().cleanup_complete);
    assert_eq!(fixture.bytes(), before);
}
