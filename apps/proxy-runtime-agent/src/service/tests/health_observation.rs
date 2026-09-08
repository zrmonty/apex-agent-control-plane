//! Fresh health route must authenticate the controller before touching an owner.
use super::*;
use crate::proto::runtime_health_observation_client::RuntimeHealthObservationClient;

fn observation() -> proto::RuntimeHealthObservationRequest {
    let r = request();
    proto::RuntimeHealthObservationRequest {
        schema_version: 1,
        binding: Some(proto::ManagedDeploymentBinding {
            installation_id: INSTALL.into(),
            target: r.target,
            process_instance_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e09".into(),
            config_hash: r.config_hash,
            launch_context_hash: "b".repeat(64),
        }),
        nonce: vec![7; 32],
    }
}
async fn client(
    f: &Fixture,
    leaf: &str,
) -> RuntimeHealthObservationClient<tonic::transport::Channel> {
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")))
        .identity(f.pki.identity("trusted-host", leaf));
    RuntimeHealthObservationClient::new(
        Endpoint::from_shared(f.endpoint.clone())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_lazy(),
    )
}

#[tokio::test]
#[ignore = "requires explicit TLS fixture gate"]
async fn health_observation_registered_controller_refuses_missing_owner_without_callback() {
    let f = Fixture::start().await;
    let e = client(&f, CONTROLLER)
        .await
        .observe(observation())
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::Unavailable);
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires explicit TLS fixture gate"]
async fn health_observation_denies_wrong_role_and_scope_before_effects() {
    let f = Fixture::start().await;
    let mut r = Request::new(observation());
    r.metadata_mut()
        .insert("authorization", "Bearer health-token".parse().unwrap());
    assert_eq!(
        client(&f, AGENT).await.observe(r).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let mut c = client(&f, CONTROLLER).await;
    for field in ["installation", "workspace", "namespace"] {
        let mut r = observation();
        let b = r.binding.as_mut().unwrap();
        match field {
            "installation" => b.installation_id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e10".into(),
            "workspace" => b.target.as_mut().unwrap().workspace_id = "other".into(),
            _ => b.target.as_mut().unwrap().namespace_id = "other".into(),
        }
        assert_eq!(
            c.observe(r).await.unwrap_err().code(),
            tonic::Code::PermissionDenied,
            "{field}"
        );
    }
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires explicit TLS fixture gate"]
async fn health_observation_requires_exact_binding_and_nonce() {
    let f = Fixture::start().await;
    let mut c = client(&f, CONTROLLER).await;
    let mutations: &[fn(&mut proto::RuntimeHealthObservationRequest)] = &[
        |r| r.schema_version = 0,
        |r| r.schema_version = 2,
        |r| r.binding = None,
        |r| r.nonce = vec![0; 31],
        |r| r.nonce = vec![0; 33],
        |r| r.binding.as_mut().unwrap().target = None,
        |r| r.binding.as_mut().unwrap().process_instance_id.clear(),
        |r| r.binding.as_mut().unwrap().config_hash = "A".repeat(64),
        |r| r.binding.as_mut().unwrap().launch_context_hash.clear(),
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .generation = 0
        },
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .fencing_token = u64::MAX
        },
    ];
    for mutate in mutations {
        let mut r = observation();
        mutate(&mut r);
        assert_eq!(
            c.observe(r).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    let mut r = observation();
    r.nonce = vec![0; 8192];
    assert!(c.observe(r).await.is_err());
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}
