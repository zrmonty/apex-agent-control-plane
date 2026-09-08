//! Real incoming TLS and registered read-only route, with no authority callback.
use super::*;
use crate::proto::runtime_network_inspection_client::RuntimeNetworkInspectionClient;
#[cfg(target_os = "linux")]
mod owned;
#[cfg(target_os = "linux")]
pub(crate) use owned::check as owned_pair;
#[cfg(target_os = "linux")]
pub(crate) use owned::check_health as owned_health;

fn inspection() -> proto::RuntimeNetworkInspectionRequest {
    let r = request();
    proto::RuntimeNetworkInspectionRequest {
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
    leaf: Option<(&str, &str)>,
) -> RuntimeNetworkInspectionClient<tonic::transport::Channel> {
    let mut tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(f.pki.read("trusted-host", "ca.pem")));
    if let Some((tree, leaf)) = leaf {
        tls = tls.identity(f.pki.identity(tree, leaf));
    }
    RuntimeNetworkInspectionClient::new(
        Endpoint::from_shared(f.endpoint.clone())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_lazy(),
    )
}

#[tokio::test]
#[ignore = "requires explicit Linux/TLS fixture gate"]
async fn network_inspection_registered_controller_read_refuses_missing_owner_without_callback() {
    let f = Fixture::start().await;
    let mut c = client(&f, Some(("trusted-host", CONTROLLER))).await;
    let e = c.check(inspection()).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::Unavailable);
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires explicit Linux/TLS fixture gate"]
async fn network_inspection_rejects_wrong_roles_scopes_and_bearer_before_io() {
    let f = Fixture::start().await;
    for leaf in [None, Some(("trusted-host", AGENT))] {
        let mut c = client(&f, leaf).await;
        let mut r = Request::new(inspection());
        r.metadata_mut()
            .insert("authorization", "Bearer health-token".parse().unwrap());
        let e = c.check(r).await.unwrap_err();
        if leaf.is_some() {
            assert_eq!(e.code(), tonic::Code::PermissionDenied, "{e}");
        } else {
            assert_ne!(
                e.code(),
                tonic::Code::Unimplemented,
                "TLS handshake must refuse: {e}"
            );
        }
    }
    let mut c = client(&f, Some(("trusted-host", CONTROLLER))).await;
    for field in ["installation", "workspace", "namespace"] {
        let mut r = inspection();
        let b = r.binding.as_mut().unwrap();
        match field {
            "installation" => b.installation_id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e10".into(),
            "workspace" => b.target.as_mut().unwrap().workspace_id = "other".into(),
            _ => b.target.as_mut().unwrap().namespace_id = "other".into(),
        }
        assert_eq!(
            c.check(r).await.unwrap_err().code(),
            tonic::Code::PermissionDenied,
            "{field}"
        );
    }
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires explicit Linux/TLS fixture gate"]
async fn network_inspection_exact_bounded_wire_is_required() {
    let f = Fixture::start().await;
    let mut c = client(&f, Some(("trusted-host", CONTROLLER))).await;
    let mutations: &[fn(&mut proto::RuntimeNetworkInspectionRequest)] = &[
        |r| r.schema_version = 0,
        |r| r.schema_version = 2,
        |r| r.binding = None,
        |r| r.nonce = vec![1; 31],
        |r| r.nonce = vec![1; 33],
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
        let mut r = inspection();
        mutate(&mut r);
        assert_eq!(
            c.check(r).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    let mut r = inspection();
    r.nonce = vec![1; 8192];
    assert!(c.check(r).await.is_err());
    assert_eq!(f.callback.calls.load(Ordering::SeqCst), 0);
    f.stop().await;
}
