use super::*;

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_refuses_wrong_configuration_identity_and_exact_scope_before_dispatch() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::Good);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        for mode in 0..4 {
            let mut config = fixture.config(&pki, pki::CONTROLLER);
            match mode {
                0 => config.installation_id = "0191b7f1-7f2c-7c13-9a61-2f29f2be1099".into(),
                1 => config.scopes.clear(),
                2 => config.scopes[0].namespace_id = "other".into(),
                3 => {
                    config.scopes = vec![
                        crate::ExactScope {
                            workspace_id: "acme".into(),
                            namespace_id: "other".into(),
                        },
                        crate::ExactScope {
                            workspace_id: "other".into(),
                            namespace_id: "prod".into(),
                        },
                    ]
                }
                _ => unreachable!(),
            }
            let mut client = RuntimeExecutionClient::connect(&config, deadline())
                .await
                .unwrap();
            let (request, observed) = inputs();
            assert!(
                client
                    .observe_health(&request, &observed, deadline(), &|| Ok(()))
                    .await
                    .is_err(),
                "mode {mode}"
            );
        }
    });
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_refuses_invalid_original_request_and_attestation_before_dispatch() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::Good);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut client =
            RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                .await
                .unwrap();
        for mode in 0..18 {
            let (mut request, mut observed) = inputs();
            match mode {
                0 => request.schema_version = 0,
                1 => request.operation_id.clear(),
                2 => request.command_id = "arbitrary-command".into(),
                3 => request.config_hash = "A".repeat(64),
                4 => request.target = None,
                5 => request.target.as_mut().unwrap().workspace_id = "a".repeat(5000),
                6 => request.target.as_mut().unwrap().generation = u64::MAX,
                7 => request.target.as_mut().unwrap().fencing_token = u64::MAX,
                8 => request.target.as_mut().unwrap().proxy_id = "not-a-uuid".into(),
                9 => observed.runtime = None,
                10 => observed.runtime.as_mut().unwrap().launch_attestation = None,
                11 => {
                    observed
                        .runtime
                        .as_mut()
                        .unwrap()
                        .launch_attestation
                        .as_mut()
                        .unwrap()
                        .launch = None
                }
                12 => observed.runtime.as_mut().unwrap().runtime_id.clear(),
                13 => {
                    observed
                        .runtime
                        .as_mut()
                        .unwrap()
                        .launch_attestation
                        .as_mut()
                        .unwrap()
                        .schema_version = 0
                }
                14 => observed
                    .runtime
                    .as_mut()
                    .unwrap()
                    .launch_attestation
                    .as_mut()
                    .unwrap()
                    .launch
                    .as_mut()
                    .unwrap()
                    .launch_context_hash
                    .clear(),
                15 => observed.runtime.as_mut().unwrap().admitting = true,
                16 => observed
                    .runtime
                    .as_mut()
                    .unwrap()
                    .launch_attestation
                    .as_mut()
                    .unwrap()
                    .image_id
                    .clear(),
                17 => {
                    observed
                        .runtime
                        .as_mut()
                        .unwrap()
                        .launch_attestation
                        .as_mut()
                        .unwrap()
                        .installation_id = "0191b7f1-7f2c-7c13-9a61-2f29f2be1099".into()
                }
                _ => unreachable!(),
            }
            observed.claims = Some(request.clone());
            assert!(
                client
                    .observe_health(&request, &observed, deadline(), &|| Ok(()))
                    .await
                    .is_err(),
                "mode {mode}"
            );
        }
    });
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_rejects_actual_wrong_mtls_peer_before_health_dispatch() {
    let pki = pki::Pki::require();
    let fixture = Fixture::new(&pki, Mode::Good);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut client =
            RuntimeExecutionClient::connect(&fixture.config(&pki, pki::OTHER), deadline())
                .await
                .unwrap();
        let (request, observed) = inputs();
        assert!(
            client
                .observe_health(&request, &observed, deadline(), &|| Ok(()))
                .await
                .is_err()
        );
    });
    assert!(fixture.requests.lock().unwrap().is_empty());
}
