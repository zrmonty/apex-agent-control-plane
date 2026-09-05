use super::*;

#[tokio::test]
async fn either_peers_wrong_installation_workspace_or_namespace_prevents_pairing() {
    let pki = Pki::require();
    for index in [0, 1] {
        for wrong in [
            grant(INSTALL_B, "work", "ns"),
            grant(INSTALL_A, "other", "ns"),
            grant(INSTALL_A, "work", "other"),
        ] {
            let mut doc = document(&pki);
            for entry in [0, 1] {
                doc["peers"][entry]["grants"]
                    .as_array_mut()
                    .unwrap()
                    .push(grant(INSTALL_B, "other", "space"));
            }
            doc["peers"][index]["grants"][0] = wrong;
            let server = Server::start(&pki, &doc);
            let denied = positive(&pki, &server.endpoint).await;
            let valid = invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", AGENT)),
                Query {
                    installation: INSTALL_B,
                    workspace: "other",
                    namespace: "space",
                    ..Query::valid(&pki)
                },
            )
            .await;
            let counts = server.state.counts();
            server.shutdown().await;
            assert_eq!(counts.0, 2);
            denied
                .unwrap_err()
                .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
            valid.unwrap();
            assert_eq!(counts.1, 1);
        }
    }
}

#[tokio::test]
async fn two_exact_shared_grants_do_not_authorize_their_cartesian_product() {
    let pki = Pki::require();
    let mut doc = document(&pki);
    for entry in [0, 1] {
        doc["peers"][entry]["grants"]
            .as_array_mut()
            .unwrap()
            .push(grant(INSTALL_B, "other", "space"));
    }
    let server = Server::start(&pki, &doc);
    let first = positive(&pki, &server.endpoint).await;
    let second = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Query {
            installation: INSTALL_B,
            workspace: "other",
            namespace: "space",
            ..Query::valid(&pki)
        },
    )
    .await;
    let mut denied = Vec::new();
    for (installation, workspace, namespace) in [
        (INSTALL_A, "other", "space"),
        (INSTALL_B, "work", "ns"),
        (INSTALL_A, "work", "space"),
    ] {
        denied.push(
            invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", AGENT)),
                Query {
                    installation,
                    workspace,
                    namespace,
                    ..Query::valid(&pki)
                },
            )
            .await,
        );
    }
    let counts = server.state.counts();
    server.shutdown().await;
    assert_eq!(counts.0, 5);
    for outcome in denied {
        outcome
            .unwrap_err()
            .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    }
    first.unwrap();
    second.unwrap();
    assert_eq!(counts.1, 2);
}

#[tokio::test]
async fn public_pair_checks_real_time_for_expired_and_future_policy() {
    let pki = Pki::require();
    for future in [false, true] {
        let mut doc = document(&pki);
        let (from, until) = if future {
            let from = now_us().checked_add(86_400_000_000).unwrap();
            (from, from.checked_add(60_000_000).unwrap())
        } else {
            (1, 2)
        };
        doc["validFromUnixUs"] = json!(from.to_string());
        doc["expiresAtUnixUs"] = json!(until.to_string());
        let server = Server::start(&pki, &doc);
        let denied = positive(&pki, &server.endpoint).await;
        let counts = server.state.counts();
        server.shutdown().await;
        assert_eq!(counts, (1, 0), "valid TLS must reach the pair time check");
        denied
            .unwrap_err()
            .application(Code::FailedPrecondition, "RUNTIME_PEER_POLICY_NOT_CURRENT");
    }
}

#[tokio::test]
async fn spoofed_metadata_cannot_replace_actual_tls_agent_identity() {
    let pki = Pki::require();
    let server = Server::start(&pki, &document(&pki));
    let denied = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Query {
            spoof: true,
            ..Query::valid(&pki)
        },
    )
    .await;
    let valid = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Query {
            spoof: true,
            ..Query::valid(&pki)
        },
    )
    .await;
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    assert_eq!(counts.0, 2);
    denied
        .unwrap_err()
        .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    valid.unwrap();
    assert_eq!(counts.1, 1);
    assert_eq!(evidence[0].agent, "pair-agent");
}

#[tokio::test]
async fn approved_rotation_of_actual_agent_and_observed_controller_preserves_both_ids() {
    let pki = Pki::require();
    let mut doc = document(&pki);
    for (index, leaf) in [(0, OTHER), (1, "control-plane-server")] {
        let mut rotated = doc["peers"][index].clone();
        rotated["certificateSha256"] = json!(hex(&pki.pin(leaf)));
        doc["peers"].as_array_mut().unwrap().push(rotated);
    }
    let server = Server::start(&pki, &doc);
    let mut results = Vec::new();
    for agent in [AGENT, OTHER] {
        for controller in [CONTROLLER, "control-plane-server"] {
            results.push(
                invoke(
                    &pki,
                    &server.endpoint,
                    Some(("trusted-host", agent)),
                    Query {
                        observed: pki.pin(controller),
                        ..Query::valid(&pki)
                    },
                )
                .await,
            );
        }
    }
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    assert_eq!(counts.0, 4);
    for result in results {
        result.unwrap();
    }
    assert_eq!(counts.1, 4);
    for pair in evidence {
        assert_eq!(
            (pair.agent.as_str(), pair.observed_controller.as_str()),
            ("pair-agent", "pair-controller")
        );
    }
}

#[tokio::test]
async fn malformed_wire_selectors_reach_pair_refusal_without_normalization() {
    let pki = Pki::require();
    let server = Server::start(&pki, &document(&pki));
    let valid = positive(&pki, &server.endpoint).await;
    let mut denied = Vec::new();
    for (installation, workspace, namespace) in [
        ("*", "work", "ns"),
        (INSTALL_A, "work/ns", "ns"),
        (INSTALL_A, "work", "*"),
    ] {
        denied.push(
            invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", AGENT)),
                Query {
                    installation,
                    workspace,
                    namespace,
                    ..Query::valid(&pki)
                },
            )
            .await,
        );
    }
    let counts = server.state.counts();
    server.shutdown().await;
    assert_eq!(counts.0, 4);
    for outcome in denied {
        outcome
            .unwrap_err()
            .application(Code::InvalidArgument, "RUNTIME_PEER_INVALID_SELECTOR");
    }
    valid.unwrap();
    assert_eq!(counts.1, 1);
}
