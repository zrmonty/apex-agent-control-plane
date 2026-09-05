//! Actual TLS tests of the shared pair method, NOT the production callback.
//! Existing PKI required. No PostgreSQL, enrollment, runtime or effect succeeds.

#[path = "runtime_peer_pair/pki.rs"]
mod pki;
#[path = "runtime_peer_pair/server.rs"]
mod server;
#[path = "runtime_peer_pair/support.rs"]
mod support;

use pki::*;
use serde_json::json;
use server::Server;
use support::*;
use tonic::Code;

#[tokio::test]
async fn actual_agent_and_distinct_observed_controller_produce_only_local_pair_evidence() {
    let pki = Pki::require();
    let server = Server::start(&pki, &document(&pki));
    let before = now_us();
    let first = positive(&pki, &server.endpoint).await;
    let second = positive(&pki, &server.endpoint).await;
    let after = now_us();
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    assert_eq!(
        counts.0, 2,
        "both real TLS requests must reach the public pair method"
    );
    first.expect("valid pair must pass the public production pair check");
    second.unwrap();
    assert_eq!(counts.1, 2);
    for pair in evidence {
        assert_eq!(pair.agent, "pair-agent");
        assert_eq!(pair.observed_controller, "pair-controller");
        assert_eq!(pair.installation, INSTALL_A);
        assert_eq!(
            (pair.workspace.as_str(), pair.namespace.as_str()),
            ("work", "ns")
        );
        assert_eq!(pair.version, "pair-tls-policy");
        assert!(
            (before..=after).contains(&pair.checked),
            "local time sample only"
        );
        assert!(pair.debug.len() <= 128);
        for canary in [
            "pair-agent",
            "pair-controller",
            "pair-tls-policy",
            INSTALL_A,
            "work",
        ] {
            assert!(!pair.debug.contains(canary));
        }
    }
}

#[tokio::test]
async fn absent_certificate_and_wrong_ca_cannot_dispatch_to_pair_logic() {
    let pki = Pki::require();
    let server = Server::start(&pki, &document(&pki));
    let before = positive(&pki, &server.endpoint).await;
    let before_counts = server.state.counts();
    let absent = invoke(&pki, &server.endpoint, None, Query::valid(&pki)).await;
    let absent_counts = server.state.counts();
    let wrong_ca = invoke(
        &pki,
        &server.endpoint,
        Some(("untrusted-host", CONTROLLER)),
        Query::valid(&pki),
    )
    .await;
    let wrong_ca_counts = server.state.counts();
    let after = positive(&pki, &server.endpoint).await;
    let counts = server.state.counts();
    server.shutdown().await;
    before.expect("healthy otherwise-valid Agent control before TLS negatives");
    after.expect("healthy otherwise-valid Agent control after TLS negatives");
    assert_eq!(before_counts, (1, 1));
    assert_eq!(
        counts,
        (2, 2),
        "only the real Agent controls reach pair logic"
    );
    absent.unwrap_err().transport(before_counts, absent_counts);
    wrong_ca
        .unwrap_err()
        .transport(absent_counts, wrong_ca_counts);
}

#[tokio::test]
async fn trusted_controller_and_unknown_actual_leaf_cannot_assert_an_agent_role() {
    let pki = Pki::require();
    let server = Server::start(&pki, &document(&pki));
    let valid = positive(&pki, &server.endpoint).await;
    let mut denied = Vec::new();
    for caller in [CONTROLLER, OTHER] {
        denied.push(
            invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", caller)),
                Query::valid(&pki),
            )
            .await,
        );
    }
    let counts = server.state.counts();
    server.shutdown().await;
    assert_eq!(counts.0, 3);
    for outcome in denied {
        outcome
            .unwrap_err()
            .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    }
    valid.unwrap();
    assert_eq!(counts.1, 1);
}

#[tokio::test]
async fn revoked_agent_is_denied_while_an_explicit_distinct_agent_still_passes() {
    let pki = Pki::require();
    let mut doc = document(&pki);
    let mut spare = doc["peers"][0].clone();
    spare["certificateSha256"] = json!(hex(&pki.pin(OTHER)));
    spare["identityId"] = json!("pair-spare-agent");
    doc["peers"].as_array_mut().unwrap().push(spare);
    doc["peers"][0]["revoked"] = json!(true);
    let server = Server::start(&pki, &doc);
    let revoked = positive(&pki, &server.endpoint).await;
    let valid = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", OTHER)),
        Query::valid(&pki),
    )
    .await;
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    assert_eq!(counts.0, 2);
    revoked
        .unwrap_err()
        .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    valid.unwrap();
    assert_eq!(counts.1, 1);
    assert_eq!(evidence[0].agent, "pair-spare-agent");
}

#[tokio::test]
async fn observed_unknown_or_agent_leaf_never_becomes_a_controller() {
    let pki = Pki::require();
    let server = Server::start(&pki, &document(&pki));
    let valid = positive(&pki, &server.endpoint).await;
    let mut denied = Vec::new();
    for leaf in [AGENT, OTHER] {
        denied.push(
            invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", AGENT)),
                Query {
                    observed: pki.pin(leaf),
                    ..Query::valid(&pki)
                },
            )
            .await,
        );
    }
    let counts = server.state.counts();
    server.shutdown().await;
    assert_eq!(counts.0, 3);
    for outcome in denied {
        outcome
            .unwrap_err()
            .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    }
    valid.unwrap();
    assert_eq!(counts.1, 1);
}

#[tokio::test]
async fn observed_revoked_controller_refuses_without_revoking_its_approved_rotation() {
    let pki = Pki::require();
    let mut doc = document(&pki);
    let mut replacement = doc["peers"][1].clone();
    replacement["certificateSha256"] = json!(hex(&pki.pin(OTHER)));
    doc["peers"].as_array_mut().unwrap().push(replacement);
    doc["peers"][1]["revoked"] = json!(true);
    let server = Server::start(&pki, &doc);
    let revoked = positive(&pki, &server.endpoint).await;
    let valid = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Query {
            observed: pki.pin(OTHER),
            ..Query::valid(&pki)
        },
    )
    .await;
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    assert_eq!(counts.0, 2);
    revoked
        .unwrap_err()
        .application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    valid.unwrap();
    assert_eq!(counts.1, 1);
    assert_eq!(evidence[0].observed_controller, "pair-controller");
}

#[path = "runtime_peer_pair/policy_tests.rs"]
mod policy_tests;
