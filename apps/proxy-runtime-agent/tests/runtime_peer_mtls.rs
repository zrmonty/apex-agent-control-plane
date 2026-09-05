//! Real TLS prerequisite only: no runtime listener source, engine or PG authority.
//! Requires the existing APEX_BROWSER_TEST_PKI_DIR; never generates or skips PKI.

#[path = "runtime_peer_mtls/server.rs"]
mod server;
#[path = "runtime_peer_mtls/support.rs"]
mod support;

use apex_auth::RuntimePeerRole;
use serde_json::json;
use server::Server;
use support::*;
use tonic::Code;

#[tokio::test]
async fn authorized_controller_and_agent_reach_only_post_auth_test_actions() {
    let pki = Pki::require();
    let server = Server::start(&pki, &policy_document(&pki));
    let before = now_us();
    let controller = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let agent = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Method::Agent,
        Query::default(),
    )
    .await;
    let after = now_us();
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    controller.expect("authorized controller must pass the actual public TLS boundary");
    agent.expect("authorized agent must pass the actual public TLS boundary");
    assert_eq!(counts, (2, 2));
    assert_eq!(evidence.len(), 2);
    for (checked, identity, role) in [
        (&evidence[0], "test-controller", RuntimePeerRole::Controller),
        (&evidence[1], "test-agent", RuntimePeerRole::Agent),
    ] {
        assert_eq!(checked.identity, identity);
        assert_eq!(checked.role, role);
        assert_eq!(
            (
                &*checked.installation,
                &*checked.workspace,
                &*checked.namespace
            ),
            (INSTALL_A, "work", "ns")
        );
        assert_eq!(checked.version, "tls-policy-1");
        assert!(
            (before..=after).contains(&checked.checked_at),
            "same-process local time sample only"
        );
    }
}

#[tokio::test]
async fn no_certificate_and_wrong_ca_never_dispatch_to_the_policy_handler() {
    let pki = Pki::require();
    let server = Server::start(&pki, &policy_document(&pki));
    let positive = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let before = server.state.counts();
    let absent = invoke(
        &pki,
        &server.endpoint,
        None,
        Method::Controller,
        Query::default(),
    )
    .await;
    let wrong_ca = invoke(
        &pki,
        &server.endpoint,
        Some(("untrusted-host", CONTROLLER)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let after = server.state.counts();
    let positive_after = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Method::Agent,
        Query::default(),
    )
    .await;
    server.shutdown().await;
    positive.expect("positive transport/application control before TLS refusals");
    positive_after.expect("positive transport/application control after TLS refusals");
    absent.unwrap_err().assert_transport();
    wrong_ca.unwrap_err().assert_transport();
    assert_eq!(before, (1, 1));
    assert_eq!(after, before);
}

#[tokio::test]
async fn trusted_wrong_role_and_unknown_pin_cannot_reach_post_auth_actions() {
    let pki = Pki::require();
    let server = Server::start(&pki, &policy_document(&pki));
    let positive = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let wrong_role = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let other_direction = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Agent,
        Query::default(),
    )
    .await;
    let unknown = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", UNKNOWN)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let counts = server.state.counts();
    server.shutdown().await;
    positive.unwrap();
    for refusal in [wrong_role, other_direction, unknown] {
        refusal
            .unwrap_err()
            .assert_application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    }
    assert_eq!(counts, (4, 1));
}

#[tokio::test]
async fn actual_tls_exact_grants_do_not_expand_across_installations_or_scopes() {
    let pki = Pki::require();
    let server = Server::start(&pki, &policy_document(&pki));
    let first = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let second = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query {
            installation: INSTALL_B,
            workspace: "other",
            namespace: "space",
            spoof_identity: false,
        },
    )
    .await;
    let mut refusals = Vec::new();
    for (installation, workspace, namespace) in [
        (INSTALL_A, "other", "space"),
        (INSTALL_B, "work", "ns"),
        (INSTALL_A, "work", "space"),
        (INSTALL_A, "Work", "ns"),
    ] {
        refusals.push(
            invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", CONTROLLER)),
                Method::Controller,
                Query {
                    installation,
                    workspace,
                    namespace,
                    spoof_identity: false,
                },
            )
            .await,
        );
    }
    let counts = server.state.counts();
    server.shutdown().await;
    first.unwrap();
    second.unwrap();
    for refusal in refusals {
        refusal
            .unwrap_err()
            .assert_application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    }
    assert_eq!(counts, (6, 2));
}

#[tokio::test]
async fn revoked_actual_leaf_is_denied_while_distinct_authorized_agent_still_works() {
    let pki = Pki::require();
    let mut document = policy_document(&pki);
    document["peers"][0]["revoked"] = json!(true);
    let server = Server::start(&pki, &document);
    let refused = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query::default(),
    )
    .await;
    let positive = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Method::Agent,
        Query::default(),
    )
    .await;
    let counts = server.state.counts();
    server.shutdown().await;
    refused
        .unwrap_err()
        .assert_application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    positive.unwrap();
    assert_eq!(counts, (2, 1));
}

#[tokio::test]
async fn public_tls_check_uses_real_clock_and_rejects_expired_and_future_policy() {
    let pki = Pki::require();
    for future in [false, true] {
        let mut document = policy_document(&pki);
        let (from, until) = if future {
            let from = now_us().checked_add(86_400_000_000).unwrap();
            (from, from.checked_add(60_000_000).unwrap())
        } else {
            (1, 2)
        };
        document["validFromUnixUs"] = json!(from.to_string());
        document["expiresAtUnixUs"] = json!(until.to_string());
        let server = Server::start(&pki, &document);
        let refused = invoke(
            &pki,
            &server.endpoint,
            Some(("trusted-host", CONTROLLER)),
            Method::Controller,
            Query::default(),
        )
        .await;
        let counts = server.state.counts();
        server.shutdown().await;
        refused
            .unwrap_err()
            .assert_application(Code::FailedPrecondition, "RUNTIME_PEER_POLICY_NOT_CURRENT");
        assert_eq!(
            counts,
            (1, 0),
            "TLS reaches handler but time refusal prevents the action"
        );
    }
}

#[tokio::test]
async fn spoofed_identity_metadata_never_overrides_the_actual_tls_leaf() {
    let pki = Pki::require();
    let server = Server::start(&pki, &policy_document(&pki));
    let refused = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Method::Controller,
        Query {
            spoof_identity: true,
            ..Query::default()
        },
    )
    .await;
    let controller = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", CONTROLLER)),
        Method::Controller,
        Query {
            spoof_identity: true,
            ..Query::default()
        },
    )
    .await;
    let agent = invoke(
        &pki,
        &server.endpoint,
        Some(("trusted-host", AGENT)),
        Method::Agent,
        Query {
            spoof_identity: true,
            ..Query::default()
        },
    )
    .await;
    let counts = server.state.counts();
    let evidence = server.state.evidence();
    server.shutdown().await;
    refused
        .unwrap_err()
        .assert_application(Code::PermissionDenied, "RUNTIME_PEER_DENIED");
    controller.unwrap();
    agent.unwrap();
    assert_eq!(counts, (3, 2));
    assert_eq!(evidence[0].identity, "test-controller");
    assert_eq!(evidence[1].identity, "test-agent");
}

#[tokio::test]
async fn malformed_claimed_installation_or_scope_is_not_normalized_into_a_grant() {
    let pki = Pki::require();
    let server = Server::start(&pki, &policy_document(&pki));
    let mut outcomes = Vec::new();
    for query in [
        Query {
            installation: "*",
            ..Query::default()
        },
        Query {
            workspace: "work/ns",
            ..Query::default()
        },
        Query {
            namespace: "*",
            ..Query::default()
        },
    ] {
        outcomes.push(
            invoke(
                &pki,
                &server.endpoint,
                Some(("trusted-host", CONTROLLER)),
                Method::Controller,
                query,
            )
            .await,
        );
    }
    let counts = server.state.counts();
    server.shutdown().await;
    for outcome in outcomes {
        outcome
            .unwrap_err()
            .assert_application(Code::InvalidArgument, "RUNTIME_PEER_INVALID_SELECTOR");
    }
    assert_eq!(counts, (3, 0));
}
