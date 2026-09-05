use super::{
    pki::{CONTROLLER, Pki},
    server::{Callback, CallbackState, Fixture, Ingress, IngressState, Listener, Settings},
    support::*,
};
use apex_proxy_runtime_agent::authority::{AuthorityClientError as Error, RuntimeAuthorityClient};
use std::{
    error::Error as _,
    sync::{Arc, Mutex, atomic::Ordering},
};
use tonic::Code;

#[tokio::test]
async fn malformed_configuration_is_bounded_and_redacted_before_transport() {
    // Catches URL normalization bypasses, inferred identity, unbounded PEM and parser leaks.
    let pki = Pki::require();
    let changes: &[fn(&mut apex_proxy_runtime_agent::authority::AuthorityClientConfig)] = &[
        |c| c.endpoint = "http://localhost".into(),
        |c| c.endpoint = "https:///localhost".into(),
        |c| c.endpoint = "https://user:authority-private-canary@localhost".into(),
        |c| c.endpoint = "https://@localhost".into(),
        |c| c.endpoint = "https://localhost/path".into(),
        |c| c.endpoint = "https://localhost/a/..".into(),
        |c| c.endpoint = "https://localhost?".into(),
        |c| c.endpoint = "https://localhost#".into(),
        |c| c.endpoint = "https://localhost\\path".into(),
        |c| c.endpoint = "https://localhost\n".into(),
        |c| c.endpoint = "x".repeat(2049),
        |c| c.tls_server_name.clear(),
        |c| c.tls_server_name = "x".repeat(254),
        |c| c.tls_server_name = "https://localhost".into(),
        |c| c.tls_server_name = "bad name".into(),
        |c| c.tls_server_name = "*.example.com".into(),
        |c| c.ca_pem.clear(),
        |c| c.client_certificate_pem.clear(),
        |c| c.client_key_pem.clear(),
        |c| c.ca_pem = vec![b'x'; 65_537],
        |c| c.client_certificate_pem = vec![b'x'; 65_537],
        |c| c.client_key_pem = vec![b'x'; 65_537],
        |c| c.installation_id = c.installation_id.to_uppercase(),
        |c| c.agent_identity_id.clear(),
        |c| c.agent_identity_id = "x".repeat(129),
        |c| c.enrollment_version = "..".into(),
        |c| c.enrollment_version = "x".repeat(129),
        |c| c.host_policy_version = "x/y".into(),
        |c| c.host_policy_version = "x".repeat(129),
    ];
    for change in changes {
        let mut settings = config(&pki, "https://127.0.0.1:1");
        change(&mut settings);
        assert!(!format!("{settings:?}").contains(CANARY));
        let error = within(RuntimeAuthorityClient::connect(settings))
            .await
            .unwrap_err();
        assert_eq!(error, Error::InvalidConfiguration);
        assert_eq!(format!("{error}"), error.code());
        assert_eq!(format!("{error:?}"), error.code());
        assert!(error.source().is_none());
    }
}

#[tokio::test]
async fn wrong_callback_ca_hostname_and_untrusted_or_malformed_identity_never_dispatch() {
    // Catches trust-store fallback, name verification bypass and optional client identity.
    let pki = Pki::require();
    let state = CallbackState::new();
    let callback = Listener::start(
        &pki,
        Callback {
            state: state.clone(),
            policy: policy(&pki, "client-policy", false),
        },
        false,
    );
    for (case, label) in [
        "wrong_callback_ca",
        "wrong_callback_hostname",
        "untrusted_client_identity",
        "malformed_client_key",
        "malformed_client_certificate",
    ]
    .into_iter()
    .enumerate()
    {
        let mut settings = config(&pki, &callback.endpoint);
        match case {
            0 => settings.ca_pem = pki.read("untrusted-host", "ca.pem"),
            1 => settings.tls_server_name = "wrong-name.invalid".into(),
            2 => {
                settings.client_certificate_pem =
                    pki.read("untrusted-host", &format!("{CONTROLLER}.pem"));
                settings.client_key_pem = pki.read("untrusted-host", &format!("{CONTROLLER}.key"));
            }
            3 => settings.client_key_pem = CANARY.as_bytes().to_vec(),
            4 => settings.client_certificate_pem = CANARY.as_bytes().to_vec(),
            _ => unreachable!(),
        }
        match within(RuntimeAuthorityClient::connect(settings)).await {
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        Error::Transport | Error::Unavailable | Error::InvalidConfiguration
                    ),
                    "{label}"
                );
                assert!(error.source().is_none(), "{label}");
                assert!(!format!("{error:?}").contains(CANARY), "{label}");
            }
            Ok(client) => {
                // In TLS 1.3 the client can finish its own flight before receiving
                // the server's client-certificate rejection alert. Tonic's ready
                // Channel is not proof that the server accepted that identity.
                assert_eq!(
                    case, 2,
                    "{label}: only remote client-identity rejection may arrive late"
                );
                let failure = through_real_ingress(&pki, client)
                    .await
                    .expect_err("untrusted_client_identity: real RPC must fail");
                assert_eq!(failure.code(), Code::Unavailable, "{label}");
                assert!(
                    matches!(
                        failure.message(),
                        "RUNTIME_AUTHORITY_CLIENT_TRANSPORT"
                            | "RUNTIME_AUTHORITY_CLIENT_UNAVAILABLE"
                    ),
                    "{label}: local admission denial, deadline or remote application refusal is not TLS proof"
                );
                assert!(failure.source().is_none(), "{label}");
                assert!(!format!("{failure:?}").contains(CANARY), "{label}");
            }
        }
        // Handler entry is counted before application pair authorization; an
        // application-role refusal cannot masquerade as transport rejection.
        assert_eq!(state.calls.load(Ordering::SeqCst), 0, "{label}");
    }
    // A full positive RPC on this exact callback prevents an inert listener passing.
    let client = within(RuntimeAuthorityClient::connect(config(
        &pki,
        &callback.endpoint,
    )))
    .await
    .unwrap();
    assert_eq!(
        through_real_ingress(&pki, client).await.unwrap(),
        snapshot()
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    callback.shutdown().await;
}

async fn through_real_ingress(
    pki: &Pki,
    client: RuntimeAuthorityClient,
) -> Result<apex_proxy_runtime_agent::proto::RuntimeAuthoritySnapshot, tonic::Status> {
    let state = Arc::new(IngressState {
        settings: Mutex::new(Settings {
            policy: policy(pki, "client-policy", false),
            budget: BUDGET,
            config_hash: HASH.into(),
        }),
        cancel: tokio::sync::Notify::new(),
    });
    let ingress = Listener::start(
        pki,
        Ingress {
            client: Arc::new(client),
            state,
        },
        false,
    );
    let mut controller = ingress_client(pki, &ingress.endpoint, Some(CONTROLLER)).await;
    let result = within(controller.check_runtime_authority(query()))
        .await
        .map(|r| r.into_inner());
    drop(controller);
    ingress.shutdown().await;
    result
}

#[tokio::test]
async fn remote_status_canaries_are_classified_without_retaining_sources_or_retrying() {
    // Catches bubbling Status diagnostics, conflating deadlines, and retrying refusals.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    for (index, (code, expected)) in [
        (Code::Unauthenticated, Error::Unauthenticated),
        (Code::PermissionDenied, Error::Denied),
        (Code::Unavailable, Error::Unavailable),
        (Code::DeadlineExceeded, Error::Deadline),
        (Code::ResourceExhausted, Error::RemoteRefusal),
        (Code::FailedPrecondition, Error::RemoteRefusal),
        (Code::InvalidArgument, Error::RemoteRefusal),
        (Code::Internal, Error::RemoteRefusal),
        (Code::Unknown, Error::RemoteRefusal),
    ]
    .into_iter()
    .enumerate()
    {
        *fixture.state.refusal.lock().unwrap() = Some(code);
        assert_error(
            within(caller.check_runtime_authority(query()))
                .await
                .unwrap_err(),
            expected,
        );
        assert_eq!(fixture.state.calls.load(Ordering::SeqCst), index + 1);
    }
    drop(caller);
    fixture.shutdown().await;
}

#[test]
fn errors_have_only_static_safe_envelope_codes() {
    // Catches accidental payload-bearing error variants or unstable display formatting.
    for error in [
        Error::InvalidConfiguration,
        Error::InvalidInput,
        Error::Unauthenticated,
        Error::Denied,
        Error::Transport,
        Error::Unavailable,
        Error::Overloaded,
        Error::Deadline,
        Error::RemoteRefusal,
        Error::InvalidSnapshot,
        Error::MismatchedSnapshot,
    ] {
        assert!(error.code().starts_with("RUNTIME_AUTHORITY_CLIENT_"));
        assert!(
            error
                .code()
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'_')
        );
        assert_eq!(format!("{error:?}"), error.code());
        assert_eq!(format!("{error}"), error.code());
        assert!(error.source().is_none());
    }
}
