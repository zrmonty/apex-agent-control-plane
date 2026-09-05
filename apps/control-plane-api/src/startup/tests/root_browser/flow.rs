use super::{login, support};
use reqwest::{Client, Response};
use std::{net::SocketAddr, time::Duration};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
};
use zeroize::Zeroizing;

fn http() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}

fn no_store(response: &Response) {
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

async fn json(mut response: Response) -> serde_json::Value {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        assert!(
            body.len() + chunk.len() <= 1024 * 1024,
            "bounded browser response exceeded"
        );
        body.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&body).unwrap();
    for forbidden in ["access_token", "refresh_token", "id_token"] {
        assert!(!text.contains(forbidden));
    }
    serde_json::from_slice(&body).unwrap()
}

async fn health(control: SocketAddr, pki: &support::Pki, client_identity: bool) -> bool {
    let mut tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.trusted("ca.pem")));
    if client_identity {
        let key = Zeroizing::new(pki.trusted("control-operator-client.key"));
        tls = tls.identity(Identity::from_pem(
            pki.trusted("control-operator-client.pem"),
            key.as_slice(),
        ));
    }
    let endpoint = Endpoint::from_shared(format!("https://{control}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(2));
    let Ok(channel) = endpoint.connect().await else {
        return false;
    };
    // HTTP/2 connect can succeed before a TLS client-certificate failure is
    // surfaced. Require the actual authenticated health RPC, not connect alone.
    HealthClient::new(channel)
        .check(tonic::Request::new(HealthCheckRequest {
            service: "apex.v1.ControlGateway".into(),
        }))
        .await
        .is_ok_and(|reply| reply.into_inner().status == ServingStatus::Serving as i32)
}

pub(super) async fn control_ready(control: SocketAddr, pki: &support::Pki) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if health(control, pki, true).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("production mTLS health did not become ready");
}

pub(super) async fn live(control: SocketAddr, browser: SocketAddr, pki: &support::Pki) {
    let edge = format!("http://{browser}");
    let client = http();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(response) = client.get(format!("{edge}/api/session")).send().await
                && response.status() == 401
            {
                no_store(&response);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("production browser live-401 readiness was not observed");
    control_ready(control, pki).await;
    assert!(
        !health(control, pki, false).await,
        "dedicated control plane must require client mTLS"
    );
    let session = login::Browser::new(pki)
        .login(&edge, &support::required("APEX_BROWSER_KEYCLOAK_ISSUER"))
        .await;
    let response = client
        .get(format!("{edge}/api/session"))
        .header("cookie", &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    no_store(&response);
    let value = json(response).await;
    assert!(
        value["subject"]
            .as_str()
            .unwrap()
            .starts_with("operator:keycloak:")
    );
    assert_eq!(
        value["scopes"],
        serde_json::json!([{"workspaceId":"acme","namespaceId":"prod"}])
    );
    let csrf = Zeroizing::new(value["csrfToken"].as_str().unwrap().to_owned());
    let proxy_id = support::required(support::PROXY_ID);
    for (workspace, status) in [("acme", 200), ("unauthorized", 403)] {
        let response = client
            .post(format!("{edge}/api/apex/v1/McpProxyService/ListProxies"))
            .header("cookie", &session.cookie)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.as_str())
            .header(
                "authorization",
                "Bearer attacker-controlled-must-not-be-forwarded",
            )
            .json(&serde_json::json!({"workspaceId":workspace,"namespaceId":"prod"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        no_store(&response);
        let value = json(response).await;
        if status == 200 {
            let proxies = value["proxies"].as_array().unwrap();
            assert_eq!(
                proxies.len(),
                1,
                "actual service must read the seeded PG row"
            );
            assert_eq!(proxies[0]["proxyId"].as_str(), Some(proxy_id.as_str()));
        }
    }
    let replay = client
        .get(&session.callback)
        .header("cookie", &session.login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        401,
        "consumed real PKCE callback must not be reusable"
    );
    let response = client
        .post(format!("{edge}/auth/logout"))
        .header("cookie", &session.cookie)
        .header("origin", "https://console.example")
        .header("x-apex-csrf", csrf.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    no_store(&response);
    let response = client
        .get(format!("{edge}/api/session"))
        .header("cookie", &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "logged-out opaque session must be rejected"
    );
    no_store(&response);
}
