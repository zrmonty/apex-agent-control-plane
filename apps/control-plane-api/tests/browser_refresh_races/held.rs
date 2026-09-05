//! Authenticate held bytes without consuming either refresh token.
use super::{Decision, ISSUER, wire};
use crate::{
    fixture::{Fixture, WATCHDOG, within},
    session::now,
};
use apex_control_plane_api::browser::{
    bundle::SessionBundle,
    oidc::verify::{IdTokenExpectation, IdTokenVerifier},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::time::Instant;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

pub struct HeldReply {
    bytes: Zeroizing<Vec<u8>>,
    decision: oneshot::Sender<Decision>,
    completed_at: Instant,
}

pub struct ValidatedReply {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub signed_expiry: i64,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    refresh_token: String,
    id_token: String,
    token_type: String,
    expires_in: u64,
    refresh_expires_in: u64,
}
impl Drop for TokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

impl HeldReply {
    pub(super) fn new(
        bytes: Zeroizing<Vec<u8>>,
        decision: oneshot::Sender<Decision>,
        completed_at: Instant,
    ) -> Self {
        Self {
            bytes,
            decision,
            completed_at,
        }
    }

    pub async fn validate(
        &self,
        fixture: &Fixture,
        old: &SessionBundle,
        subject: &str,
    ) -> ValidatedReply {
        let material: TokenReply = serde_json::from_slice(&self.bytes).unwrap_or_else(|_| {
            panic!("real Keycloak refresh must include bounded token fields and an ID token")
        });
        assert!(material.token_type.eq_ignore_ascii_case("Bearer"));
        assert!((1..=3600).contains(&material.expires_in));
        assert!((1..=86400).contains(&material.refresh_expires_in));
        for token in [&material.access_token, &material.refresh_token] {
            assert!(!token.is_empty() && token.len() <= 4096);
            assert!(token.bytes().all(|byte| byte.is_ascii_graphic()));
        }
        assert!(!material.id_token.is_empty() && material.id_token.len() <= 16384);
        assert!(
            material.refresh_token != old.refresh.as_str(),
            "Keycloak must rotate the real token"
        );
        let caller = fixture
            .resolver
            .resolve(&material.access_token)
            .unwrap_or_else(|_| panic!("held access must pass the real Keycloak resolver"));
        assert!(caller.subject() == format!("operator:keycloak:{subject}"));
        let discovery = self
            .document(
                fixture,
                &format!("{ISSUER}/.well-known/openid-configuration"),
            )
            .await;
        fixture.config.validate_discovery(&discovery).unwrap();
        // The authentic discovery is checked first; it never selects this URL.
        let jwks = self
            .document(fixture, &format!("{ISSUER}/protocol/openid-connect/certs"))
            .await;
        let verifier = IdTokenVerifier::new(&fixture.config, &discovery, &jwks).unwrap();
        let identity = verifier
            .verify(
                &material.id_token,
                &material.access_token,
                IdTokenExpectation::Refresh {
                    subject,
                    original_nonce: old.nonce.expose_secret(),
                },
            )
            .unwrap();
        assert!(identity.subject == subject);
        assert!(identity.expires_at > now());
        // Parse only after the resolver has authenticated these exact bytes.
        let payload = material.access_token.split('.').nth(1).unwrap();
        let payload = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).unwrap());
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(claims["iss"].as_str() == Some(ISSUER));
        assert!(claims["sub"].as_str() == Some(subject));
        let signed_expiry = claims["exp"].as_i64().unwrap();
        assert!(signed_expiry > now());
        assert!(signed_expiry <= now() + 3600);
        self.check_deadline();
        ValidatedReply {
            access: Zeroizing::new(material.access_token.clone()),
            refresh: Zeroizing::new(material.refresh_token.clone()),
            signed_expiry,
        }
    }

    async fn document(&self, fixture: &Fixture, url: &str) -> Zeroizing<Vec<u8>> {
        let reply = within(async {
            let response = fixture
                .gate
                .client
                .get(url)
                .send()
                .await
                .unwrap_or_else(|_| {
                    panic!("held-reply verification requires genuine HTTPS metadata")
                });
            wire::read_reply(response)
                .await
                .expect("bounded authentic Keycloak metadata")
        })
        .await;
        assert_eq!(reply.status, 200);
        self.check_deadline();
        reply.body
    }

    fn check_deadline(&self) {
        assert!(
            self.completed_at.elapsed() < WATCHDOG,
            "release/drop must precede transport, provider and claim deadlines"
        );
    }

    pub fn release(self) {
        self.check_deadline();
        assert!(
            self.decision.send(Decision::Release).is_ok(),
            "held gate connection must remain live"
        );
    }

    pub fn lose_reply(self) {
        self.check_deadline();
        assert!(
            self.decision.send(Decision::Close).is_ok(),
            "held gate connection must remain live"
        );
    }
    // Dropping the one-shot sender closes the held downstream connection too.
}
