use super::BrowserError;
use crate::{OperatorCaller, OperatorCredentialResolver};
use std::{fmt, time::Duration};
use zeroize::Zeroizing;

/// Verified access credential, never an OIDC ID token or a gateway service token.
/// The production edge supplies its Keycloak access-token resolver. The tonic
/// handler independently authenticates this credential and its requested scope.
pub struct OperatorAccess {
    token: Zeroizing<String>,
    caller: OperatorCaller,
}

impl OperatorAccess {
    pub fn verify(
        token: Zeroizing<String>,
        resolver: &dyn OperatorCredentialResolver,
    ) -> Result<Self, BrowserError> {
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(BrowserError::Unauthenticated);
        }
        let caller = resolver
            .resolve(&token)
            .map_err(|error| BrowserError::from_credential_error(&error))?;
        Ok(Self { token, caller })
    }
    pub fn caller(&self) -> &OperatorCaller {
        &self.caller
    }
    pub(super) fn request<T>(
        &self,
        input: T,
        timeout: Duration,
    ) -> Result<tonic::Request<T>, BrowserError> {
        if !(Duration::from_millis(100)..=Duration::from_secs(30)).contains(&timeout) {
            return Err(BrowserError::InvalidRequest);
        }
        let mut request = tonic::Request::new(input);
        let wire = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let mut header: tonic::metadata::MetadataValue<_> =
            wire.parse().map_err(|_| BrowserError::Unauthenticated)?;
        header.set_sensitive(true);
        request.metadata_mut().insert("authorization", header);
        request.set_timeout(timeout);
        Ok(request)
    }
}

impl fmt::Debug for OperatorAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorAccess([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticOperatorTokenResolver;

    const TOKEN: &str = "verified-operator-test-credential";
    fn resolver() -> StaticOperatorTokenResolver {
        StaticOperatorTokenResolver::new().with_token(
            TOKEN,
            OperatorCaller::scoped("operator:test", ["work/ns"]).unwrap(),
        )
    }
    #[test]
    fn verifies_access_before_constructing_a_forwardable_credential() {
        let access = OperatorAccess::verify(Zeroizing::new(TOKEN.to_owned()), &resolver()).unwrap();
        assert_eq!(access.caller().subject(), "operator:test");
        assert!(access.caller().allows_scope("work", "ns"));
        assert!(!access.caller().allows_scope("other", "ns"));
        assert!(!format!("{access:?}").contains(TOKEN));
        for token in ["untrusted-operator-token", "ID-token", "mcp-service-token"] {
            assert!(matches!(
                OperatorAccess::verify(Zeroizing::new(token.to_owned()), &resolver()),
                Err(BrowserError::Unauthenticated)
            ));
        }
    }
    #[test]
    fn malformed_or_oversized_tokens_do_not_reach_the_resolver() {
        struct MustNotResolve;
        impl OperatorCredentialResolver for MustNotResolve {
            fn resolve(&self, _: &str) -> Result<OperatorCaller, crate::CommandError> {
                panic!("invalid token reached verifier")
            }
        }
        for token in [
            "".to_owned(),
            "x".repeat(4097),
            "Bearer value".to_owned(),
            "token\nInjected: yes".to_owned(),
            "token\tvalue".to_owned(),
            "token\u{007f}".to_owned(),
            "token-é".to_owned(),
        ] {
            assert!(matches!(
                OperatorAccess::verify(Zeroizing::new(token), &MustNotResolve),
                Err(BrowserError::Unauthenticated)
            ));
        }
    }
    #[test]
    fn fresh_metadata_contains_only_sensitive_operator_bearer_and_deadline() {
        let access = OperatorAccess::verify(Zeroizing::new(TOKEN.to_owned()), &resolver()).unwrap();
        let request = access
            .request("input", Duration::from_millis(1500))
            .unwrap();
        assert_eq!(request.get_ref(), &"input");
        let auth = request.metadata().get("authorization").unwrap();
        assert_eq!(auth.to_str().unwrap(), format!("Bearer {TOKEN}"));
        assert!(auth.is_sensitive());
        assert_eq!(request.metadata().len(), 2);
        assert!(request.metadata().get("grpc-timeout").is_some());
        assert!(!format!("{:?}", request.metadata()).contains(TOKEN));
    }
    #[test]
    fn forwarded_deadline_is_bounded_and_never_omitted() {
        let access = OperatorAccess::verify(Zeroizing::new(TOKEN.to_owned()), &resolver()).unwrap();
        for duration in [
            Duration::ZERO,
            Duration::from_millis(99),
            Duration::from_secs(31),
        ] {
            assert!(matches!(
                access.request((), duration),
                Err(BrowserError::InvalidRequest)
            ));
        }
        for duration in [Duration::from_millis(100), Duration::from_secs(30)] {
            assert!(access.request((), duration).is_ok());
        }
    }

    #[test]
    fn verifier_outage_is_distinct_from_an_invalid_access_token() {
        struct Unavailable;
        impl OperatorCredentialResolver for Unavailable {
            fn resolve(&self, _: &str) -> Result<OperatorCaller, crate::CommandError> {
                Err(crate::CommandError::credential_verifier_unavailable())
            }
        }
        assert!(matches!(
            OperatorAccess::verify(Zeroizing::new(TOKEN.to_owned()), &Unavailable),
            Err(BrowserError::Unavailable)
        ));
    }
}
