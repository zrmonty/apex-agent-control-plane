//! Fixed-endpoint, CA-pinned provider transport. Never an arbitrary URL client.
use super::{
    config::{OidcConfig, trusted_https_url},
    protocol::ProviderHttp,
};
use crate::browser::errors::BrowserError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oauth2::{HttpRequest, HttpResponse};
use reqwest::{
    Client, Method, StatusCode, Url,
    header::{
        ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap,
        HeaderName, HeaderValue, TRANSFER_ENCODING,
    },
};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};

mod dns;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INFLIGHT: usize = 8;
const MAX_REQUEST_BYTES: usize = 16384;
const MAX_RESPONSE_BYTES: usize = 65536;
const JSON_CONTENT_TYPE: &str = "application/json";
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

pub(super) struct BoundedProviderHttp {
    client: Client,
    discovery_uri: Url,
    jwks_uri: Url,
    token_uri: Url,
    revocation_uri: Url,
    basic_authorization: Zeroizing<String>,
    inflight: Semaphore,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Resource {
    Discovery,
    Jwks,
    Token,
    Revocation,
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn start() -> Result<Self, BrowserError> {
        Instant::now()
            .checked_add(CALL_TIMEOUT)
            .map(Self)
            .ok_or(BrowserError::Unavailable)
    }

    fn check(self) -> Result<(), BrowserError> {
        if Instant::now() >= self.0 {
            Err(BrowserError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl BoundedProviderHttp {
    pub(super) fn new(config: &OidcConfig) -> Result<Self, BrowserError> {
        Self::with_resolver(config, None)
    }

    fn with_resolver(
        config: &OidcConfig,
        resolver: Option<Arc<dns::Resolver>>,
    ) -> Result<Self, BrowserError> {
        config.validate()?;
        let certificates = reqwest::Certificate::from_pem_bundle(&config.provider_ca_pem)
            .map_err(|_| BrowserError::Unavailable)?;
        if certificates.is_empty() {
            return Err(BrowserError::Unavailable);
        }
        crate::install_rustls_provider();
        let builder = Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(certificates)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            // Reqwest retries some protocol errors by default, including POSTs.
            .retry(reqwest::retry::never())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connection_verbose(false)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(CALL_TIMEOUT)
            .pool_max_idle_per_host(MAX_INFLIGHT);
        let builder = match resolver {
            Some(resolver) => builder.dns_resolver(resolver),
            None => builder.dns_resolver(dns::global_resolver()?),
        };
        let client = builder.build().map_err(|_| BrowserError::Unavailable)?;
        // RFC 6749 Basic auth percent-encodes each credential before base64.
        let id: String =
            url::form_urlencoded::byte_serialize(config.client_id.as_bytes()).collect();
        let secret = Zeroizing::new(
            url::form_urlencoded::byte_serialize(config.client_secret.as_bytes())
                .collect::<String>(),
        );
        let credentials = Zeroizing::new(format!("{id}:{}", secret.as_str()));
        let mut basic_authorization = Zeroizing::new(String::from("Basic "));
        STANDARD.encode_string(credentials.as_bytes(), &mut basic_authorization);
        Ok(Self {
            client,
            discovery_uri: config.discovery_uri()?,
            jwks_uri: trusted_https_url(&config.jwks_uri)?,
            token_uri: trusted_https_url(&config.token_endpoint)?,
            revocation_uri: trusted_https_url(&config.revocation_endpoint)?,
            basic_authorization,
            inflight: Semaphore::new(MAX_INFLIGHT),
        })
    }

    pub(super) async fn discovery(&self) -> Result<Vec<u8>, BrowserError> {
        self.get(Resource::Discovery).await
    }

    pub(super) async fn jwks(&self) -> Result<Vec<u8>, BrowserError> {
        self.get(Resource::Jwks).await
    }

    async fn get(&self, resource: Resource) -> Result<Vec<u8>, BrowserError> {
        let deadline = Deadline::start()?;
        let uri = match resource {
            Resource::Discovery => &self.discovery_uri,
            Resource::Jwks => &self.jwks_uri,
            _ => return Err(BrowserError::Unavailable),
        };
        let request = self
            .client
            .get(uri.clone())
            .header(ACCEPT, JSON_CONTENT_TYPE)
            .build()
            .map_err(|_| BrowserError::Unavailable)?;
        self.execute(request, resource, deadline)
            .await
            .map(HttpResponse::into_body)
    }

    // Request-building seam for send; kept private and fixed-endpoint only.
    fn prepare_post(&self, request: HttpRequest) -> Result<reqwest::Request, BrowserError> {
        let (parts, body) = request.into_parts();
        let mut body = Zeroizing::new(body);
        if parts.method != Method::POST
            || body.len() > MAX_REQUEST_BYTES
            || parts.headers.len() != 3
        {
            return Err(BrowserError::Unavailable);
        }
        // Compare the literal request target before URL parsing could normalize
        // away escapes, dot paths or alternate spellings. Send the cached URL,
        // never the supplied URI. These URLs are the same canonical deployment
        // URLs used by oauth2's TokenUrl/RevocationUrl request builders.
        let target = parts.uri.to_string();
        let uri = if target == self.token_uri.as_str() {
            &self.token_uri
        } else if target == self.revocation_uri.as_str() {
            &self.revocation_uri
        } else {
            return Err(BrowserError::Unavailable);
        };
        let authorization = single_header(&parts.headers, AUTHORIZATION)?;
        if !bool::from(
            authorization
                .as_bytes()
                .ct_eq(self.basic_authorization.as_bytes()),
        ) || single_header(&parts.headers, ACCEPT)?.as_bytes() != JSON_CONTENT_TYPE.as_bytes()
            || single_header(&parts.headers, CONTENT_TYPE)?.as_bytes()
                != FORM_CONTENT_TYPE.as_bytes()
        {
            return Err(BrowserError::Unavailable);
        }
        // Neither headers nor extensions are copied from the input envelope.
        let mut authorization = HeaderValue::from_str(self.basic_authorization.as_str())
            .map_err(|_| BrowserError::Unavailable)?;
        authorization.set_sensitive(true);
        self.client
            .post(uri.clone())
            .header(AUTHORIZATION, authorization)
            .header(ACCEPT, JSON_CONTENT_TYPE)
            .header(CONTENT_TYPE, FORM_CONTENT_TYPE)
            .body(std::mem::take(&mut *body))
            .build()
            .map_err(|_| BrowserError::Unavailable)
    }

    async fn execute(
        &self,
        request: reqwest::Request,
        resource: Resource,
        deadline: Deadline,
    ) -> Result<HttpResponse, BrowserError> {
        deadline.check()?;
        // HTTP admission has no queue: cancellation drops the request future
        // and this permit, including a stalled body. Uncancellable OS DNS has
        // separate, process-wide worker-owned admission (see dns).
        let _permit = self
            .inflight
            .try_acquire()
            .map_err(|_| BrowserError::Unavailable)?;
        deadline.check()?;
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.0),
            self.exchange(request, resource, deadline),
        )
        .await;
        // timeout_at polls its inner future first. Buffered success on a late
        // poll must not win over the wall deadline. A rejected body is still
        // Zeroizing here, so dropping a late result clears our owned buffer.
        deadline.check()?;
        let (status, mut body) = result.map_err(|_| BrowserError::Unavailable)??;
        let mut response = HttpResponse::new(std::mem::take(&mut *body));
        *response.status_mut() = status;
        if !response.body().is_empty() {
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
        }
        if let Err(error) = deadline.check() {
            response.body_mut().zeroize();
            return Err(error);
        }
        Ok(response)
    }

    async fn exchange(
        &self,
        request: reqwest::Request,
        resource: Resource,
        deadline: Deadline,
    ) -> Result<(StatusCode, Zeroizing<Vec<u8>>), BrowserError> {
        deadline.check()?;
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(|_| BrowserError::Unavailable)?;
        deadline.check()?;
        let status = response.status();
        let is_metadata = matches!(resource, Resource::Discovery | Resource::Jwks);
        if status != StatusCode::OK
            && (is_metadata || !(status.is_client_error() || status.is_server_error()))
        {
            return Err(BrowserError::Unavailable);
        }
        let headers = response.headers();
        if headers.contains_key(CONTENT_ENCODING)
            || (headers.contains_key(CONTENT_LENGTH) && headers.contains_key(TRANSFER_ENCODING))
        {
            return Err(BrowserError::Unavailable);
        }
        if headers.contains_key(CONTENT_LENGTH) {
            let length = single_header(headers, CONTENT_LENGTH)?
                .to_str()
                .map_err(|_| BrowserError::Unavailable)?
                .parse::<u64>()
                .map_err(|_| BrowserError::Unavailable)?;
            if length > MAX_RESPONSE_BYTES as u64 {
                return Err(BrowserError::Unavailable);
            }
        }
        let empty_revocation = resource == Resource::Revocation && status == StatusCode::OK;
        let is_json = if headers.contains_key(CONTENT_TYPE) {
            single_header(headers, CONTENT_TYPE)?.as_bytes() == JSON_CONTENT_TYPE.as_bytes()
        } else {
            false
        };
        if !is_json && (!empty_revocation || headers.contains_key(CONTENT_TYPE)) {
            return Err(BrowserError::Unavailable);
        }
        let mut body = Zeroizing::new(Vec::new());
        loop {
            deadline.check()?;
            let chunk = response
                .chunk()
                .await
                .map_err(|_| BrowserError::Unavailable)?;
            deadline.check()?;
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
                return Err(BrowserError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        if !(empty_revocation && body.is_empty()) {
            if !is_json {
                return Err(BrowserError::Unavailable);
            }
            // OAuth's ordinary serde parser would otherwise silently accept
            // duplicate keys. Apply the shared strict gate before that library.
            crate::contract_json::parse_unique_json(&body)
                .map_err(|_| BrowserError::Unavailable)?;
        }
        deadline.check()?;
        Ok((status, body))
    }
}

impl ProviderHttp for BoundedProviderHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, BrowserError> {
        let deadline = Deadline::start()?;
        let request = self.prepare_post(request)?;
        let resource = if request.url() == &self.token_uri {
            Resource::Token
        } else {
            Resource::Revocation
        };
        self.execute(request, resource, deadline).await
    }
}

fn single_header(headers: &HeaderMap, name: HeaderName) -> Result<&HeaderValue, BrowserError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(BrowserError::Unavailable)?;
    if values.next().is_some() {
        return Err(BrowserError::Unavailable);
    }
    Ok(value)
}

impl fmt::Debug for BoundedProviderHttp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedProviderHttp([REDACTED])")
    }
}

#[cfg(test)]
mod child;
#[cfg(test)]
mod test_peer;
#[cfg(test)]
mod tests_child;
#[cfg(test)]
mod tests_dns;
#[cfg(test)]
mod tests_lifecycle;
#[cfg(test)]
mod tests_requests;
#[cfg(test)]
mod tests_responses;
