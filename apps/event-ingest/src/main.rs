use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use apex_event_ingest::{
    ArchiveHttpPublisher, AsyncNatsJetStreamClient, AuthenticatedGrpcService,
    AuthenticatedHttpConfig, AuthenticatedIngestAdapter, BearerTokenResolver, BearerTokenVerifier,
    Caller, DurableFanoutPublisher, GatewayError, IngestGateway, NatsJetStreamTransport,
    NatsTlsConfig, RetryingDurableSink, RetryingJetStreamTransport, bounded_event_ingest_server,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

struct FileBearerResolver {
    token: String,
    scopes: Arc<HashSet<String>>,
}

const MAX_IDEMPOTENCY_CAPACITY: usize = 1_000_000;

impl BearerTokenResolver for FileBearerResolver {
    fn resolve(&self, token: &str) -> Result<Caller, apex_event_ingest::GatewayError> {
        if !constant_time_token_eq(token, &self.token) {
            return Err(apex_event_ingest::GatewayError::unauthenticated());
        }
        Ok(Caller::authenticated(
            "configured-file-token",
            self.scopes.iter().cloned(),
        ))
    }
}

fn constant_time_token_eq(left: &str, right: &str) -> bool {
    const MAX_TOKEN_BYTES: usize = 4096;
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    for index in 0..MAX_TOKEN_BYTES {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn required(name: &str) -> Result<String, io::Error> {
    env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required")))
}

fn startup_gateway_error(error: GatewayError) -> io::Error {
    let next_step = error
        .recommended_next_steps
        .first()
        .copied()
        .unwrap_or("Review the service configuration and diagnostic logs.");
    io::Error::other(format!(
        "{}: {} Cause: {} Next: {}",
        error.code.as_str(),
        error.summary,
        error.cause,
        next_step
    ))
}

fn path(name: &str) -> Result<PathBuf, io::Error> {
    Ok(PathBuf::from(required(name)?))
}

fn read_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unable to read {label}"),
        )
    })?;
    let mut bytes = Vec::with_capacity(max.saturating_add(1));
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unable to read {label}"),
            )
        })?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} has an invalid size"),
        ));
    }
    Ok(bytes)
}

fn read_token(path: &Path, label: &str) -> Result<String, io::Error> {
    let value = String::from_utf8(read_bounded(path, 4096, label)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{label} is not UTF-8")))?
        .trim()
        .to_owned();
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || !value.is_ascii()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains invalid characters"),
        ));
    }
    Ok(value)
}

fn trusted_secret_path(
    path: &Path,
    base: &Path,
    max: u64,
    _private: bool,
    label: &str,
) -> Result<PathBuf, io::Error> {
    if path.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must not be a symlink"),
        ));
    }
    let canonical_base = base.canonicalize().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted secret base is unavailable",
        )
    })?;
    let canonical = path.canonicalize().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is unavailable"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} metadata is unavailable"),
        )
    })?;
    if !canonical.starts_with(&canonical_base)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is outside the trusted secret policy"),
        ));
    }
    #[cfg(unix)]
    if _private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} permissions are too broad"),
            ));
        }
    }
    Ok(canonical)
}

fn optional_path(name: &str) -> Result<Option<PathBuf>, io::Error> {
    Ok(optional_path_value(env::var(name).ok().as_deref()))
}

fn attempts() -> Result<usize, io::Error> {
    attempts_value(env::var("APEX_RETRY_ATTEMPTS").ok().as_deref())
}

fn optional_path_value(value: Option<&str>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

fn attempts_value(value: Option<&str>) -> Result<usize, io::Error> {
    value
        .unwrap_or("3")
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_RETRY_ATTEMPTS must be an integer from 1 through 8",
            )
        })
        .and_then(|value| {
            if (1..=8).contains(&value) {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "APEX_RETRY_ATTEMPTS must be an integer from 1 through 8",
                ))
            }
        })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("APEX_ALLOW_IN_MEMORY_IDEMPOTENCY").as_deref() != Ok("true") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOW_IN_MEMORY_IDEMPOTENCY=true is required for the Phase 0 staging gateway; configure a durable idempotency store before production use",
        )
        .into());
    }
    let trusted_base = path("APEX_TRUSTED_SECRET_BASE")?;
    let retry_attempts = attempts()?;
    let nats_config = NatsTlsConfig {
        server_url: required("APEX_NATS_URL")?,
        ca_file: path("APEX_NATS_CA_FILE")?,
        client_cert_file: path("APEX_NATS_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_NATS_CLIENT_KEY_FILE")?,
        username_file: optional_path("APEX_NATS_USERNAME_FILE")?,
        password_file: optional_path("APEX_NATS_PASSWORD_FILE")?,
    };
    let nats = AsyncNatsJetStreamClient::connect(&nats_config, &trusted_base)
        .map_err(startup_gateway_error)?;
    let nats = NatsJetStreamTransport::new(nats, nats_config, &trusted_base)
        .map_err(startup_gateway_error)?;
    let nats =
        RetryingJetStreamTransport::new(nats, retry_attempts).map_err(startup_gateway_error)?;

    let http_base = AuthenticatedHttpConfig {
        endpoint: required("APEX_CLICKHOUSE_ENDPOINT")?,
        ca_file: path("APEX_CLICKHOUSE_CA_FILE")?,
        client_cert_file: path("APEX_CLICKHOUSE_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_CLICKHOUSE_CLIENT_KEY_FILE")?,
        bearer_token_file: optional_path("APEX_CLICKHOUSE_BEARER_FILE")?,
    };
    let clickhouse = apex_event_ingest::ClickHouseHttpPublisher::new(http_base, &trusted_base)
        .map_err(startup_gateway_error)?;
    let clickhouse =
        RetryingDurableSink::new(clickhouse, retry_attempts).map_err(startup_gateway_error)?;

    let archive_config = AuthenticatedHttpConfig {
        endpoint: required("APEX_ARCHIVE_ENDPOINT")?,
        ca_file: path("APEX_ARCHIVE_CA_FILE")?,
        client_cert_file: path("APEX_ARCHIVE_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_ARCHIVE_CLIENT_KEY_FILE")?,
        bearer_token_file: optional_path("APEX_ARCHIVE_BEARER_FILE")?,
    };
    let archive =
        ArchiveHttpPublisher::new(archive_config, &trusted_base).map_err(startup_gateway_error)?;
    let archive =
        RetryingDurableSink::new(archive, retry_attempts).map_err(startup_gateway_error)?;

    let fanout = DurableFanoutPublisher::new(nats, clickhouse, archive);
    let capacity = env::var("APEX_IDEMPOTENCY_CAPACITY")
        .unwrap_or_else(|_| "50000".to_owned())
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_IDEMPOTENCY_CAPACITY must be a positive integer",
            )
        })?;
    if capacity == 0 || capacity > MAX_IDEMPOTENCY_CAPACITY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_IDEMPOTENCY_CAPACITY must be between 1 and 1000000 for the in-memory staging store",
        )
        .into());
    }
    let gateway = IngestGateway::with_idempotency_capacity(fanout, capacity);
    let token_path = trusted_secret_path(
        &path("APEX_BEARER_TOKEN_FILE")?,
        &trusted_base,
        4096,
        true,
        "APEX_BEARER_TOKEN_FILE",
    )?;
    let token = read_token(&token_path, "APEX_BEARER_TOKEN_FILE")?;
    let scopes_value = required("APEX_ALLOWED_SCOPES")?;
    if scopes_value.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOWED_SCOPES is too large",
        )
        .into());
    }
    let scopes = scopes_value
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    if scopes.is_empty() || scopes.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOWED_SCOPES must contain between 1 and 1024 scopes",
        )
        .into());
    }
    if scopes.iter().any(|scope| !valid_scope(scope)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOWED_SCOPES contains an invalid scope",
        )
        .into());
    }
    let verifier = BearerTokenVerifier::new(FileBearerResolver {
        token,
        scopes: Arc::new(scopes),
    });
    let service = AuthenticatedGrpcService::new(AuthenticatedIngestAdapter::new(gateway), verifier);
    let server_cert_path = trusted_secret_path(
        &path("APEX_GATEWAY_SERVER_CERT_FILE")?,
        &trusted_base,
        1024 * 1024,
        false,
        "APEX_GATEWAY_SERVER_CERT_FILE",
    )?;
    let server_key_path = trusted_secret_path(
        &path("APEX_GATEWAY_SERVER_KEY_FILE")?,
        &trusted_base,
        1024 * 1024,
        true,
        "APEX_GATEWAY_SERVER_KEY_FILE",
    )?;
    let client_ca_path = trusted_secret_path(
        &path("APEX_GATEWAY_CLIENT_CA_FILE")?,
        &trusted_base,
        1024 * 1024,
        false,
        "APEX_GATEWAY_CLIENT_CA_FILE",
    )?;
    let server_cert = read_bounded(
        &server_cert_path,
        1024 * 1024,
        "APEX_GATEWAY_SERVER_CERT_FILE",
    )?;
    let server_key = read_bounded(
        &server_key_path,
        1024 * 1024,
        "APEX_GATEWAY_SERVER_KEY_FILE",
    )?;
    let client_ca = read_bounded(&client_ca_path, 1024 * 1024, "APEX_GATEWAY_CLIENT_CA_FILE")?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(client_ca));
    let listen = required("APEX_LISTEN_ADDR")?.parse()?;
    Server::builder()
        .tls_config(tls)?
        .add_service(bounded_event_ingest_server(service))
        .serve(listen)
        .await?;
    Ok(())
}

fn valid_scope(value: &str) -> bool {
    let Some((workspace, namespace)) = value.split_once('/') else {
        return false;
    };
    [workspace, namespace].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 256
            && !part.contains("..")
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        attempts_value, constant_time_token_eq, optional_path_value, read_bounded, read_token,
        required, startup_gateway_error, trusted_secret_path, valid_scope,
    };
    use apex_event_ingest::GatewayError;
    use std::fs;
    use std::path::Path;

    #[test]
    fn token_comparison_handles_length_boundaries_without_aliasing() {
        assert!(constant_time_token_eq("a", "a"));
        assert!(!constant_time_token_eq("a", "a\0"));
        assert!(!constant_time_token_eq(&"a".repeat(256), &"a".repeat(512)));
        assert!(!constant_time_token_eq(&"a".repeat(4096), "a"));
    }

    #[test]
    fn startup_errors_preserve_the_project_diagnostic_fields() {
        let error = startup_gateway_error(GatewayError::invalid_retry_configuration());
        let message = error.to_string();
        assert!(message.contains("INVALID_RETRY_CONFIGURATION"));
        assert!(message.contains("Cause:"));
        assert!(message.contains("Next:"));
    }

    #[test]
    fn scope_and_retry_configuration_reject_ambiguous_values() {
        assert!(valid_scope("workspace/namespace"));
        assert!(!valid_scope("workspace"));
        assert!(!valid_scope("workspace/"));
        assert!(!valid_scope("../namespace"));
        assert_eq!(attempts_value(None).unwrap(), 3);
        assert_eq!(attempts_value(Some("8")).unwrap(), 8);
        assert!(attempts_value(Some("0")).is_err());
        assert!(attempts_value(Some("not-a-number")).is_err());
    }

    #[test]
    fn bounded_file_and_environment_helpers_enforce_limits() {
        assert_eq!(
            optional_path_value(Some("relative/path")),
            Some(Path::new("relative/path").to_path_buf())
        );
        assert!(optional_path_value(Some("")).is_none());
        assert!(optional_path_value(None).is_none());

        let root = std::env::temp_dir().join(format!("apex-main-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        let file = root.join("secret");
        fs::write(&file, b"token\n").unwrap();
        assert_eq!(read_bounded(&file, 32, "secret").unwrap(), b"token\n");
        assert_eq!(read_token(&file, "token").unwrap(), "token");
        fs::write(&file, b"bad token").unwrap();
        assert!(read_token(&file, "token").is_err());
        assert!(trusted_secret_path(&file, &root, 32, false, "secret").is_ok());
        fs::write(&file, vec![0; 33]).unwrap();
        assert!(read_bounded(&file, 32, "secret").is_err());
        assert!(read_bounded(&root.join("missing"), 32, "secret").is_err());
        assert!(trusted_secret_path(&file, &root.join("outside"), 32, false, "secret").is_err());
        assert!(required("APEX_TEST_MISSING").is_err());
    }
}
