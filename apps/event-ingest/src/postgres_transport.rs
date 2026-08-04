//! Fail-closed PostgreSQL transport selection.
//!
//! PostgreSQL is durable security evidence storage. A remote connection must
//! therefore use TLS with certificate verification; a libpq `prefer` setting
//! is unsafe because it silently falls back to plaintext. The only plaintext
//! exception is an explicitly marked loopback-only development connection.

use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use postgres::config::{Host, SslMode};
use postgres::{Client, Config, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

const MAX_CONNECTION_STRING_BYTES: usize = 2048;
const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    LoopbackPlaintext,
    VerifiedTls,
}

/// Connect without allowing a remote plaintext or downgradeable PostgreSQL
/// session. The connection string is never included in an error because it
/// can contain database credentials.
pub(crate) fn connect(connection_string: &str) -> Result<Client, ()> {
    let config = parse_and_classify(connection_string)?;
    match config.1 {
        TransportMode::LoopbackPlaintext => config.0.connect(NoTls).map_err(|_| ()),
        TransportMode::VerifiedTls => {
            let roots = load_ca_roots()?;
            let tls = MakeRustlsConnect::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            config.0.connect(tls).map_err(|_| ())
        }
    }
}

fn parse_and_classify(connection_string: &str) -> Result<(Config, TransportMode), ()> {
    if connection_string.is_empty()
        || connection_string.len() > MAX_CONNECTION_STRING_BYTES
        || connection_string.chars().any(char::is_control)
    {
        return Err(());
    }
    let config = Config::from_str(connection_string).map_err(|_| ())?;
    match config.get_ssl_mode() {
        SslMode::Disable if loopback_hosts_only(&config) => {
            Ok((config, TransportMode::LoopbackPlaintext))
        }
        SslMode::Require => Ok((config, TransportMode::VerifiedTls)),
        // `prefer` can negotiate a plaintext session, while `disable` must
        // never be accepted for a remotely reachable database.
        _ => Err(()),
    }
}

fn loopback_hosts_only(config: &Config) -> bool {
    !config.get_hosts().is_empty()
        && config.get_hosts().iter().all(|host| match host {
            Host::Tcp(host) => host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback()),
            #[cfg(unix)]
            Host::Unix(_) => false,
        })
        && config.get_hostaddrs().iter().all(IpAddr::is_loopback)
}

fn load_ca_roots() -> Result<rustls::RootCertStore, ()> {
    let path = env::var("APEX_POSTGRES_CA_FILE").map_err(|_| ())?;
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(());
    }
    let path = PathBuf::from(path);
    if path.is_symlink() {
        return Err(());
    }
    let metadata = fs::metadata(&path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CA_FILE_BYTES {
        return Err(());
    }
    let pem = fs::read(path).map_err(|_| ())?;
    let mut reader = pem.as_slice();
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    if certificates.is_empty() {
        return Err(());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| ())?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::{TransportMode, parse_and_classify};

    #[test]
    fn allows_only_explicit_loopback_plaintext_for_local_development() {
        let (_, mode) =
            parse_and_classify("postgres://apex:local@127.0.0.1:5432/apex?sslmode=disable")
                .expect("loopback development transport");
        assert_eq!(mode, TransportMode::LoopbackPlaintext);
        assert!(
            parse_and_classify("postgres://apex:local@localhost:5432/apex?sslmode=disable")
                .is_err()
        );
        assert!(
            parse_and_classify("postgres://apex:local@10.0.0.9:5432/apex?sslmode=disable").is_err()
        );
    }

    #[test]
    fn rejects_downgradeable_ssl_modes_and_requires_verified_tls_remotely() {
        assert!(parse_and_classify("postgres://apex:secret@db.internal/apex").is_err());
        assert!(
            parse_and_classify("postgres://apex:secret@db.internal/apex?sslmode=prefer").is_err()
        );
        let (_, mode) =
            parse_and_classify("postgres://apex:secret@db.internal/apex?sslmode=require")
                .expect("remote TLS transport");
        assert_eq!(mode, TransportMode::VerifiedTls);
    }
}
