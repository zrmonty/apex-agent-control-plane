//! Lazy host attempts preserving hostname/address/port and load-balancing policy.

use super::resolver::{Resolver, global_resolver};
use super::{DEADLINE, WorkerPostgresError};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_postgres::config::{Host, LoadBalanceHosts};
use tokio_postgres_rustls::MakeRustlsConnect;

pub(super) async fn connect(
    config: &tokio_postgres::Config,
    resolver: Option<&Resolver>,
    tls: Option<MakeRustlsConnect>,
    deadline: Instant,
) -> Result<(tokio_postgres::Client, JoinHandle<()>), WorkerPostgresError> {
    let mut last_error = WorkerPostgresError::Closed;
    // Resolve only the host whose turn it is. A working primary never depends
    // on backup DNS; random mode shuffles host groups, not all addresses at once.
    for index in host_indices(config)? {
        check_deadline(deadline)?;
        let resolved = match resolve_host(config, index, resolver, deadline).await {
            Ok(config) => config,
            Err(WorkerPostgresError::Deadline) => return Err(WorkerPostgresError::Deadline),
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        for address_index in host_indices(&resolved)? {
            let attempt = endpoint(&resolved, address_index);
            // All TCP endpoints now have numeric hostaddr. Tokio never submits
            // blocking DNS, and each address attempt checks the original budget.
            check_deadline(deadline)?;
            match connect_once(&attempt, tls.as_ref()).await {
                Ok(connected) => return Ok(connected),
                Err(error) => last_error = error,
            }
        }
    }
    check_deadline(deadline)?;
    Err(last_error)
}

fn check_deadline(deadline: Instant) -> Result<(), WorkerPostgresError> {
    if Instant::now() >= deadline {
        Err(WorkerPostgresError::Deadline)
    } else {
        Ok(())
    }
}

fn host_indices(config: &tokio_postgres::Config) -> Result<Vec<usize>, WorkerPostgresError> {
    let hosts = config.get_hosts().len();
    let addresses = config.get_hostaddrs().len();
    let count = hosts.max(addresses);
    if count == 0
        || (hosts != 0 && addresses != 0 && hosts != addresses)
        || (config.get_ports().len() > 1 && config.get_ports().len() != count)
    {
        return Err(WorkerPostgresError::Closed);
    }
    let mut indices: Vec<_> = (0..count).collect();
    if config.get_load_balance_hosts() == LoadBalanceHosts::Random {
        for index in (1..indices.len()).rev() {
            let mut random = [0; size_of::<usize>()];
            getrandom::fill(&mut random).map_err(|_| WorkerPostgresError::Closed)?;
            indices.swap(index, usize::from_ne_bytes(random) % (index + 1));
        }
    }
    Ok(indices)
}

async fn connect_once(
    config: &tokio_postgres::Config,
    tls: Option<&MakeRustlsConnect>,
) -> Result<(tokio_postgres::Client, JoinHandle<()>), WorkerPostgresError> {
    match tls {
        None => {
            let (client, connection) = config
                .connect(tokio_postgres::NoTls)
                .await
                .map_err(WorkerPostgresError::Database)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, driver))
        }
        Some(tls) => {
            let (client, connection) = config
                .connect(tls.clone())
                .await
                .map_err(WorkerPostgresError::Database)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, driver))
        }
    }
}

pub(super) async fn resolve_host(
    config: &tokio_postgres::Config,
    index: usize,
    resolver: Option<&Resolver>,
    deadline: Instant,
) -> Result<tokio_postgres::Config, WorkerPostgresError> {
    check_deadline(deadline)?;
    // Explicit hostaddr keeps the corresponding original hostname/SNI intact.
    if config.get_hostaddrs().get(index).is_some() {
        return Ok(endpoint(config, index));
    }
    let host = config
        .get_hosts()
        .get(index)
        .ok_or(WorkerPostgresError::Closed)?;
    #[cfg(not(unix))]
    let Host::Tcp(hostname) = host;
    #[cfg(unix)]
    let hostname = match host {
        Host::Tcp(hostname) => hostname,
        // Preserve the original Unix endpoint, including native TLS rejection.
        Host::Unix(_) => return Ok(endpoint(config, index)),
    };
    let addresses = match hostname.parse::<IpAddr>() {
        Ok(address) => vec![address],
        Err(_) => {
            let resolver = match resolver {
                Some(resolver) => resolver,
                None => global_resolver()?,
            };
            resolver.lookup(hostname, deadline).await?
        }
    };
    check_deadline(deadline)?;
    if addresses.is_empty() {
        return Err(WorkerPostgresError::Closed);
    }
    let mut resolved = config_without_endpoints(config);
    for address in addresses {
        resolved
            .host(hostname)
            .hostaddr(address)
            .port(port(config, index));
    }
    Ok(resolved)
}

fn port(config: &tokio_postgres::Config, index: usize) -> u16 {
    config
        .get_ports()
        .get(index)
        .or_else(|| config.get_ports().first())
        .copied()
        .unwrap_or(5432)
}

fn endpoint(config: &tokio_postgres::Config, index: usize) -> tokio_postgres::Config {
    let mut result = config_without_endpoints(config);
    match config.get_hosts().get(index) {
        Some(Host::Tcp(host)) => {
            result.host(host);
        }
        #[cfg(unix)]
        Some(Host::Unix(path)) => {
            result.host_path(path);
        }
        None => {}
    }
    if let Some(address) = config.get_hostaddrs().get(index) {
        result.hostaddr(*address);
    }
    result.port(port(config, index));
    result
}

// Config has additive endpoint setters only. Copy every non-endpoint setting
// exposed by the pinned 0.7.18 API when selecting a host or expanding its DNS address pairs.
fn config_without_endpoints(config: &tokio_postgres::Config) -> tokio_postgres::Config {
    let mut result = tokio_postgres::Config::new();
    if let Some(user) = config.get_user() {
        result.user(user);
    }
    if let Some(password) = config.get_password() {
        result.password(password);
    }
    if let Some(database) = config.get_dbname() {
        result.dbname(database);
    }
    if let Some(options) = config.get_options() {
        result.options(options);
    }
    if let Some(application) = config.get_application_name() {
        result.application_name(application);
    }
    result
        .ssl_mode(config.get_ssl_mode())
        .ssl_negotiation(config.get_ssl_negotiation())
        .channel_binding(config.get_channel_binding())
        .target_session_attrs(config.get_target_session_attrs())
        .load_balance_hosts(config.get_load_balance_hosts())
        .connect_timeout(DEADLINE)
        .tcp_user_timeout(DEADLINE)
        .keepalives(true)
        .keepalives_idle(DEADLINE)
        .keepalives_interval(Duration::from_secs(1))
        .keepalives_retries(3);
    result
}
