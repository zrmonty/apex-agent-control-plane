//! Synchronous worker facade for PostgreSQL with whole-operation deadlines.
//!
//! Construct, use, and drop this facade outside an asynchronous runtime context.
//! Requests exclusively borrow one connection; uncertain mutations are never retried.

use postgres::Row;
use postgres::types::ToSql;
use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
mod bootstrap;
mod endpoints;
mod resolver;

use bootstrap::BootstrapIo;
use resolver::Resolver;

const DEADLINE: Duration = Duration::from_secs(5);

/// Redacted transport failure, preserving PostgreSQL SQLSTATE for callers.
pub enum WorkerPostgresError {
    Database(postgres::Error),
    Deadline,
    Closed,
}

impl WorkerPostgresError {
    pub fn code(&self) -> Option<&postgres::error::SqlState> {
        match self {
            Self::Database(error) => error.code(),
            Self::Deadline | Self::Closed => None,
        }
    }
}

impl fmt::Debug for WorkerPostgresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => f.write_str("Database"),
            Self::Deadline => f.write_str("Deadline"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

impl fmt::Display for WorkerPostgresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database(_) => "PostgreSQL worker database operation failed",
            Self::Deadline => "PostgreSQL worker operation deadline exceeded",
            Self::Closed => "PostgreSQL worker connection unavailable",
        })
    }
}

// Do not expose the upstream error chain: it can contain SQL or failing-row data.
impl std::error::Error for WorkerPostgresError {}

pub struct WorkerPostgresClient {
    runtime: Runtime,
    client: Option<tokio_postgres::Client>,
    driver: Option<JoinHandle<()>>,
    transaction_depth: u32,
}

impl fmt::Debug for WorkerPostgresClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerPostgresClient")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl WorkerPostgresClient {
    pub fn connect(connection_string: &str) -> Result<Self, WorkerPostgresError> {
        Self::connect_with_policy(connection_string, super::plaintext_explicitly_allowed())
    }

    fn connect_with_policy(
        connection_string: &str,
        plaintext_allowed: bool,
    ) -> Result<Self, WorkerPostgresError> {
        let (_, mode) = super::parse_and_classify(connection_string, plaintext_allowed)
            .map_err(|_| WorkerPostgresError::Closed)?;
        // Both Config types use the same pinned tokio-postgres parser. Keep the
        // validated string private and preserve its configured startup options.
        let config: tokio_postgres::Config = connection_string
            .parse()
            .map_err(WorkerPostgresError::Database)?;
        Self::connect_config(config, mode, None)
    }

    fn connect_config(
        config: tokio_postgres::Config,
        mode: super::TransportMode,
        resolver: Option<&Resolver>,
    ) -> Result<Self, WorkerPostgresError> {
        Self::connect_config_with_loader(config, mode, resolver, super::load_ca_roots)
    }

    fn connect_config_with_loader(
        config: tokio_postgres::Config,
        mode: super::TransportMode,
        resolver: Option<&Resolver>,
        load_roots: impl FnOnce() -> Result<rustls::RootCertStore, ()> + Send + 'static,
    ) -> Result<Self, WorkerPostgresError> {
        Self::connect_config_with_bootstrap(config, mode, resolver, None, load_roots)
    }

    fn connect_config_with_bootstrap(
        mut config: tokio_postgres::Config,
        mode: super::TransportMode,
        resolver: Option<&Resolver>,
        bootstrap: Option<&BootstrapIo>,
        load_roots: impl FnOnce() -> Result<rustls::RootCertStore, ()> + Send + 'static,
    ) -> Result<Self, WorkerPostgresError> {
        let deadline = Instant::now() + DEADLINE;
        config
            .connect_timeout(DEADLINE)
            .tcp_user_timeout(DEADLINE)
            .keepalives(true)
            .keepalives_idle(DEADLINE)
            .keepalives_interval(Duration::from_secs(1))
            .keepalives_retries(3);
        let options = format!(
            "{} -c statement_timeout=5000 -c lock_timeout=2000",
            config.get_options().unwrap_or_default()
        );
        config.options(&options);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| WorkerPostgresError::Closed)?;
        let (client, driver) = runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                let tls = match mode {
                    super::TransportMode::LoopbackPlaintext => None,
                    super::TransportMode::VerifiedTls => {
                        let bootstrap = match bootstrap {
                            Some(executor) => executor,
                            None => bootstrap::global_bootstrap()?,
                        };
                        Some(bootstrap.load(load_roots, deadline).await?)
                    }
                };
                endpoints::connect(&config, resolver, tls, deadline).await
            })
            .await
            .map_err(|_| WorkerPostgresError::Deadline)?
        })?;
        Ok(Self {
            runtime,
            client: Some(client),
            driver: Some(driver),
            transaction_depth: 0,
        })
    }

    pub fn query(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, WorkerPostgresError> {
        let result = self
            .runtime
            .block_on(with_deadline(self.open_client()?.query(query, params)));
        self.complete(result)
    }

    pub fn execute(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, WorkerPostgresError> {
        let result = self
            .runtime
            .block_on(with_deadline(self.open_client()?.execute(query, params)));
        self.complete(result)
    }

    pub fn query_one(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, WorkerPostgresError> {
        let result = self
            .runtime
            .block_on(with_deadline(self.open_client()?.query_one(query, params)));
        self.complete(result)
    }

    pub fn query_opt(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, WorkerPostgresError> {
        let result = self
            .runtime
            .block_on(with_deadline(self.open_client()?.query_opt(query, params)));
        self.complete(result)
    }

    pub fn batch_execute(&mut self, query: &str) -> Result<(), WorkerPostgresError> {
        let result = self
            .runtime
            .block_on(with_deadline(self.open_client()?.batch_execute(query)));
        self.complete(result)
    }

    pub fn is_closed(&self) -> bool {
        self.client
            .as_ref()
            .is_none_or(tokio_postgres::Client::is_closed)
            || self.driver.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub fn transaction(&mut self) -> Result<WorkerPostgresTransaction<'_>, WorkerPostgresError> {
        let depth = self
            .transaction_depth
            .checked_add(1)
            .ok_or(WorkerPostgresError::Closed)?;
        if depth == 1 {
            self.batch_execute("BEGIN")?;
        } else {
            self.batch_execute(&format!("SAVEPOINT apex_worker_{depth}"))?;
        }
        self.transaction_depth = depth;
        Ok(WorkerPostgresTransaction {
            client: self,
            depth,
            finished: false,
        })
    }

    fn open_client(&self) -> Result<&tokio_postgres::Client, WorkerPostgresError> {
        if self.is_closed() {
            return Err(WorkerPostgresError::Closed);
        }
        self.client.as_ref().ok_or(WorkerPostgresError::Closed)
    }

    fn complete<T>(
        &mut self,
        result: Result<T, WorkerPostgresError>,
    ) -> Result<T, WorkerPostgresError> {
        if matches!(&result, Err(WorkerPostgresError::Deadline)) || self.is_closed() {
            self.close();
        }
        result
    }

    fn close(&mut self) {
        self.client.take();
        self.transaction_depth = 0;
        if let Some(driver) = self.driver.take() {
            driver.abort();
            // The socket belongs to the driver future. Await cancellation so it
            // is dropped before returning; never detach an outstanding request.
            self.runtime.block_on(async {
                let _ = driver.await;
            });
        }
    }
}

impl Drop for WorkerPostgresClient {
    fn drop(&mut self) {
        self.close();
    }
}

async fn with_deadline<T>(
    future: impl Future<Output = Result<T, postgres::Error>>,
) -> Result<T, WorkerPostgresError> {
    tokio::time::timeout(DEADLINE, future)
        .await
        .map_err(|_| WorkerPostgresError::Deadline)?
        .map_err(WorkerPostgresError::Database)
}

/// Exclusive transaction borrow; nesting creates a savepoint on the same connection.
#[derive(Debug)]
pub struct WorkerPostgresTransaction<'a> {
    client: &'a mut WorkerPostgresClient,
    depth: u32,
    finished: bool,
}

impl WorkerPostgresTransaction<'_> {
    pub fn query(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, WorkerPostgresError> {
        self.active_client()?.query(query, params)
    }

    pub fn execute(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, WorkerPostgresError> {
        self.active_client()?.execute(query, params)
    }

    pub fn query_one(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, WorkerPostgresError> {
        self.active_client()?.query_one(query, params)
    }

    pub fn query_opt(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, WorkerPostgresError> {
        self.active_client()?.query_opt(query, params)
    }

    pub fn batch_execute(&mut self, query: &str) -> Result<(), WorkerPostgresError> {
        self.active_client()?.batch_execute(query)
    }

    pub fn transaction(&mut self) -> Result<WorkerPostgresTransaction<'_>, WorkerPostgresError> {
        self.active_client()?.transaction()
    }

    pub fn commit(mut self) -> Result<(), WorkerPostgresError> {
        self.finish(true)
    }

    pub fn rollback(mut self) -> Result<(), WorkerPostgresError> {
        self.finish(false)
    }

    fn active_client(&mut self) -> Result<&mut WorkerPostgresClient, WorkerPostgresError> {
        if self.finished || self.depth != self.client.transaction_depth {
            self.client.close();
            return Err(WorkerPostgresError::Closed);
        }
        Ok(self.client)
    }

    fn finish(&mut self, commit: bool) -> Result<(), WorkerPostgresError> {
        self.active_client()?;
        // Consuming commit/rollback never triggers a second attempt from Drop.
        self.finished = true;
        let sql = match (self.depth, commit) {
            (1, true) => "COMMIT".to_owned(),
            (1, false) => "ROLLBACK".to_owned(),
            (depth, true) => format!("RELEASE SAVEPOINT apex_worker_{depth}"),
            (depth, false) => format!(
                "ROLLBACK TO SAVEPOINT apex_worker_{depth}; RELEASE SAVEPOINT apex_worker_{depth}"
            ),
        };
        let result = self.client.batch_execute(&sql);
        if result.is_ok() {
            self.client.transaction_depth -= 1;
        } else {
            // An unsuccessful finish leaves transaction state uncertain. The
            // connection must not escape for reuse by the parent or another job.
            self.client.close();
        }
        result
    }
}

impl Drop for WorkerPostgresTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(false);
        }
    }
}

#[cfg(test)]
mod tests;
