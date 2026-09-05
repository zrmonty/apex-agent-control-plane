//! Shared SQL surface for existing synchronous clients and deadline-bound worker
//! clients. Both execute the same authoritative SQL, scopes and transactions.
use postgres::{Row, types::ToSql};

use crate::postgres_transport::{
    WorkerPostgresClient, WorkerPostgresError, WorkerPostgresTransaction,
};

pub type PostgresClientError = WorkerPostgresError;
type Params<'a> = &'a [&'a (dyn ToSql + Sync)];
type Result<T> = std::result::Result<T, PostgresClientError>;

pub enum PostgresConnection {
    Standard(postgres::Client),
    Worker(WorkerPostgresClient),
}

impl PostgresConnection {
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Standard(client) => client.is_closed(),
            Self::Worker(client) => client.is_closed(),
        }
    }
}

pub enum PostgresTransaction<'a> {
    Standard(postgres::Transaction<'a>),
    Worker(WorkerPostgresTransaction<'a>),
}

impl PostgresTransaction<'_> {
    pub fn commit(self) -> Result<()> {
        match self {
            Self::Standard(tx) => tx.commit().map_err(PostgresClientError::Database),
            Self::Worker(tx) => tx.commit(),
        }
    }
    pub fn rollback(self) -> Result<()> {
        match self {
            Self::Standard(tx) => tx.rollback().map_err(PostgresClientError::Database),
            Self::Worker(tx) => tx.rollback(),
        }
    }
}

/// Narrow SQL adapter; callers still own exact-scope validation.
pub trait PostgresClientOps {
    fn query(&mut self, query: &str, params: Params<'_>) -> Result<Vec<Row>>;
    fn query_one(&mut self, query: &str, params: Params<'_>) -> Result<Row>;
    fn query_opt(&mut self, query: &str, params: Params<'_>) -> Result<Option<Row>>;
    fn execute(&mut self, query: &str, params: Params<'_>) -> Result<u64>;
    fn batch_execute(&mut self, query: &str) -> Result<()>;
    fn transaction(&mut self) -> Result<PostgresTransaction<'_>>;
}

macro_rules! sql_methods {
    () => {
        fn query(&mut self, query: &str, params: Params<'_>) -> Result<Vec<Row>> {
            match self {
                Self::Standard(client) => client
                    .query(query, params)
                    .map_err(PostgresClientError::Database),
                Self::Worker(client) => client.query(query, params),
            }
        }
        fn query_one(&mut self, query: &str, params: Params<'_>) -> Result<Row> {
            match self {
                Self::Standard(client) => client
                    .query_one(query, params)
                    .map_err(PostgresClientError::Database),
                Self::Worker(client) => client.query_one(query, params),
            }
        }
        fn query_opt(&mut self, query: &str, params: Params<'_>) -> Result<Option<Row>> {
            match self {
                Self::Standard(client) => client
                    .query_opt(query, params)
                    .map_err(PostgresClientError::Database),
                Self::Worker(client) => client.query_opt(query, params),
            }
        }
        fn execute(&mut self, query: &str, params: Params<'_>) -> Result<u64> {
            match self {
                Self::Standard(client) => client
                    .execute(query, params)
                    .map_err(PostgresClientError::Database),
                Self::Worker(client) => client.execute(query, params),
            }
        }
        fn batch_execute(&mut self, query: &str) -> Result<()> {
            match self {
                Self::Standard(client) => client
                    .batch_execute(query)
                    .map_err(PostgresClientError::Database),
                Self::Worker(client) => client.batch_execute(query),
            }
        }
        fn transaction(&mut self) -> Result<PostgresTransaction<'_>> {
            match self {
                Self::Standard(client) => client
                    .transaction()
                    .map(PostgresTransaction::Standard)
                    .map_err(PostgresClientError::Database),
                Self::Worker(client) => client.transaction().map(PostgresTransaction::Worker),
            }
        }
    };
}

impl PostgresClientOps for PostgresConnection {
    sql_methods!();
}
impl PostgresClientOps for PostgresTransaction<'_> {
    sql_methods!();
}

// Compatibility for existing tests and stores that intentionally use the
// original postgres client. They receive no implicit deadline/retry policy.
macro_rules! standard_client {
    ($client:ty) => {
        impl PostgresClientOps for $client {
            fn query(&mut self, query: &str, params: Params<'_>) -> Result<Vec<Row>> {
                postgres::GenericClient::query(self, query, params)
                    .map_err(PostgresClientError::Database)
            }
            fn query_one(&mut self, query: &str, params: Params<'_>) -> Result<Row> {
                postgres::GenericClient::query_one(self, query, params)
                    .map_err(PostgresClientError::Database)
            }
            fn query_opt(&mut self, query: &str, params: Params<'_>) -> Result<Option<Row>> {
                postgres::GenericClient::query_opt(self, query, params)
                    .map_err(PostgresClientError::Database)
            }
            fn execute(&mut self, query: &str, params: Params<'_>) -> Result<u64> {
                postgres::GenericClient::execute(self, query, params)
                    .map_err(PostgresClientError::Database)
            }
            fn batch_execute(&mut self, query: &str) -> Result<()> {
                postgres::GenericClient::batch_execute(self, query)
                    .map_err(PostgresClientError::Database)
            }
            fn transaction(&mut self) -> Result<PostgresTransaction<'_>> {
                postgres::GenericClient::transaction(self)
                    .map(PostgresTransaction::Standard)
                    .map_err(PostgresClientError::Database)
            }
        }
    };
}
standard_client!(postgres::Client);
standard_client!(postgres::Transaction<'_>);
