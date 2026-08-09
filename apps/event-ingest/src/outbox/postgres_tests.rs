#![cfg(all(test, feature = "postgres"))]

use super::postgres::PostgresOutbox;
use super::types::{EnqueueResult, EventOutbox, OutboxKey};
use crate::{IngestRequest, proto};
use prost::Message;

include!("postgres_tests_cases.rs");
include!("postgres_tests_concurrency.rs");
