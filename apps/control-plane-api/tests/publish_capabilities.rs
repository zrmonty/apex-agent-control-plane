//! Publication boundary tests, not runtime/provider acceptance.
#![cfg(feature = "postgres")]

#[path = "publish_capabilities/contract.rs"]
mod contract;
#[path = "publish_capabilities/database.rs"]
mod database;
#[path = "publish_capabilities/fixtures.rs"]
mod fixtures;
#[path = "publish_capabilities/service.rs"]
mod service;

use apex_control_plane_api::{InMemoryProxyStore, PostgresProxyStore};
use database::Database;

#[test]
fn memory_rejects_unsupported_publication_without_mutation_and_keeps_drafts_editable() {
    contract::unsupported_publication(&InMemoryProxyStore::default(), || ());
}

#[test]
fn postgres_rejects_unsupported_publication_without_mutation_and_keeps_drafts_editable() {
    let database = Database::new();
    let store = PostgresProxyStore::connect(&database.url).unwrap();
    contract::unsupported_publication(&store, || database.snapshot());
}

#[test]
fn memory_supported_publication_preserves_immutable_spec_and_successful_replay() {
    contract::supported_replay(&InMemoryProxyStore::default(), || ());
}

#[test]
fn postgres_supported_publication_preserves_immutable_spec_and_successful_replay() {
    let database = Database::new();
    let store = PostgresProxyStore::connect(&database.url).unwrap();
    contract::supported_replay(&store, || database.snapshot());
}

#[test]
fn memory_scope_and_revision_conflicts_precede_capability_rejection() {
    contract::guard_precedence(&InMemoryProxyStore::default(), || ());
}

#[test]
fn postgres_scope_and_revision_conflicts_precede_capability_rejection() {
    let database = Database::new();
    let store = PostgresProxyStore::connect(&database.url).unwrap();
    contract::guard_precedence(&store, || database.snapshot());
}
