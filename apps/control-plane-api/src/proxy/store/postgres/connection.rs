//! Reconnect between calls, never replay a transaction with an uncertain result.
use std::sync::{Mutex, MutexGuard};

use apex_durability::{PostgresClientOps, PostgresConnection as Client};

use super::super::shared::configuration_error;
use crate::proxy::ProxyError;

const SESSION_SETTINGS: [&str; 2] = ["SET statement_timeout = '5s'", "SET lock_timeout = '2s'"];

pub(super) struct ProxyConnection {
    client: Mutex<Client>,
    // Deliberately no Debug/Display: this deployment value may contain credentials.
    connection_string: Box<str>,
}

impl ProxyConnection {
    pub(super) fn new(client: Client, connection_string: &str) -> Result<Self, ()> {
        let mut client = client;
        configure_session(&mut client)?;
        Ok(Self {
            client: Mutex::new(client),
            connection_string: connection_string.into(),
        })
    }

    pub(super) fn lock(&self) -> Result<MutexGuard<'_, Client>, ()> {
        self.reconnect(self.client.lock().map_err(|_| ())?)
    }

    pub(super) fn try_lock(&self) -> Result<MutexGuard<'_, Client>, ()> {
        self.reconnect(self.client.try_lock().map_err(|_| ())?)
    }

    pub(super) fn try_lock_checked(
        &self,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<MutexGuard<'_, Client>, ProxyError> {
        check()?;
        let mut client = self.client.try_lock().map_err(|_| configuration_error())?;
        if client.is_closed() {
            check()?;
            let mut replacement =
                apex_durability::connect_postgres_for_worker(&self.connection_string)
                    .map_err(|_| configuration_error())?;
            // A refusal during setup drops the replacement (and its owned
            // driver) before releasing the existing connection's lock.
            configure_session_checked(&mut replacement, check)?;
            *client = replacement;
        }
        check()?;
        Ok(client)
    }

    fn reconnect<'a>(
        &self,
        mut client: MutexGuard<'a, Client>,
    ) -> Result<MutexGuard<'a, Client>, ()> {
        if client.is_closed() {
            // The schema was migrated at startup. Reconnecting does not rerun DDL
            // or drop protection; a missing/incompatible schema fails each query.
            let mut replacement =
                apex_durability::connect_postgres_for_worker(&self.connection_string)?;
            configure_session(&mut replacement)?;
            *client = replacement;
        }
        Ok(client)
    }
}

fn configure_session(client: &mut Client) -> Result<(), ()> {
    // Bounds server-side query/lock waits on every connection. The relay also
    // permits only one blocking job at a time; network timeouts are transport policy.
    client
        .batch_execute(&SESSION_SETTINGS.join("; "))
        .map_err(|_| ())
}

fn configure_session_checked(
    client: &mut Client,
    check: &impl Fn() -> Result<(), ProxyError>,
) -> Result<(), ProxyError> {
    // The checked path must allow refusal between the two actual statements;
    // existing connection consumers retain their single setup batch above.
    for statement in SESSION_SETTINGS {
        check()?;
        client
            .batch_execute(statement)
            .map_err(|_| configuration_error())?;
    }
    check()?;
    Ok(())
}
