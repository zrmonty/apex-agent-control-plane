use super::*;

// The SQL batch has one catalog validator for both newly created and existing
// version-2 storage. Existing storage never takes its DDL branch; v1 is refused.
pub(super) fn ensure(
    client: &mut PostgresConnection,
    allow_create: bool,
) -> Result<(), BrowserError> {
    let mut tx = transaction(client)?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&SCHEMA_LOCK])
        .map_err(|_| BrowserError::Unavailable)?;
    // Enforce the mode inside the SQL's creation branch, not with an earlier
    // existence probe that could race a concurrent DROP. This setting is local
    // to the transaction and is explicitly reset for every validation call.
    let mode = if allow_create { "on" } else { "off" };
    tx.execute(
        "SELECT pg_catalog.set_config('apex.browser_session_create', $1, true)",
        &[&mode],
    )
    .map_err(|_| BrowserError::Unavailable)?;
    tx.batch_execute(include_str!(
        "../../../../../../deploy/postgres/operator_sessions.sql"
    ))
    .map_err(|_| BrowserError::Unavailable)?;
    tx.commit().map_err(|_| BrowserError::Unavailable)
}
