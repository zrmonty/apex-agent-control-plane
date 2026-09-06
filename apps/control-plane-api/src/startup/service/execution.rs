use apex_control_plane_api::{RuntimeExecutionConfig, RuntimeExecutionOwner};
use std::{io, path::Path};

pub(super) fn prepare(
    base: &Path,
    authority_configured: bool,
) -> Result<Option<RuntimeExecutionOwner>, io::Error> {
    let value = match std::env::var("APEX_CONTROL_RUNTIME_EXECUTION_CONFIG_FILE") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if value.is_empty() || !authority_configured {
        return Err(unavailable());
    }
    let database = crate::startup::env::control_postgres_url()?.ok_or_else(unavailable)?;
    let config =
        RuntimeExecutionConfig::load(base, Path::new(&value)).map_err(|_| unavailable())?;
    RuntimeExecutionOwner::new(config, &database)
        .map(Some)
        .map_err(|_| unavailable())
}
fn unavailable() -> io::Error {
    io::Error::other("runtime execution configuration unavailable")
}
