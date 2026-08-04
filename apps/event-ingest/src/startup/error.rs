use std::io;

use apex_event_ingest::GatewayError;

pub(crate) fn startup_gateway_error(error: GatewayError) -> io::Error {
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
