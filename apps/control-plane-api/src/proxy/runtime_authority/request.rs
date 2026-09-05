//! Bounded generated claims only, never transport identity or an authority brand.

use std::{fmt, time::Duration};

use prost::Message;

use super::RuntimeAuthorityError;
use crate::proto::{CheckRuntimeAuthorityRequest, RuntimeAuthorityAction};

pub(super) struct RequestClaims {
    pub message: CheckRuntimeAuthorityRequest,
    pub budget: Duration,
}

impl RequestClaims {
    pub(super) fn parse(
        request: &tonic::Request<CheckRuntimeAuthorityRequest>,
    ) -> Result<Self, RuntimeAuthorityError> {
        let invalid = RuntimeAuthorityError::InvalidRequest;
        let message = request.get_ref();
        let target = message.target.as_ref().ok_or(invalid)?;
        if message.schema_version != 1
            || RuntimeAuthorityAction::try_from(message.action)
                != Ok(RuntimeAuthorityAction::CheckCurrentOperation)
            || message.observed_controller_certificate_sha256.len() != 32
            || !apex_domain::is_scope_identifier(&target.workspace_id)
            || !apex_domain::is_scope_identifier(&target.namespace_id)
            || target.generation == 0
            || i64::try_from(target.generation).is_err()
            || target.fencing_token == 0
            || i64::try_from(target.fencing_token).is_err()
            || ![
                &message.operation_id,
                &message.command_id,
                &message.installation_id,
                &target.proxy_id,
                &target.revision_id,
            ]
            .into_iter()
            .all(|id| apex_domain::is_lowercase_uuidv7(id))
            || message.encoded_len() > 4096
        {
            return Err(invalid);
        }
        let mut timeouts = request.metadata().get_all("grpc-timeout").iter();
        let budget = match timeouts.next() {
            None => Duration::from_secs(5),
            Some(value) => timeout(value.to_str().map_err(|_| invalid)?)?,
        };
        if timeouts.next().is_some() {
            return Err(invalid);
        }
        // Clone only bounded generated claims, never headers or arbitrary extensions.
        Ok(Self {
            message: message.clone(),
            budget,
        })
    }
}

fn timeout(text: &str) -> Result<Duration, RuntimeAuthorityError> {
    let invalid = RuntimeAuthorityError::InvalidRequest;
    let (&unit, digits) = text.as_bytes().split_last().ok_or(invalid)?;
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid);
    }
    let value: u64 = std::str::from_utf8(digits)
        .map_err(|_| invalid)?
        .parse()
        .map_err(|_| invalid)?;
    let duration = match unit {
        b'n' => Duration::from_nanos(value),
        b'u' => Duration::from_micros(value),
        b'm' => Duration::from_millis(value),
        b'S' => Duration::from_secs(value),
        b'M' => Duration::from_secs(value.checked_mul(60).ok_or(invalid)?),
        b'H' => Duration::from_secs(value.checked_mul(3600).ok_or(invalid)?),
        _ => return Err(invalid),
    };
    Ok(duration.min(Duration::from_secs(5)))
}

impl fmt::Debug for RequestClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestClaims { [redacted] }")
    }
}
