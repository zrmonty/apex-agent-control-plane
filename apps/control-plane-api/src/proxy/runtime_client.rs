//! Concrete deployment-owned mTLS execution transport. No provider fallback.
use crate::{ProxyError, proto};
use prost::Message;
use std::time::{Duration, Instant};
use tonic::transport::{Channel, Endpoint};
mod attestation;
mod config;
pub use config::RuntimeExecutionConfig;
#[cfg(test)]
mod tests;

pub(crate) const RPC_LIMIT: Duration = Duration::from_secs(120);
pub(crate) struct RuntimeExecutionClient {
    client: proto::runtime_execution_service_client::RuntimeExecutionServiceClient<Channel>,
    installation: String,
}

impl RuntimeExecutionClient {
    pub(crate) async fn connect(
        config: &RuntimeExecutionConfig,
        deadline: Instant,
    ) -> Result<Self, ProxyError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(unavailable)?;
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|_| unavailable())?
            .tls_config(config.tls.clone())
            .map_err(|_| unavailable())?
            .connect_timeout(remaining.min(Duration::from_secs(5)));
        let channel =
            tokio::time::timeout(remaining.min(Duration::from_secs(5)), endpoint.connect())
                .await
                .map_err(|_| unavailable())?
                .map_err(|_| unavailable())?;
        Ok(Self {
            installation: config.installation_id.clone(),
            client: proto::runtime_execution_service_client::RuntimeExecutionServiceClient::new(
                channel,
            )
            .max_encoding_message_size(4096)
            .max_decoding_message_size(16384),
        })
    }

    pub(crate) async fn reconcile(
        &mut self,
        request: &proto::RuntimeReconcileRequest,
        desired: proto::ProxyDesiredState,
        deadline: Instant,
    ) -> Result<proto::RuntimeReconcileResponse, ProxyError> {
        if request.encoded_len() > 4096 {
            return Err(invalid());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(unavailable)?
            .min(RPC_LIMIT);
        let mut wire = tonic::Request::new(request.clone());
        wire.set_timeout(remaining);
        let response = tokio::time::timeout(remaining, self.client.reconcile_runtime(wire))
            .await
            .map_err(|_| unavailable())?
            .map_err(rpc_error)?
            .into_inner();
        validate_response(request, &response, desired)?;
        validate_installation(&response, &self.installation)?;
        Ok(response)
    }
}

fn rpc_error(status: tonic::Status) -> ProxyError {
    // Never log the peer's arbitrary status text, metadata, or transport source.
    let reason = match status.message() {
        "RUNTIME_AUTHORITY_REFUSED" => "RUNTIME_AUTHORITY_REFUSED",
        "RUNTIME_LAUNCH_REFUSED" => "RUNTIME_LAUNCH_REFUSED",
        "RUNTIME_PEER_DENIED" => "RUNTIME_PEER_DENIED",
        "RUNTIME_OPERATION_NOT_CURRENT" => "RUNTIME_OPERATION_NOT_CURRENT",
        _ => "RUNTIME_RPC_REFUSED",
    };
    eprintln!(
        "runtime_execution_rpc_refused code={:?} reason={reason}",
        status.code()
    );
    if status.code() == tonic::Code::Unavailable && reason == "RUNTIME_AUTHORITY_REFUSED" {
        ProxyError::new(
            "RUNTIME_EXECUTION_RETRYABLE",
            "Runtime temporarily refused.",
        )
    } else {
        unavailable()
    }
}

pub(crate) fn validate_response(
    request: &proto::RuntimeReconcileRequest,
    response: &proto::RuntimeReconcileResponse,
    desired: proto::ProxyDesiredState,
) -> Result<(), ProxyError> {
    use proto::ProxyObservedState as State;
    if response.schema_version != 1
        || response.claims.as_ref() != Some(request)
        || response.encoded_len() > 16384
        || !code(&response.error_code)
    {
        return Err(invalid());
    }
    let state = State::try_from(response.observed_state).map_err(|_| invalid())?;
    if !matches!(
        (desired, state),
        (proto::ProxyDesiredState::Paused, State::Paused)
            | (proto::ProxyDesiredState::Retired, State::Retired)
            | (
                proto::ProxyDesiredState::Serving
                    | proto::ProxyDesiredState::Paused
                    | proto::ProxyDesiredState::Retired,
                State::NotServing | State::Reconciling | State::Failed
            )
    ) {
        return Err(invalid());
    }
    if matches!(state, State::Paused | State::Retired) && !response.error_code.is_empty() {
        return Err(invalid());
    }
    if state == State::Retired && response.runtime.is_some() {
        return Err(invalid());
    }
    if let Some(runtime) = &response.runtime {
        attestation::validate(request, runtime)?;
        let current = request.target.as_ref().ok_or_else(invalid)?;
        let installed = runtime.target.as_ref().ok_or_else(invalid)?;
        if installed.workspace_id != current.workspace_id
            || installed.namespace_id != current.namespace_id
            || installed.proxy_id != current.proxy_id
            || !apex_domain::is_lowercase_uuidv7(&installed.revision_id)
            || installed.generation == 0
            || installed.generation > current.generation
            || installed.fencing_token == 0
            || installed.fencing_token > current.fencing_token
            || (installed.generation == current.generation
                && installed.revision_id != current.revision_id)
            || runtime.runtime_id.len() != 64
            || !runtime
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || runtime.state != "not-serving"
            || runtime.ready
            || runtime.admitting
            || runtime.active_calls != 0
            || runtime.observed_at_unix_us == 0
            || runtime.observed_at_unix_us > i64::MAX as u64
            || runtime.error_code != response.error_code
            || !runtime.resource_url.is_empty()
            || !runtime.stages.is_empty()
            || runtime.readiness.is_some()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn validate_installation(
    response: &proto::RuntimeReconcileResponse,
    installation: &str,
) -> Result<(), ProxyError> {
    if response
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.launch_attestation.as_ref())
        .is_some_and(|attestation| attestation.installation_id != installation)
    {
        return Err(invalid());
    }
    Ok(())
}

fn code(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
fn invalid() -> ProxyError {
    ProxyError::new("RUNTIME_RESPONSE_INVALID", "Runtime response refused.")
}
pub(crate) fn unavailable() -> ProxyError {
    ProxyError::new(
        "RUNTIME_EXECUTION_UNAVAILABLE",
        "Runtime execution unavailable.",
    )
}
