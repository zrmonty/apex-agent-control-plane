//! Read-only Controller transport; no execution RPC or workload credential.
use super::{RuntimeExecutionConfig, unavailable};
use crate::{ProxyError, proto};
use prost::Message;
use std::time::{Duration, Instant};
use tonic::transport::{Channel, Endpoint};

pub(crate) const LIMIT: Duration = Duration::from_secs(2);

/// Only a recognized authenticated agent contention reply is retryable. This
/// classification never carries peer text or overrides currentness checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InspectionFailure {
    Busy,
    Refused,
}
impl From<ProxyError> for InspectionFailure {
    fn from(_: ProxyError) -> Self {
        Self::Refused
    }
}
impl InspectionFailure {
    fn from_status(status: tonic::Status) -> Self {
        if status.code() == tonic::Code::ResourceExhausted
            && status.details().is_empty()
            && matches!(
                status.message(),
                "RUNTIME_PROXY_BUSY" | "RUNTIME_NETWORK_BUSY" | "RUNTIME_OVERLOADED"
            )
        {
            Self::Busy
        } else {
            Self::Refused
        }
    }
}

/// Construct/use/drop on the root's owned blocking worker, never an entered
/// serving runtime. One reusable channel is retained until that owner joins.
pub(crate) struct Transport {
    client: proto::runtime_network_inspection_client::RuntimeNetworkInspectionClient<Channel>,
    runtime: tokio::runtime::Runtime,
    config: RuntimeExecutionConfig,
}
impl Transport {
    pub(crate) fn new(config: RuntimeExecutionConfig) -> Result<Self, ProxyError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(unavailable());
        }
        config.recheck()?;
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|_| unavailable())?
            .tls_config(config.tls.clone())
            .map_err(|_| unavailable())?
            .connect_timeout(LIMIT);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| unavailable())?;
        let channel = runtime.block_on(async { endpoint.connect_lazy() });
        Ok(Self {
            client: proto::runtime_network_inspection_client::RuntimeNetworkInspectionClient::new(
                channel,
            )
            .max_encoding_message_size(4096)
            .max_decoding_message_size(4096),
            runtime,
            config,
        })
    }

    pub(crate) fn inspect(
        &mut self,
        input: &proto::RuntimeNetworkInspectionRequest,
        started: Instant,
        budget: Duration,
        check: &dyn Fn() -> Result<(), ProxyError>,
    ) -> Result<proto::RuntimeNetworkInspectionResponse, InspectionFailure> {
        validate_request(input, &self.config)?;
        let budget = budget.min(LIMIT);
        let current = || {
            remaining(started, budget)?;
            check()
        };
        current()?;
        self.config.recheck()?;
        current()?;
        let mut request = tonic::Request::new(input.clone());
        request.set_timeout(remaining(started, budget)?);
        let mut client = self.client.clone();
        let reply = self.runtime.block_on(async {
            let call = client.check(request);
            tokio::pin!(call);
            loop {
                current()?;
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(started + budget)) => return Err(unavailable()),
                    result = &mut call => return Ok(result.map(tonic::Response::into_inner).map_err(InspectionFailure::from_status)),
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                }
            }
        })?;
        current()?;
        self.config.recheck()?;
        current()?;
        // Busy is released only after the same credential/current-operation
        // checks as success. Revocation or expiry wins over an earlier reply.
        let reply = reply?;
        validate_response(input, &reply, started.elapsed())?;
        current()?;
        Ok(reply)
    }
}

fn remaining(started: Instant, budget: Duration) -> Result<Duration, ProxyError> {
    let age = Instant::now()
        .checked_duration_since(started)
        .ok_or_else(unavailable)?;
    budget
        .checked_sub(age)
        .filter(|d| !d.is_zero())
        .ok_or_else(unavailable)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_request(
    input: &proto::RuntimeNetworkInspectionRequest,
    config: &RuntimeExecutionConfig,
) -> Result<(), ProxyError> {
    let b = input.binding.as_ref().ok_or_else(unavailable)?;
    let t = b.target.as_ref().ok_or_else(unavailable)?;
    if input.encoded_len() > 4096
        || input.schema_version != 1
        || input.nonce.len() != 32
        || b.installation_id != config.installation_id
        || ![
            &b.installation_id,
            &b.process_instance_id,
            &t.proxy_id,
            &t.revision_id,
        ]
        .into_iter()
        .all(|v| apex_domain::is_lowercase_uuidv7(v))
        || ![&t.workspace_id, &t.namespace_id]
            .into_iter()
            .all(|v| crate::proxy::is_scope_identifier(v))
        || !config
            .scopes
            .iter()
            .any(|s| s.workspace_id == t.workspace_id && s.namespace_id == t.namespace_id)
        || !digest(&b.config_hash)
        || !digest(&b.launch_context_hash)
        || t.generation == 0
        || t.generation > i64::MAX as u64
        || t.fencing_token == 0
        || t.fencing_token > i64::MAX as u64
    {
        return Err(unavailable());
    }
    Ok(())
}

pub(crate) fn validate_response(
    request: &proto::RuntimeNetworkInspectionRequest,
    response: &proto::RuntimeNetworkInspectionResponse,
    elapsed: Duration,
) -> Result<(), ProxyError> {
    if response.encoded_len() > 4096
        || response.schema_version != 1
        || response.binding != request.binding
        || response.nonce != request.nonce
        || !response.confined
        || !digest(&response.network_binding_sha256)
        || !digest(&response.gateway_process_sha256)
        || !digest(&response.guard_process_sha256)
        || !(1..=10_000_000).contains(&response.valid_for_us)
        || elapsed >= Duration::from_micros(response.valid_for_us)
    {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
