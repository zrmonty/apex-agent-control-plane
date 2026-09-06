//! Explicit synthetic online authority callback fixture; never a PG substitute.
use super::*;
#[tonic::async_trait]
impl proto::runtime_authority_service_server::RuntimeAuthorityService for Arc<Callback> {
    async fn check_runtime_authority(
        &self,
        r: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeAuthoritySnapshot>, Status> {
        let b = r.get_ref();
        let t = b
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("fixture"))?;
        self.policy
            .authorize_agent_observation(
                &r,
                b.observed_controller_certificate_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("fixture"))?,
                INSTALL,
                &t.workspace_id,
                &t.namespace_id,
            )
            .map_err(|_| Status::permission_denied("fixture"))?;
        *self.pin.lock().unwrap() = b.observed_controller_certificate_sha256.clone();
        let a = self
            .targets
            .lock()
            .unwrap()
            .get(&t.proxy_id)
            .and_then(|s| s.authority.clone())
            .unwrap_or_else(|| self.reply.lock().unwrap().authority.clone().unwrap());
        Ok(Response::new(a))
    }
}
