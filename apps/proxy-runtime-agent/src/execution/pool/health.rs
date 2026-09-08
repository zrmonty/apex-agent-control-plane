use super::super::health::Observation;
use super::*;
use crate::service::health_observation as wire;

pub(super) struct Job {
    pub request: Request<proto::RuntimeHealthObservationRequest>,
    pub started: Instant,
    pub cancelled: Arc<AtomicBool>,
    pub metadata: Arc<owner::Metadata>,
    reply: oneshot::Sender<Result<Observation, Status>>,
    _permit: OwnedSemaphorePermit,
    _proxy: ProxyGuard,
}
pub(super) fn run(ctx: &Context, job: Job) {
    let result = super::super::health::collect(
        ctx,
        &job.request,
        job.started,
        &job.cancelled,
        &job.metadata,
    )
    .map_err(Status::unavailable);
    // collect retains ownership through daemon termination, including after the
    // logical request disappears. Never release based on stream EOF.
    let Job {
        reply,
        _permit,
        _proxy,
        ..
    } = job;
    drop(_proxy);
    drop(_permit);
    let _ = reply.send(result);
}
impl Facility {
    pub(crate) async fn observe_health(
        &self,
        request: Request<proto::RuntimeHealthObservationRequest>,
        started: Instant,
        metadata: Arc<owner::Metadata>,
    ) -> Result<Observation, Status> {
        wire::validate(request.get_ref())?;
        let until = started + wire::BUDGET;
        if Instant::now() >= until {
            return Err(Status::deadline_exceeded("RUNTIME_DEADLINE"));
        }
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("RUNTIME_OVERLOADED"))?;
        let target = request
            .get_ref()
            .binding
            .as_ref()
            .and_then(|b| b.target.as_ref())
            .ok_or_else(|| Status::invalid_argument("RUNTIME_HEALTH_REQUEST_INVALID"))?;
        let proxy = ProxyGuard::acquire(
            &self.active,
            Journal::key(&self.installation, target),
            Kind::Health,
        )
        .map_err(Status::resource_exhausted)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancellation(Arc::clone(&cancelled));
        let (reply, response) = oneshot::channel();
        let job = Job {
            request,
            started,
            cancelled,
            metadata,
            reply,
            _permit: permit,
            _proxy: proxy,
        };
        self.sender
            .as_ref()
            .ok_or_else(|| Status::unavailable("RUNTIME_SHUTTING_DOWN"))?
            .try_send(Work::Health(job))
            .map_err(|_| Status::resource_exhausted("RUNTIME_OVERLOADED"))?;
        let result = tokio::time::timeout_at(until.into(), response)
            .await
            .map_err(|_| Status::deadline_exceeded("RUNTIME_DEADLINE"))?
            .map_err(|_| Status::unavailable("RUNTIME_WORKER_UNAVAILABLE"))?;
        if Instant::now() >= until {
            return Err(Status::deadline_exceeded("RUNTIME_DEADLINE"));
        }
        result
    }
}
#[cfg(test)]
mod tests;
