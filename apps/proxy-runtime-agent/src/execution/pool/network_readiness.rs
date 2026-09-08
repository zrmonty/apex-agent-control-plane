use super::*;
use crate::service::network_readiness::{self as wire, BUDGET};

pub(super) struct Job {
    pub request: Request<proto::RuntimeNetworkInspectionRequest>,
    pub started: Instant,
    pub cancelled: Arc<AtomicBool>,
    pub metadata: Arc<owner::Metadata>,
    reply: oneshot::Sender<Result<proto::RuntimeNetworkInspectionResponse, Status>>,
    _permit: OwnedSemaphorePermit,
    _proxy: ProxyGuard,
}

pub(super) fn run(ctx: &Context, job: Job) {
    // Nonblocking admission to the physical network owner: no queued repair path.
    let effect = ctx.resources.network_effect.try_lock();
    let result = match &effect {
        Ok(_) => super::super::network_readiness::inspect(
            ctx,
            &job.request,
            job.started,
            &job.cancelled,
            &job.metadata,
        )
        .map_err(Status::unavailable),
        Err(_) => Err(Status::resource_exhausted("RUNTIME_NETWORK_BUSY")),
    };
    // Keep the network owner and both capacity guards through the reply. This
    // final check is serialized with protected metadata replacement.
    let state = ctx.shared.lock();
    let result = result.and_then(|reply| {
        let state = state
            .as_ref()
            .map_err(|_| Status::unavailable(owner::UNAVAILABLE))?;
        if state.stopped
            || *ctx.shutdown.borrow()
            || state.read_started.elapsed() >= owner::FRESHNESS
            || state
                .metadata
                .as_ref()
                .is_none_or(|m| !Arc::ptr_eq(m, &job.metadata))
            || job.cancelled.load(Ordering::Acquire)
            || job.started.elapsed() >= BUDGET
        {
            return Err(Status::unavailable(wire::ERROR));
        }
        job.metadata.current().map_err(Status::unavailable)?;
        wire::authorize(&job.request, &ctx.installation, &job.metadata)?;
        Ok(reply)
    });
    let _ = job.reply.send(result);
}

impl Facility {
    pub(crate) async fn inspect_network(
        &self,
        request: Request<proto::RuntimeNetworkInspectionRequest>,
        started: Instant,
        metadata: Arc<owner::Metadata>,
    ) -> Result<proto::RuntimeNetworkInspectionResponse, Status> {
        wire::validate(request.get_ref())?;
        let until = started + BUDGET;
        if Instant::now() >= until {
            return Err(Status::deadline_exceeded("RUNTIME_DEADLINE"));
        }
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("RUNTIME_OVERLOADED"))?;
        let t = request
            .get_ref()
            .binding
            .as_ref()
            .and_then(|b| b.target.as_ref())
            .ok_or_else(|| Status::invalid_argument("RUNTIME_NETWORK_REQUEST_INVALID"))?;
        let key = Journal::key(&self.installation, t);
        let proxy = ProxyGuard::acquire(&self.active, key, Kind::Network)
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
            .try_send(Work::Inspect(job))
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
mod tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context as TaskContext, Waker},
    };
    #[tokio::test]
    async fn network_inspection_cancel_and_deadline_keep_slots_until_worker_drops() {
        let (sender, receiver) = mpsc::sync_channel(8);
        let facility = Facility {
            sender: Some(sender),
            threads: vec![],
            slots: Arc::new(Semaphore::new(8)),
            active: Arc::default(),
            installation: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
        };
        let (p, c) = owner::tests::documents();
        let metadata = Arc::new(owner::Metadata::parse(&p, &c).unwrap());
        let request = || {
            Request::new(proto::RuntimeNetworkInspectionRequest {
                schema_version: 1,
                nonce: vec![5; 32],
                binding: Some(proto::ManagedDeploymentBinding {
                    installation_id: facility.installation.clone(),
                    target: Some(proto::RuntimeTarget {
                        workspace_id: "work".into(),
                        namespace_id: "ns".into(),
                        proxy_id: uuid::Uuid::now_v7().to_string(),
                        revision_id: uuid::Uuid::now_v7().to_string(),
                        generation: 1,
                        fencing_token: 1,
                    }),
                    process_instance_id: uuid::Uuid::now_v7().to_string(),
                    config_hash: "a".repeat(64),
                    launch_context_hash: "b".repeat(64),
                }),
            })
        };
        let first = request();
        let repeat = first.get_ref().clone();
        let mut pending =
            Box::pin(facility.inspect_network(first, Instant::now(), Arc::clone(&metadata)));
        assert!(
            pending
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop()))
                .is_pending()
        );
        let physical = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(pending);
        let Work::Inspect(held) = &physical else {
            panic!("inspection must retain its own request")
        };
        assert!(held.cancelled.load(Ordering::Acquire));
        assert_eq!(facility.slots.available_permits(), 7);
        assert_eq!(
            facility
                .inspect_network(Request::new(repeat), Instant::now(), Arc::clone(&metadata))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut others = vec![];
        for _ in 0..7 {
            let mut pending = Box::pin(facility.inspect_network(
                request(),
                Instant::now(),
                Arc::clone(&metadata),
            ));
            assert!(
                pending
                    .as_mut()
                    .poll(&mut TaskContext::from_waker(Waker::noop()))
                    .is_pending()
            );
            others.push(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
            drop(pending);
        }
        assert_eq!(facility.slots.available_permits(), 0);
        assert_eq!(
            facility
                .inspect_network(request(), Instant::now(), Arc::clone(&metadata))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        drop(physical);
        drop(others);
        assert_eq!(facility.slots.available_permits(), 8);
        assert!(facility.active.lock().unwrap().is_empty());
        let result = facility
            .inspect_network(
                request(),
                Instant::now() - Duration::from_secs(3),
                Arc::clone(&metadata),
            )
            .await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::DeadlineExceeded);
        assert_eq!(facility.slots.available_permits(), 8);
        // A ready response first polled after the original deadline is stale.
        // Tokio's timeout may poll the ready inner future before its timer.
        let started = Instant::now() - BUDGET + Duration::from_millis(30);
        let mut pending =
            Box::pin(facility.inspect_network(request(), started, Arc::clone(&metadata)));
        assert!(
            pending
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop()))
                .is_pending()
        );
        let Work::Inspect(job) = receiver.recv_timeout(Duration::from_secs(1)).unwrap() else {
            panic!("inspection")
        };
        job.reply
            .send(Ok(proto::RuntimeNetworkInspectionResponse::default()))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            pending.await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        // Logical timeout also keeps physical capacity and marks cancellation.
        let mut pending = Box::pin(facility.inspect_network(
            request(),
            Instant::now() - BUDGET + Duration::from_millis(30),
            metadata,
        ));
        assert!(
            pending
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop()))
                .is_pending()
        );
        let Work::Inspect(job) = receiver.recv_timeout(Duration::from_secs(1)).unwrap() else {
            panic!("inspection")
        };
        assert_eq!(
            pending.await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        assert!(job.cancelled.load(Ordering::Acquire));
        assert!(facility.slots.available_permits() < 8);
        drop(job);
    }
}
