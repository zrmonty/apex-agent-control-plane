use apex_durability::{
    IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult,
};
use apex_event_ingest::{
    AuthenticatedIngestAdapter, Caller, EventPublisher, GatewayError, IngestGateway, IngestRequest,
    PublishOutcome,
};
use std::sync::{Arc, Mutex};

// Observe the real gateway dispatch, not a verifier substitute. The network RPC
// supplies Caller later; these fixtures establish the no-I/O-before-scope gate.
struct Owner {
    label: &'static str,
    fail: bool,
    observed: Arc<Mutex<Vec<&'static str>>>,
}
impl Owner {
    fn check(&self, workspace: &str, namespace: &str) -> Result<(), GatewayError> {
        assert_eq!((workspace, namespace), ("acme", "prod"));
        self.observed.lock().unwrap().push(self.label);
        if self.fail {
            Err(GatewayError::internal())
        } else {
            Ok(())
        }
    }
}
impl EventPublisher for Owner {
    fn publish(&mut self, _: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        panic!("not admission")
    }
    fn check_admission_readiness(
        &mut self,
        workspace: &str,
        namespace: &str,
    ) -> Result<(), GatewayError> {
        self.check(workspace, namespace)
    }
}
impl IdempotencyStore for Owner {
    fn reserve(
        &mut self,
        _: IdempotencyKey,
        _: [u8; 32],
    ) -> Result<ReservationResult, GatewayError> {
        panic!("not admission")
    }
    fn commit(&mut self, _: IdempotencyReservation) -> Result<(), GatewayError> {
        panic!("not admission")
    }
    fn abort(&mut self, _: IdempotencyReservation) {
        panic!("not admission")
    }
    fn check_admission_readiness(
        &mut self,
        workspace: &str,
        namespace: &str,
    ) -> Result<(), GatewayError> {
        self.check(workspace, namespace)
    }
}
fn caller() -> Caller {
    Caller::authenticated_for_agent("workload", "proxy-evidence", ["acme/prod"]).unwrap()
}
fn fixture(
    fail_idempotency: bool,
    fail_outbox: bool,
) -> (
    AuthenticatedIngestAdapter<Owner>,
    Arc<Mutex<Vec<&'static str>>>,
) {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let owner = |label, fail| Owner {
        label,
        fail,
        observed: observed.clone(),
    };
    (
        AuthenticatedIngestAdapter::new(IngestGateway::with_idempotency_store(
            owner("outbox", fail_outbox),
            Box::new(owner("idempotency", fail_idempotency)),
        )),
        observed,
    )
}

#[test]
fn readiness_visits_both_actual_stores_without_reserving_or_publishing() {
    let (mut adapter, observed) = fixture(false, false);
    adapter
        .check_admission_readiness(&caller(), "acme", "prod", "proxy-evidence")
        .unwrap();
    assert_eq!(*observed.lock().unwrap(), ["idempotency", "outbox"]);
}

#[test]
fn readiness_refuses_wrong_scope_agent_or_anonymous_before_touching_storage() {
    for (caller, workspace, namespace, agent) in [
        (Caller::anonymous(), "acme", "prod", "proxy-evidence"),
        (caller(), "other", "prod", "proxy-evidence"),
        (caller(), "acme", "other", "proxy-evidence"),
        (caller(), "acme", "prod", "other-agent"),
        (caller(), "", "prod", "proxy-evidence"),
        (caller(), "acme", "../prod", "proxy-evidence"),
    ] {
        let (mut adapter, observed) = fixture(false, false);
        assert!(
            adapter
                .check_admission_readiness(&caller, workspace, namespace, agent)
                .is_err()
        );
        assert!(observed.lock().unwrap().is_empty());
    }
}

#[test]
fn readiness_never_hides_either_stores_failure() {
    for (idempotency, outbox) in [(true, false), (false, true)] {
        let (mut adapter, observed) = fixture(idempotency, outbox);
        assert!(
            adapter
                .check_admission_readiness(&caller(), "acme", "prod", "proxy-evidence")
                .is_err()
        );
        assert_eq!(
            observed.lock().unwrap().len(),
            if idempotency { 1 } else { 2 }
        );
    }
}
