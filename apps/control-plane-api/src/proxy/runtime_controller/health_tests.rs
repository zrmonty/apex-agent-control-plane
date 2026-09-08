//! Real controller/client/PG integration with a SYNTHETIC agent reply.
//! No native runtime, production readiness, or business-serving proof.
use super::*;
use crate::{LeasedProxyOperation, proxy::store::DeploymentRegistration};
use prost::Message;
use uuid::Uuid;
#[allow(dead_code, clippy::duplicate_mod)]
#[path = "../store/postgres/serving/tests/fixture.rs"]
mod fixture;
#[path = "health_tests/peer.rs"]
mod peer;
#[allow(dead_code, clippy::duplicate_mod)]
#[path = "../../../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;

fn run(f: &fixture::Fixture, peer: &peer::Peer) -> Result<(), ProxyError> {
    let target = f.registration.binding.target.as_ref().unwrap();
    // Replacement lease legitimately adopts the same generation's original
    // registered launch. Never rewrite that launch to the new fence.
    f.client()
        .execute(
            "UPDATE mcp_proxy_controller_leases SET expires_at_micros=0",
            &[],
        )
        .unwrap();
    let shared = Shared {
        stopped: AtomicBool::new(false),
        active: AtomicBool::new(true),
        scan_ok: AtomicBool::new(true),
        in_flight: Mutex::new(BTreeSet::new()),
        last_response: Mutex::new(None),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    run_job(
        &shared,
        &peer.config,
        &f.store,
        &runtime,
        &Job {
            scope: ExactScope {
                workspace_id: target.workspace_id.clone(),
                namespace_id: target.namespace_id.clone(),
            },
            proxy_id: ProxyId::new(&target.proxy_id).unwrap(),
            admitted: Instant::now(),
        },
    )
}

#[test]
#[ignore = "requires disposable PG, existing browser PKI and generated runtime launch; never skips"]
fn real_controller_health_selects_first_candidate_without_rewriting_execution_evidence() {
    let mut f = fixture::Fixture::new();
    let peer = peer::Peer::new(&mut f, false);
    peer.prepare(&f);
    run(&f, &peer).unwrap();
    let row = f
        .client()
        .query_one(
            "SELECT mode,admitting,applied_mode FROM mcp_proxy_deployments",
            &[],
        )
        .unwrap();
    assert_eq!(
        row.get::<_, i32>(0),
        2,
        "actual run_job must consume authenticated health and select"
    );
    assert!(!row.get::<_, bool>(1));
    assert_eq!(
        row.get::<_, i32>(2),
        1,
        "selection does not fabricate applied SERVE"
    );
    let response = proto::RuntimeReconcileResponse::decode(
        f.client()
            .query_one("SELECT response_bytes FROM mcp_proxy_runtime_attempts", &[])
            .unwrap()
            .get::<_, Vec<u8>>(0)
            .as_slice(),
    )
    .unwrap();
    assert_eq!(
        response.observed_state,
        proto::ProxyObservedState::NotServing as i32
    );
    assert_eq!(response.runtime.unwrap(), peer.observed);
    let calls = peer.calls.lock().unwrap();
    assert_eq!(*calls, vec!["reconcile", "health"]);
}

#[test]
#[ignore = "requires disposable PG, existing browser PKI and generated runtime launch; never skips"]
fn health_unavailable_keeps_not_serving_and_records_original_execution_once() {
    let mut f = fixture::Fixture::new();
    let peer = peer::Peer::new(&mut f, true);
    peer.prepare(&f);
    run(&f, &peer).unwrap();
    let row = f
        .client()
        .query_one(
            "SELECT mode,readiness_id,terminated FROM mcp_proxy_deployments",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, i32>(0), 1);
    assert!(row.get::<_, Option<Uuid>>(1).is_none());
    assert!(!row.get::<_, bool>(2));
    assert_eq!(*peer.calls.lock().unwrap(), vec!["reconcile", "health"]);
    assert_eq!(
        f.client()
            .query_one(
                "SELECT count(*) FROM mcp_proxy_runtime_attempts WHERE response_bytes IS NOT NULL",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[test]
#[ignore = "requires disposable PG, existing browser PKI and generated runtime launch; never skips"]
fn controller_refuses_missing_prepare_wrong_candidate_and_ineligible_deployments() {
    for change in [
        "missing-prepare",
        "busy-prepare",
        "closed",
        "unpublished",
        "wrong-original",
        "previous-generation",
        "paused",
        "retired",
        "selected",
    ] {
        let mut f = fixture::Fixture::new();
        let peer = peer::Peer::new(&mut f, false);
        if change == "wrong-original" {
            f.registration.binding.process_instance_id = Uuid::now_v7().to_string();
        }
        if change == "missing-prepare" {
            f.store
                .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
                .unwrap();
        } else {
            peer.prepare(&f);
        }
        match change {
            "busy-prepare" => {
                f.client()
                    .execute("UPDATE mcp_proxy_deployments SET active_calls=1", &[])
                    .unwrap();
            }
            "closed" => {
                f.client()
                    .execute("UPDATE mcp_proxy_deployments SET mode=3", &[])
                    .unwrap();
            }
            "unpublished" => {
                f.client()
                    .execute("UPDATE mcp_proxy_revisions SET is_published=false", &[])
                    .unwrap();
            }
            "previous-generation" => f.advance(proto::ProxyDesiredState::Serving, true),
            "paused" => f.advance(proto::ProxyDesiredState::Paused, false),
            "retired" => f.advance(proto::ProxyDesiredState::Retired, false),
            "selected" => {
                run(&f, &peer).unwrap();
                peer.calls.lock().unwrap().clear();
            }
            _ => {}
        }
        let before = f.rows("mcp_proxy_serving_selection");
        let result = run(&f, &peer);
        if matches!(
            change,
            "missing-prepare" | "busy-prepare" | "unpublished" | "wrong-original"
        ) {
            assert!(result.is_err(), "store refusal must be returned: {change}");
        } else {
            result.unwrap();
        }
        assert_eq!(before, f.rows("mcp_proxy_serving_selection"), "{change}");
        assert!(
            !peer.calls.lock().unwrap().contains(&"health"),
            "no health attempt for {change}"
        );
    }
}

#[test]
#[ignore = "requires disposable PG, existing browser PKI and generated runtime launch; never skips"]
fn controller_preserves_old_serving_blocker_without_withdrawal_or_candidate_selection() {
    let mut f = fixture::Fixture::new();
    let original = peer::Peer::new(&mut f, false);
    original.prepare(&f);
    run(&f, &original).unwrap();
    let selected = f.rows("mcp_proxy_serving_selection");
    f.advance(proto::ProxyDesiredState::Serving, true);
    let candidate = peer::Peer::new(&mut f, false);
    candidate.prepare(&f);
    run(&f, &candidate).unwrap();
    assert_eq!(selected, f.rows("mcp_proxy_serving_selection"));
    assert_eq!(*candidate.calls.lock().unwrap(), vec!["reconcile"]);
    assert_eq!(
        f.client()
            .query_one(
                "SELECT count(*) FROM mcp_proxy_deployments WHERE mode=2",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}
