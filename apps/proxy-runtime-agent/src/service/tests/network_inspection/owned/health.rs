//! Actual authenticated route and physical collector, not direct collect injection.
use super::*;
use crate::proto::runtime_health_observation_client::RuntimeHealthObservationClient;

pub(super) async fn check(
    channel: tonic::transport::Channel,
    shared: &owner::Shared,
    binding: &proto::ManagedDeploymentBinding,
    launch: &proto::RuntimeLaunchContext,
) {
    let mut client = RuntimeHealthObservationClient::new(channel).max_decoding_message_size(32768);
    let request = proto::RuntimeHealthObservationRequest {
        schema_version: 1,
        binding: Some(binding.clone()),
        nonce: vec![29; 32],
    };
    let started = Instant::now();
    let response = client
        .observe(request.clone())
        .await
        .expect("Controller TLS -> actual worker/journal -> packaged probe must join")
        .into_inner();
    assert_eq!(response.schema_version, 1);
    assert_eq!(response.binding, request.binding);
    assert_eq!(response.nonce, request.nonce);
    let sample = response.sample.unwrap();
    assert_eq!(sample.schema_version, 1);
    assert!((1..10_000_000_000).contains(&sample.valid_for_ns));
    assert!(started.elapsed() < Duration::from_secs(10));
    let report = sample.report.unwrap();
    assert!(report.live && report.ready);
    assert_eq!(report.target, launch.target);
    assert_eq!(report.config_hash, launch.config_hash);
    assert_eq!(report.launch_context_hash, launch.launch_context_hash);
    assert_eq!(report.runtime_manifest_hash, launch.runtime_manifest_hash);
    assert_eq!(report.process_instance_id, launch.process_instance_id);
    assert_eq!(report.checks.len(), 9);
    assert_eq!(report.stages.len(), 9);
    for stage in &report.stages {
        assert_eq!(stage.duration_ns, Some(7001));
        assert_eq!(stage.duration_us, 7);
    }
    eprintln!(
        "HEALTH COLLECTOR joined actualTLS/worker/daemon elapsed_ns={} remaining_ns={}",
        started.elapsed().as_nanos(),
        sample.valid_for_ns
    );
    // Already revoked metadata cannot obtain another sample from an old channel.
    {
        let mut state = shared.lock().unwrap();
        state.stopped = true;
        state.metadata = None;
    }
    assert_eq!(
        client.observe(request).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
}
