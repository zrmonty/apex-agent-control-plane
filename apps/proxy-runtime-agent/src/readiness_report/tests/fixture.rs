use crate::proto;

pub(super) fn launch() -> proto::RuntimeLaunchContext {
    proto::RuntimeLaunchContext {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "workspace-a".into(),
            namespace_id: "namespace-a".into(),
            proxy_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001".into(),
            revision_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002".into(),
            generation: 9_007_199_254_740_993,
            fencing_token: 9_007_199_254_740_995,
        }),
        config_hash: "a".repeat(64),
        runtime_manifest_hash: "b".repeat(64),
        launch_context_hash: "c".repeat(64),
        image_ref: format!("registry.example/gateway@sha256:{}", "d".repeat(64)),
        process_instance_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003".into(),
        health: Some(proto::RuntimeHealthBinding {
            port: 8081,
            credential_ref: "secret://deployment/health".into(),
        }),
        materials: vec![proto::RuntimeMaterialBinding {
            role: proto::RuntimeMaterialRole::HealthToken.into(),
            reference: "secret://deployment/health".into(),
            version: "material-v1".into(),
        }],
        authority_profile_ref: "deployment-live".into(),
        authority_profile_version: "authority-v1".into(),
    }
}

pub(super) fn report(launch: &proto::RuntimeLaunchContext) -> proto::ReadinessReport {
    let stages = [
        "config",
        "launch",
        "material",
        "inbound_auth",
        "upstream_catalog",
        "governance",
        "evidence_admission",
        "network",
        "admission",
    ];
    proto::ReadinessReport {
        live: true,
        ready: true,
        target: launch.target.clone(),
        observed_at_unix_us: 9_007_199_254_740_993,
        config_hash: launch.config_hash.clone(),
        runtime_manifest_hash: launch.runtime_manifest_hash.clone(),
        launch_context_hash: launch.launch_context_hash.clone(),
        process_instance_id: launch.process_instance_id.clone(),
        checks: (1..=9)
            .map(|id| proto::ReadinessCheck {
                id,
                status: proto::ReadinessCheckStatus::Pass.into(),
                reason: proto::ReadinessReason::Ok.into(),
            })
            .collect(),
        stages: stages
            .iter()
            .map(|name| proto::ProxyStageTiming {
                name: format!("readiness.{name}"),
                started_at_unix_us: 9_007_199_254_740_991,
                duration_us: 7,
                duration_ns: Some(7001),
                process_instance_id: launch.process_instance_id.clone(),
                clock_source: "test-monotonic".into(),
                clock_resolution_ns: 1,
                ..Default::default()
            })
            .collect(),
    }
}

pub(super) fn stdout(report: &proto::ReadinessReport) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(report).unwrap();
    bytes.push(b'\n');
    bytes
}
