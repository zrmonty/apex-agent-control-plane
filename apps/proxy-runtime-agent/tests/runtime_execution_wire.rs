use apex_proxy_runtime_agent::FILE_DESCRIPTOR_SET;
use prost::Message;

#[test]
fn reconciliation_is_additive_and_has_no_caller_effect_inputs() {
    let descriptor = prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let file = descriptor
        .file
        .iter()
        .find(|f| f.name.as_deref() == Some("apex/v1/proxy_runtime.proto"))
        .unwrap();
    let service = file
        .service
        .iter()
        .find(|s| s.name.as_deref() == Some("RuntimeExecutionService"));
    assert!(
        service.is_some(),
        "production reconciliation service is missing"
    );
    let methods = &service.unwrap().method;
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].name.as_deref(), Some("ReconcileRuntime"));
    assert_eq!(
        methods[0].input_type.as_deref(),
        Some(".apex.v1.RuntimeReconcileRequest")
    );
    assert_eq!(
        methods[0].output_type.as_deref(),
        Some(".apex.v1.RuntimeReconcileResponse")
    );
    let fields = |name: &str| {
        file.message_type
            .iter()
            .find(|m| m.name.as_deref() == Some(name))
            .unwrap()
            .field
            .iter()
            .map(|f| (f.name.as_deref().unwrap(), f.number.unwrap()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        fields("RuntimeReconcileRequest"),
        [
            ("schema_version", 1),
            ("target", 2),
            ("operation_id", 3),
            ("command_id", 4),
            ("config_hash", 5)
        ]
    );
    assert_eq!(
        fields("RuntimeReconcileResponse"),
        [
            ("schema_version", 1),
            ("claims", 2),
            ("observed_state", 3),
            ("runtime", 4),
            ("error_code", 5)
        ]
    );
    assert_eq!(
        fields("RuntimeTarget"),
        [
            ("workspace_id", 1),
            ("namespace_id", 2),
            ("proxy_id", 3),
            ("revision_id", 4),
            ("generation", 5),
            ("fencing_token", 6)
        ]
    );
    let legacy = file
        .service
        .iter()
        .find(|s| s.name.as_deref() == Some("ProxyRuntimeAgent"))
        .unwrap();
    assert_eq!(
        legacy
            .method
            .iter()
            .map(|m| (
                m.name.as_deref().unwrap(),
                m.input_type.as_deref().unwrap(),
                m.output_type.as_deref().unwrap()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "EnsureRuntime",
                ".apex.v1.EnsureRuntimeRequest",
                ".apex.v1.RuntimeObservation"
            ),
            (
                "InspectRuntime",
                ".apex.v1.RuntimeTarget",
                ".apex.v1.RuntimeObservation"
            ),
            (
                "SetAdmission",
                ".apex.v1.SetRuntimeAdmissionRequest",
                ".apex.v1.RuntimeObservation"
            ),
            (
                "DrainRuntime",
                ".apex.v1.DrainRuntimeRequest",
                ".apex.v1.RuntimeObservation"
            ),
            (
                "RemoveRuntime",
                ".apex.v1.RuntimeTarget",
                ".apex.v1.RuntimeObservation"
            ),
            (
                "ProbeUpstream",
                ".apex.v1.ProbeUpstreamRequest",
                ".apex.v1.UpstreamProbeObservation"
            )
        ]
    );
}

#[test]
fn current_correlation_and_installed_launch_keep_distinct_integer_fences() {
    use apex_proxy_runtime_agent::proto::*;
    let installed = RuntimeTarget {
        generation: 9_007_199_254_740_993,
        fencing_token: 9_007_199_254_740_995,
        ..Default::default()
    };
    let current = RuntimeTarget {
        generation: 9_007_199_254_740_994,
        fencing_token: 9_007_199_254_740_999,
        ..Default::default()
    };
    let response = RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(RuntimeReconcileRequest {
            schema_version: 1,
            target: Some(current.clone()),
            ..Default::default()
        }),
        observed_state: 7,
        runtime: Some(RuntimeObservation {
            target: Some(installed.clone()),
            readiness: Some(ReadinessReport {
                target: Some(installed.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        error_code: "RUNTIME_NOT_SERVING".into(),
    };
    for roundtrip in [
        RuntimeReconcileResponse::decode(response.encode_to_vec().as_slice()).unwrap(),
        serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap(),
    ] {
        assert_eq!(roundtrip.claims.unwrap().target, Some(current.clone()));
        let runtime = roundtrip.runtime.unwrap();
        assert_eq!(runtime.target, Some(installed.clone()));
        assert_eq!(runtime.readiness.unwrap().target, Some(installed.clone()));
    }
    // Serialization evidence only: decoding/default runtime is not semantic trust.
    let missing: RuntimeReconcileResponse = serde_json::from_str("{}").unwrap();
    assert!(missing.runtime.is_none());
}
