use super::*;

type Reply = proto::RuntimeHealthObservationResponse;
type Mutation = (&'static str, fn(&mut Reply));
fn report(r: &mut Reply) -> &mut proto::ReadinessReport {
    r.sample.as_mut().unwrap().report.as_mut().unwrap()
}
fn stage(r: &mut Reply) -> &mut proto::ProxyStageTiming {
    &mut report(r).stages[0]
}

#[test]
#[ignore = "requires existing browser PKI and generated task-1-parity runtime fixture; never skips"]
fn health_refuses_malformed_authenticated_responses() {
    let mutations: &[Mutation] = &[
        ("missing schema", |r| r.schema_version = 0),
        ("changed schema", |r| r.schema_version = 2),
        ("missing binding", |r| r.binding = None),
        ("changed installation", |r| {
            r.binding.as_mut().unwrap().installation_id.push('1')
        }),
        ("changed original fence", |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .fencing_token += 2
        }),
        ("changed instance", |r| {
            r.binding.as_mut().unwrap().process_instance_id.push('1')
        }),
        ("changed launch hash", |r| {
            r.binding.as_mut().unwrap().launch_context_hash.clear()
        }),
        ("missing nonce", |r| r.nonce.clear()),
        ("changed nonce", |r| r.nonce[0] ^= 1),
        ("large nonce", |r| r.nonce = vec![7; 4097]),
        ("oversized response", |r| r.nonce = vec![7; 32769]),
        ("missing sample", |r| r.sample = None),
        ("missing sample schema", |r| {
            r.sample.as_mut().unwrap().schema_version = 0
        }),
        ("changed sample schema", |r| {
            r.sample.as_mut().unwrap().schema_version = 2
        }),
        ("missing report", |r| {
            r.sample.as_mut().unwrap().report = None
        }),
        ("zero or absent validity", |r| {
            r.sample.as_mut().unwrap().valid_for_ns = 0
        }),
        ("already expired validity", |r| {
            r.sample.as_mut().unwrap().valid_for_ns = 1
        }),
        ("over limit validity", |r| {
            r.sample.as_mut().unwrap().valid_for_ns = 10_000_000_001
        }),
        ("max uint validity", |r| {
            r.sample.as_mut().unwrap().valid_for_ns = u64::MAX
        }),
        ("not live", |r| report(r).live = false),
        ("not ready", |r| report(r).ready = false),
        ("missing report target", |r| report(r).target = None),
        ("changed report target", |r| {
            report(r).target.as_mut().unwrap().generation += 1
        }),
        ("zero observed time", |r| report(r).observed_at_unix_us = 0),
        ("wrong config", |r| report(r).config_hash.clear()),
        ("wrong manifest", |r| {
            report(r).runtime_manifest_hash.clear()
        }),
        ("wrong launch", |r| report(r).launch_context_hash.clear()),
        ("wrong process", |r| report(r).process_instance_id.clear()),
        ("missing checks", |r| report(r).checks.clear()),
        ("missing check", |r| {
            report(r).checks.pop();
        }),
        ("extra check", |r| {
            let c = report(r).checks[0];
            report(r).checks.push(c);
        }),
        ("duplicate check", |r| report(r).checks[0].id = 2),
        ("unknown check", |r| report(r).checks[0].id = 99),
        ("absent check", |r| report(r).checks[0].id = 0),
        ("pending check", |r| report(r).checks[0].status = 1),
        ("unknown status", |r| report(r).checks[0].status = 99),
        ("missing status", |r| report(r).checks[0].status = 0),
        ("bad reason", |r| report(r).checks[0].reason = 2),
        ("unknown reason", |r| report(r).checks[0].reason = 99),
        ("missing reason", |r| report(r).checks[0].reason = 0),
        ("missing stages", |r| report(r).stages.clear()),
        ("missing stage", |r| {
            report(r).stages.pop();
        }),
        ("extra stage", |r| {
            let s = stage(r).clone();
            report(r).stages.push(s);
        }),
        ("duplicate stage", |r| {
            stage(r).name = "readiness.launch".into()
        }),
        ("unknown stage", |r| {
            stage(r).name = "readiness.other".into()
        }),
        ("oversized stage", |r| stage(r).name = "a".repeat(4097)),
        ("absent duration ns", |r| stage(r).duration_ns = None),
        ("inconsistent integer duration", |r| {
            stage(r).duration_us += 1
        }),
        ("zero stage start", |r| stage(r).started_at_unix_us = 0),
        ("zero resolution", |r| stage(r).clock_resolution_ns = 0),
        ("absent source", |r| stage(r).clock_source.clear()),
        ("oversized source", |r| {
            stage(r).clock_source = "a".repeat(129)
        }),
        ("control source", |r| {
            stage(r).clock_source = "clock\ncanary".into()
        }),
        ("nonascii source", |r| {
            stage(r).clock_source = "clocké".into()
        }),
        ("padded source", |r| stage(r).clock_source = " clock".into()),
        ("stage instance mismatch", |r| {
            stage(r).process_instance_id.clear()
        }),
        ("unowned trace", |r| stage(r).otel_trace_id = "a".repeat(32)),
        ("unowned span", |r| stage(r).span_id = "a".repeat(16)),
        ("unowned parent span", |r| {
            stage(r).parent_span_id = "a".repeat(16)
        }),
    ];
    let pki = pki::Pki::require();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for &(name, mutation) in mutations {
        let fixture = Fixture::new(&pki, Mode::Mutate(mutation));
        runtime.block_on(async {
            let mut client =
                RuntimeExecutionClient::connect(&fixture.config(&pki, pki::CONTROLLER), deadline())
                    .await
                    .unwrap();
            let (request, observed) = inputs();
            let result = client
                .observe_health(&request, &observed, deadline(), &|| Ok(()))
                .await;
            assert!(result.is_err(), "accepted {name}");
        });
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            1,
            "{name}: no retries"
        );
    }
}
