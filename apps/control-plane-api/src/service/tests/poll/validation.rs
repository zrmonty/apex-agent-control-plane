// Agent polling tests for validation.

#[tokio::test]
async fn submit_command_rejects_a_negative_budget_limit() {
    let service = service();
    let mut request = stop_request();
    request.action = proto::ControlAction::SetBudget as i32;
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(
        "budget_kind".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("tokens".to_owned())),
        },
    );
    fields.insert(
        "limit".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(-1.0)),
        },
    );
    request.parameters = Some(ProstStruct {
        fields: fields.into_iter().collect(),
    });
    let status = service
        .submit_command(authed_request(request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
