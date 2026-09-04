use crate::proto;

const WORKSPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e80";
const NAMESPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e81";
const OTHER_WORKSPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e82";
const OTHER_NAMESPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e83";
const PROXY_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
const REQUEST_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85";

fn create_proxy_request() -> proto::CreateProxyRequest {
    proto::CreateProxyRequest {
        request_id: Some(REQUEST_ID.to_owned()),
        workspace_id: WORKSPACE_ID.to_owned(),
        namespace_id: NAMESPACE_ID.to_owned(),
        proxy_id: PROXY_ID.to_owned(),
        display_name: "Research MCP proxy".to_owned(),
        slug: "research-mcp-proxy".to_owned(),
        description: Some("Managed proxy for research workflows".to_owned()),
        owner: Some("research-ops".to_owned()),
        tags: vec!["mcp".to_owned(), "research".to_owned()],
    }
}

fn duplicate_idempotency_key_request() -> proto::CreateProxyRequest {
    let mut request = create_proxy_request();
    request.display_name = "Research MCP proxy duplicate".to_owned();
    request
}

fn cross_scope_request() -> proto::CreateProxyRequest {
    let mut request = create_proxy_request();
    request.workspace_id = OTHER_WORKSPACE_ID.to_owned();
    request.namespace_id = OTHER_NAMESPACE_ID.to_owned();
    request
}

#[test]
fn create_proxy_request_fixture_uses_lowercase_uuidv7_ids() {
    let request = create_proxy_request();
    assert_eq!(request.request_id, Some(REQUEST_ID.to_owned()));
    assert_eq!(request.workspace_id, WORKSPACE_ID);
    assert_eq!(request.namespace_id, NAMESPACE_ID);
    assert_eq!(request.proxy_id, PROXY_ID);
}

#[test]
fn duplicate_idempotency_key_request_reuses_the_same_request_id() {
    let request = duplicate_idempotency_key_request();
    assert_eq!(request.request_id, Some(REQUEST_ID.to_owned()));
    assert_eq!(request.workspace_id, WORKSPACE_ID);
    assert_eq!(request.namespace_id, NAMESPACE_ID);
}

#[test]
fn cross_scope_request_targets_a_different_workspace_and_namespace() {
    let request = cross_scope_request();
    assert_eq!(request.request_id, Some(REQUEST_ID.to_owned()));
    assert_eq!(request.workspace_id, OTHER_WORKSPACE_ID);
    assert_eq!(request.namespace_id, OTHER_NAMESPACE_ID);
}
