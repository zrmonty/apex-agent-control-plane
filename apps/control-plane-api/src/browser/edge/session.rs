use super::budget::Budget;
use super::*;
use crate::browser::{
    bundle::SessionBundle,
    rpc::OperatorAccess,
    security::{parse_app_cookies, verify_csrf},
    sessions::StoredSession,
    telemetry::{RequestContext, Stage},
};
use axum::{
    Extension, Json,
    extract::{Request, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(super) fn now() -> Result<i64, BrowserError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .ok_or(BrowserError::Unavailable)
}

pub(super) struct Loaded {
    pub row: StoredSession,
    pub bundle: SessionBundle,
}
pub(super) async fn load(
    state: &BrowserState,
    headers: &HeaderMap,
    csrf: bool,
    budget: Budget,
    trace: &RequestContext,
) -> Result<Loaded, BrowserError> {
    budget.check()?;
    if csrf {
        trace.stage_sync(Stage::Csrf, || {
            state
                .origin
                .verify(headers)
                .map_err(|_| BrowserError::Forbidden)
        })?;
    }
    let digest = parse_app_cookies(headers)
        .map_err(|_| BrowserError::Unauthenticated)?
        .session
        .ok_or(BrowserError::Unauthenticated)?;
    let row = trace
        .stage(Stage::SessionLoad, state.dependencies.sessions.load(digest))
        .await?
        .ok_or(BrowserError::Unauthenticated)?;
    budget.check()?;
    let bundle = trace.stage_sync(Stage::Crypto, || {
        SessionBundle::open(
            &row,
            state.dependencies.provider.config(),
            &state.dependencies.keys,
            now()?,
        )
    })?;
    if csrf {
        trace.stage_sync(Stage::Csrf, || {
            verify_csrf(headers, &row.csrf_binding).map_err(|_| BrowserError::Forbidden)
        })?;
    }
    budget.check()?;
    Ok(Loaded { row, bundle })
}

fn access(
    state: &BrowserState,
    loaded: &Loaded,
    budget: Budget,
) -> Result<OperatorAccess, BrowserError> {
    budget.check()?;
    if loaded.row.refresh_deadline.is_some() || loaded.bundle.access_expires_at <= now()? {
        return Err(BrowserError::Unavailable);
    }
    let access = OperatorAccess::verify(
        Zeroizing::new(loaded.bundle.access.to_string()),
        state.dependencies.resolver.as_ref(),
    )?;
    budget.check()?;
    if access.caller().subject() != format!("operator:keycloak:{}", loaded.row.identity.subject) {
        return Err(BrowserError::Unauthenticated);
    }
    Ok(access)
}

async fn touch(state: &BrowserState, loaded: &Loaded, budget: Budget) -> Result<(), BrowserError> {
    budget.check()?;
    if !state
        .dependencies
        .sessions
        .touch(
            loaded.row.identity.digest,
            loaded.row.generation,
            state.config.idle_timeout_secs,
        )
        .await?
    {
        return Err(BrowserError::Unauthenticated);
    }
    budget.check()?;
    if loaded.bundle.access_expires_at <= now()? {
        return Err(BrowserError::Unauthenticated);
    }
    Ok(())
}

pub(super) async fn get(
    State(state): State<Arc<BrowserState>>,
    headers: HeaderMap,
    Extension(budget): Extension<Budget>,
    Extension(trace): Extension<RequestContext>,
) -> Result<Response, BrowserError> {
    let loaded = load(&state, &headers, false, budget, &trace).await?;
    let loaded = super::refresh::ensure_fresh(&state, loaded, budget, &trace).await?;
    let access = trace.stage_sync(Stage::Auth, || access(&state, &loaded, budget))?;
    let scopes = access
        .caller()
        .scope_choices(&state.dependencies.global_scope_catalog)
        .map_err(|_| BrowserError::Unavailable)?;
    trace
        .stage(Stage::SessionTouch, touch(&state, &loaded, budget))
        .await?;
    let scopes: Vec<_> = scopes
        .iter()
        .map(|scope| json!({"workspaceId":scope.workspace_id,"namespaceId":scope.namespace_id}))
        .collect();
    trace.stage_sync(Stage::Serialization, || Ok(Json(json!({"subject":access.caller().subject(),"scopes":scopes,"csrfToken":loaded.bundle.csrf.expose_secret(),
        // This response is not a runtime health probe. Unimplemented approval
        // and trace handlers must not become enabled controls in the console.
        "capabilities":{"runtimeReadiness":"unknown","approvals":false,"traces":false}
    })).into_response()))
}

pub(super) async fn rpc(
    State(state): State<Arc<BrowserState>>,
    request: Request,
) -> Result<Response, BrowserError> {
    use crate::browser::rpc::{MAX_RPC_JSON_BYTES, ManagementRequest};
    let (parts, body) = request.into_parts();
    let budget = *parts
        .extensions
        .get::<Budget>()
        .ok_or(BrowserError::Unavailable)?;
    let trace = parts
        .extensions
        .get::<RequestContext>()
        .ok_or(BrowserError::Unavailable)?;
    let loaded = load(&state, &parts.headers, true, budget, trace).await?;
    let bytes = axum::body::to_bytes(body, MAX_RPC_JSON_BYTES)
        .await
        .map_err(|_| BrowserError::PayloadTooLarge)?;
    budget.check()?;
    let decoded = trace.stage_sync(Stage::Decode, || {
        ManagementRequest::decode(parts.uri.path(), &parts.headers, &bytes)
    })?;
    let loaded = super::refresh::ensure_fresh(&state, loaded, budget, trace).await?;
    let access = trace.stage_sync(Stage::Auth, || access(&state, &loaded, budget))?;
    trace
        .stage(Stage::SessionTouch, touch(&state, &loaded, budget))
        .await?;
    let output = trace
        .stage(
            Stage::Management,
            state.dependencies.management.forward(decoded, &access),
        )
        .await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], output).into_response())
}

pub(super) async fn logout(
    State(state): State<Arc<BrowserState>>,
    headers: HeaderMap,
    Extension(budget): Extension<Budget>,
    Extension(trace): Extension<RequestContext>,
) -> Result<Response, BrowserError> {
    use crate::browser::security::{AppCookie, clear_cookie};
    let loaded = load(&state, &headers, true, budget, &trace).await?;
    // Logout does not refresh or require still-valid access authority. The
    // bound CSRF proves control of this session; revocation can only reduce it.
    trace
        .stage(
            Stage::LocalRevoke,
            state
                .dependencies
                .sessions
                .revoke(loaded.row.identity.digest),
        )
        .await?;
    budget.check()?;
    // The durable local result wins even when provider revocation fails. No
    // background retry or external logout redirect may resurrect this session.
    let _ = trace
        .stage(
            Stage::Provider,
            state.dependencies.provider.revoke(&loaded.bundle.refresh),
        )
        .await;
    Ok((
        axum::http::StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie(AppCookie::Session))],
    )
        .into_response())
}
