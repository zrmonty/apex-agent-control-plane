//! Same-origin routing and one owning, redacted observation per HTTP request.
use super::budget::Budget;
use super::*;
use crate::browser::errors::secure_api_response;
use crate::browser::telemetry::{Action, Stage, Status};
use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};

pub(super) fn router(state: Arc<BrowserState>) -> Router {
    Router::new()
        .route("/api/session", get(super::session::get))
        .route("/api/apex/v1/{service}/{method}", post(super::session::rpc))
        .route("/auth/logout", post(super::session::logout))
        .route("/auth/login", get(super::login::start))
        .route("/auth/callback", get(super::login::callback))
        .fallback(|| async { BrowserError::NotFound })
        .method_not_allowed_fallback(|| async { BrowserError::MethodNotAllowed })
        .layer(middleware::from_fn_with_state(Arc::clone(&state), boundary))
        .with_state(state)
}

async fn boundary(
    State(state): State<Arc<BrowserState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let action = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/auth/login") => Action::Login,
        ("GET", "/auth/callback") => Action::Callback,
        ("GET", "/api/session") => Action::Session,
        ("POST", "/auth/logout") => Action::Logout,
        ("POST", path)
            if crate::browser::rpc::descriptors()
                .iter()
                .any(|method| method.path == path) =>
        {
            Action::Management
        }
        _ => Action::Rejected,
    };
    let trace = state.dependencies.telemetry.begin(action);
    let context = trace.context();
    request.extensions_mut().insert(context.clone());
    let mut timed_out = false;
    let result = context
        .stage(Stage::Ingress, async {
            let _permit = state
                .slots
                .try_acquire()
                .map_err(|_| BrowserError::RateLimited)?;
            let budget = Budget::new(state.config.request_timeout)?;
            request.extensions_mut().insert(budget);
            let result = budget.run(next.run(request)).await;
            timed_out = result.is_err();
            result
        })
        .await;
    let mut response = result.unwrap_or_else(IntoResponse::into_response);
    secure_api_response(&mut response);
    let status = if timed_out {
        Status::Timeout
    } else {
        response_status(response.status().as_u16())
    };
    state.dependencies.telemetry.export(&trace.finish(status));
    response
}

fn response_status(status: u16) -> Status {
    match status {
        200..=399 => Status::Ok,
        400 => Status::InvalidRequest,
        401 => Status::Unauthorized,
        403 => Status::Forbidden,
        404 => Status::NotFound,
        405 => Status::MethodNotAllowed,
        409 => Status::Conflict,
        413 => Status::PayloadTooLarge,
        429 => Status::RateLimited,
        _ => Status::Unavailable,
    }
}
