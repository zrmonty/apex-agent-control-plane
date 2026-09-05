use super::*;
use super::{budget::Budget, session::now};
use crate::browser::{
    bundle::{LoginBinding, LoginBundle, SessionBundle},
    callback::CallbackRequest,
    security::{AppCookie, CsrfToken, OpaqueToken, parse_app_cookies, set_cookie},
    sessions::{NewSession, SessionIdentity},
    telemetry::{RequestContext, Stage},
};
use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

pub(super) async fn start(
    State(state): State<Arc<BrowserState>>,
    request: Request,
) -> Result<Response, BrowserError> {
    let budget = *request
        .extensions()
        .get::<Budget>()
        .ok_or(BrowserError::Unavailable)?;
    let trace = request
        .extensions()
        .get::<RequestContext>()
        .ok_or(BrowserError::Unavailable)?;
    budget.check()?;
    let cookies =
        parse_app_cookies(request.headers()).map_err(|_| BrowserError::Unauthenticated)?;
    // One permanent PG bucket is shared by every replica. Spend admission
    // before discovery/entropy/provider work; cancellation and failure do not
    // refund it. Anonymous cookies and forwarded IP headers are not identities.
    let admitted = trace
        .stage(
            Stage::LoginAdmission,
            state.dependencies.sessions.admit_login(),
        )
        .await?;
    budget.check()?;
    let challenge = trace
        .stage(
            Stage::Provider,
            state.dependencies.provider.authorization_challenge(),
        )
        .await?;
    budget.check()?;
    // Existing valid binding cookies are reused without extending their age,
    // allowing independent attempts in multiple tabs during the original 10m.
    let token = if cookies.login.is_none() {
        Some(OpaqueToken::generate().map_err(|_| BrowserError::Unavailable)?)
    } else {
        None
    };
    let browser = cookies
        .login
        .or_else(|| token.as_ref().map(OpaqueToken::lookup_digest))
        .ok_or(BrowserError::Unavailable)?;
    let now = now()?;
    if admitted.expires_at <= now {
        return Err(BrowserError::Unavailable);
    }
    let row = trace.stage_sync(Stage::Crypto, || {
        LoginBundle {
            pkce: challenge.pkce,
            nonce: challenge.nonce,
        }
        .seal(
            &LoginBinding {
                state: challenge.state.lookup_digest(),
                browser,
                expires_at: admitted.expires_at,
            },
            state.dependencies.provider.config(),
            &state.dependencies.keys,
            now,
        )
    })?;
    let mut location =
        HeaderValue::from_str(challenge.url.as_str()).map_err(|_| BrowserError::Unavailable)?;
    location.set_sensitive(true);
    budget.check()?;
    trace
        .stage(
            Stage::SessionCommit,
            state.dependencies.sessions.create_login(row),
        )
        .await?;
    budget.check()?;
    let mut response = (StatusCode::FOUND, [(header::LOCATION, location)]).into_response();
    if let Some(token) = token {
        let cookie_age = u64::try_from(
            admitted
                .expires_at
                .checked_sub(session::now()?)
                .filter(|remaining| *remaining > 0)
                .ok_or(BrowserError::Unavailable)?,
        )
        .map_err(|_| BrowserError::Unavailable)?
        .min(600);
        response.headers_mut().append(
            header::SET_COOKIE,
            set_cookie(AppCookie::Login, &token, cookie_age)
                .map_err(|_| BrowserError::Unavailable)?,
        );
    }
    Ok(response)
}

pub(super) async fn callback(
    State(state): State<Arc<BrowserState>>,
    request: Request,
) -> Result<Response, BrowserError> {
    let budget = *request
        .extensions()
        .get::<Budget>()
        .ok_or(BrowserError::Unavailable)?;
    let trace = request
        .extensions()
        .get::<RequestContext>()
        .ok_or(BrowserError::Unavailable)?;
    budget.check()?;
    let callback = trace.stage_sync(Stage::Decode, || {
        CallbackRequest::parse(request.uri().query())
    })?;
    let browser = parse_app_cookies(request.headers())
        .map_err(|_| BrowserError::Unauthenticated)?
        .login
        .ok_or(BrowserError::Unauthenticated)?;
    // Take and commit before any provider I/O. A matched denial, bad issuer,
    // provider outage or lost reply consumes the same one-use attempt.
    let row = trace
        .stage(
            Stage::SessionCommit,
            state
                .dependencies
                .sessions
                .take_login(callback.state, browser),
        )
        .await?
        .ok_or(BrowserError::Unauthenticated)?;
    budget.check()?;
    let config = state.dependencies.provider.config();
    let bundle = trace.stage_sync(Stage::Crypto, || {
        LoginBundle::open(&row, config, &state.dependencies.keys, now()?)
    })?;
    if callback.denied
        || callback
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer != config.issuer)
    {
        return Err(BrowserError::Unauthenticated);
    }
    let code = callback
        .code
        .as_deref()
        .ok_or(BrowserError::InvalidRequest)?;
    budget.check()?;
    let verified = trace
        .stage(
            Stage::Provider,
            state.dependencies.provider.login(
                code,
                bundle.pkce.expose_secret(),
                bundle.nonce.expose_secret(),
            ),
        )
        .await?;
    budget.check()?;
    let token = OpaqueToken::generate().map_err(|_| BrowserError::Unavailable)?;
    let csrf = CsrfToken::generate().map_err(|_| BrowserError::Unavailable)?;
    let now = now()?;
    let identity = SessionIdentity {
        digest: token.lookup_digest(),
        issuer: config.issuer.clone(),
        client_id: config.client_id.clone(),
        subject: verified.subject,
        absolute_expires_at: now
            .checked_add(i64::from(state.config.session_max_age_secs))
            .ok_or(BrowserError::Unavailable)?,
    };
    let payload = SessionBundle {
        access: verified.access,
        refresh: verified.refresh,
        nonce: bundle.nonce,
        csrf,
        generation: 0,
        access_expires_at: verified.access_expires_at,
        refresh_expires_at: verified.refresh_expires_at,
    };
    let input = NewSession {
        envelope: trace.stage_sync(Stage::Crypto, || {
            payload.seal(&identity, &state.dependencies.keys, now)
        })?,
        identity,
        csrf_binding: payload.csrf.binding(),
        access_expires_at: payload.access_expires_at,
        refresh_expires_at: payload.refresh_expires_at,
        idle_timeout_secs: state.config.idle_timeout_secs,
    };
    let cookie = set_cookie(
        AppCookie::Session,
        &token,
        u64::from(state.config.session_max_age_secs),
    )
    .map_err(|_| BrowserError::Unavailable)?;
    budget.check()?;
    trace
        .stage(
            Stage::SessionCommit,
            state.dependencies.sessions.create_session(input),
        )
        .await?;
    budget.check()?;
    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/")),
            (header::SET_COOKIE, cookie),
        ],
    )
        .into_response())
}
