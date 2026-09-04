#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyError {
    code: &'static str,
    message: &'static str,
}

impl ProxyError {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }

    pub fn invalid_proxy_draft(message: &'static str) -> Self {
        Self::new("INVALID_PROXY_DRAFT", message)
    }

    pub fn invalid_proxy_scope() -> Self {
        Self::new(
            "INVALID_PROXY_SCOPE",
            "Proxy drafts require an exact workspace and namespace scope.",
        )
    }

    pub fn invalid_proxy_spec(message: &'static str) -> Self {
        Self::new("INVALID_PROXY_SPEC", message)
    }

    pub fn unknown_transport() -> Self {
        Self::new(
            "UNKNOWN_PROXY_TRANSPORT",
            "Proxy configuration uses an unsupported transport.",
        )
    }

    pub fn invalid_request_id() -> Self {
        Self::new(
            "INVALID_PROXY_REQUEST_ID",
            "Proxy mutations require a lowercase UUIDv7 request_id.",
        )
    }

    pub fn idempotency_conflict() -> Self {
        Self::new(
            "PROXY_IDEMPOTENCY_CONFLICT",
            "request_id was already used for a different proxy mutation payload.",
        )
    }

    pub fn identity_conflict() -> Self {
        Self::new(
            "PROXY_IDENTITY_CONFLICT",
            "A proxy with this identity already exists in the requested scope.",
        )
    }

    pub fn revision_conflict() -> Self {
        Self::new(
            "PROXY_REVISION_CONFLICT",
            "The proxy changed since the caller's expected revision.",
        )
    }

    pub fn proxy_not_found() -> Self {
        Self::new(
            "PROXY_NOT_FOUND",
            "No proxy with that identity exists in the requested scope.",
        )
    }

    pub fn revision_not_found() -> Self {
        Self::new(
            "PROXY_REVISION_NOT_FOUND",
            "No proxy revision with that identity exists in the requested scope.",
        )
    }

    pub fn immutable_revision() -> Self {
        Self::new(
            "IMMUTABLE_PROXY_REVISION",
            "Published proxy revisions are immutable and cannot be edited in place.",
        )
    }

    pub fn invalid_cursor() -> Self {
        Self::new("INVALID_PROXY_CURSOR", "The proxy list cursor is invalid.")
    }

    pub fn invalid_lifecycle_transition() -> Self {
        Self::new(
            "INVALID_PROXY_LIFECYCLE_TRANSITION",
            "The requested proxy lifecycle transition is not allowed.",
        )
    }

    pub fn approval_required() -> Self {
        Self::new(
            "PROXY_APPROVAL_REQUIRED",
            "Proxy deployment requires an approved immutable revision.",
        )
    }

    pub fn activity_unavailable() -> Self {
        Self::new(
            "PROXY_ACTIVITY_UNAVAILABLE",
            "Durable proxy activity is not available.",
        )
    }

    pub fn runtime_unavailable() -> Self {
        Self::new(
            "PROXY_RUNTIME_UNAVAILABLE",
            "The proxy runtime provider is not available.",
        )
    }

    pub fn event_sink_unavailable() -> Self {
        Self::new(
            "PROXY_EVENT_SINK_UNAVAILABLE",
            "The durable proxy event sink is not available.",
        )
    }

    pub fn provider_failed() -> Self {
        Self::new(
            "PROXY_PROVIDER_FAILED",
            "The proxy runtime provider rejected the requested operation.",
        )
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProxyError {}
