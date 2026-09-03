use apex_domain::{is_lowercase_uuidv7, is_scope_identifier};

use crate::{GovernanceInputError, IdentifierKind};

macro_rules! validated_identifier {
    ($name:ident, $kind:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses a bounded identifier without retaining invalid input.
            pub fn new(value: impl Into<String>) -> Result<Self, GovernanceInputError> {
                let value = value.into();
                if is_scope_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(GovernanceInputError::InvalidIdentifier {
                        kind: IdentifierKind::$kind,
                    })
                }
            }

            /// Returns the validated identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns the validated identifier as an owned string.
            pub fn into_string(self) -> String {
                self.0
            }
        }
    };
}

validated_identifier!(ToolName, ToolName, "A validated MCP or tool-registry name.");
validated_identifier!(
    ActionName,
    ActionName,
    "A validated action name for a tool call."
);
validated_identifier!(
    ResourceName,
    ResourceName,
    "A validated resource reference addressed by a tool call."
);
validated_identifier!(PolicyId, PolicyId, "A validated policy identity.");
validated_identifier!(
    ReasonCode,
    ReasonCode,
    "A validated machine-readable policy reason code."
);
validated_identifier!(BackendName, BackendName, "A validated backend identity.");
validated_identifier!(
    FieldPath,
    FieldPath,
    "A validated field path used by response filtering."
);
validated_identifier!(
    TraceId,
    TraceId,
    "A validated distributed trace identifier."
);
validated_identifier!(
    SpanId,
    SpanId,
    "A validated distributed-trace span identifier."
);
validated_identifier!(RunId, RunId, "A validated agent run identifier.");

/// A validated UUIDv7 identifier allocated to a durably admitted Apex event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventId(String);

impl EventId {
    /// Parses a lowercase UUIDv7 event identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, GovernanceInputError> {
        let value = value.into();
        if is_lowercase_uuidv7(&value) {
            Ok(Self(value))
        } else {
            Err(GovernanceInputError::InvalidIdentifier {
                kind: IdentifierKind::EventId,
            })
        }
    }

    /// Returns the event identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated workspace and namespace pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GovernanceScope {
    workspace_id: String,
    namespace_id: String,
}

impl GovernanceScope {
    /// Creates a scope from validated workspace and namespace identifiers.
    pub fn new(
        workspace_id: impl Into<String>,
        namespace_id: impl Into<String>,
    ) -> Result<Self, GovernanceInputError> {
        let workspace_id = workspace_id.into();
        let namespace_id = namespace_id.into();
        if !is_scope_identifier(&workspace_id) || !is_scope_identifier(&namespace_id) {
            return Err(GovernanceInputError::InvalidScope);
        }
        Ok(Self {
            workspace_id,
            namespace_id,
        })
    }

    /// Returns the validated workspace identifier.
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Returns the validated namespace identifier.
    pub fn namespace_id(&self) -> &str {
        &self.namespace_id
    }

    /// Returns the canonical scope key used by the existing caller boundary.
    pub fn key(&self) -> String {
        format!("{}/{}", self.workspace_id, self.namespace_id)
    }
}

/// Distributed trace and optional run correlation carried through governance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceContext {
    trace_id: TraceId,
    span_id: Option<SpanId>,
    parent_span_id: Option<SpanId>,
    run_id: Option<RunId>,
}

impl TraceContext {
    /// Creates a trace context with a required trace ID and optional span/run IDs.
    pub fn new<T, S, P, R>(
        trace_id: T,
        span_id: Option<S>,
        parent_span_id: Option<P>,
        run_id: Option<R>,
    ) -> Result<Self, GovernanceInputError>
    where
        T: Into<String>,
        S: Into<String>,
        P: Into<String>,
        R: Into<String>,
    {
        Ok(Self {
            trace_id: TraceId::new(trace_id)?,
            span_id: span_id.map(SpanId::new).transpose()?,
            parent_span_id: parent_span_id.map(SpanId::new).transpose()?,
            run_id: run_id.map(RunId::new).transpose()?,
        })
    }

    /// Returns the required trace identifier.
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Returns the optional current span identifier.
    pub fn span_id(&self) -> Option<&SpanId> {
        self.span_id.as_ref()
    }

    /// Returns the optional parent span identifier.
    pub fn parent_span_id(&self) -> Option<&SpanId> {
        self.parent_span_id.as_ref()
    }

    /// Returns the optional agent run identifier.
    pub fn run_id(&self) -> Option<&RunId> {
        self.run_id.as_ref()
    }
}
