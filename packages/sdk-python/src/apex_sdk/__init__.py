"""Small, framework-neutral instrumentation primitives for Apex."""

from .control import ControlAction, ControlCommand, ControlValidationError
from .errors import ConfigurationError, EventIntegrityError, TelemetryMappingError
from .exporter import BoundedGrpcExporter, ExportDeliveryError
from .event import EventBuilder, canonical_event_bytes, event_hash
from .observer import BoundedObserver, JsonlSink, ObserverStats
from .telemetry import to_otel_attributes
from .reference_runtime import ReferenceReasonActLoop
from .validation import EventValidationError, validate_event
from .template import (
    CONTROL_FRAMEWORK_MAP,
    GOLD_STANDARD_CONTROLS,
    TEMPLATE_VERSION,
    AgentTemplateError,
    TemplateAssessment,
    assess_agent_template,
)

__all__ = ["AgentTemplateError", "BoundedGrpcExporter", "BoundedObserver", "ConfigurationError", "ControlAction", "ControlCommand", "ControlValidationError", "EventBuilder", "EventIntegrityError", "EventValidationError", "ExportDeliveryError", "JsonlSink", "ObserverStats", "ReferenceReasonActLoop", "TemplateAssessment", "TelemetryMappingError", "CONTROL_FRAMEWORK_MAP", "GOLD_STANDARD_CONTROLS", "TEMPLATE_VERSION", "assess_agent_template", "canonical_event_bytes", "event_hash", "to_otel_attributes", "validate_event"]
