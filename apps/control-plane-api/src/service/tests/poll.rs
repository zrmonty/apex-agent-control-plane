//! The agent-facing path: `PollCommands` and `AckCommand`.

use prost_types::Struct as ProstStruct;

use crate::inbox::*;
use crate::proto;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

// --- PollCommands ---------------------------------------------------

include!("poll/delivery.rs");
include!("poll/authorization.rs");
include!("poll/rate_limits.rs");
include!("poll/validation.rs");
