//! Tests for [`super`], grouped the same way the implementation is:
//! `submit`/`bulk` (the write path), `admission` (the shared per-operator
//! rate ceiling `submit` exercises it through), `poll` (the agent-facing
//! path), `query` (the operator query/management path), and `force_stop`
//! (the dual-approval gate). `support` holds the fixtures shared across more
//! than one of those groups.

mod admission;
mod bulk;
mod force_stop;
mod poll;
mod query;
mod submit;
mod support;
