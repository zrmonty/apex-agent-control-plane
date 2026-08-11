//! Tests for [`super`], grouped the same way the implementation is:
//! `state` (the shared in-memory delivery decision logic and `ListCommands`
//! enumeration over it), `file` (the durable journal wrapper), and `backend`
//! (the single-mutex serialization guarantee). `support` holds the fixtures
//! shared across more than one of those groups.

mod backend;
mod file;
mod state;
mod support;
