//! Real journal and protected Unix HTTP transport; only the daemon peer is scripted.
use super::*;
use crate::execution::engine::health::tests::fixture::{
    Fixture, Request, frame, inspection, read_request, response,
};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, sync::mpsc, thread::JoinHandle};

mod cleanup;
mod recovery;
mod support;
use support::*;
