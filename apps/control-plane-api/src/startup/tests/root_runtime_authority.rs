//! Actual production run_until in an isolated exact-test child, never env mutation.
#[path = "root_runtime_authority/child.rs"]
mod child;
#[path = "root_runtime_authority/config.rs"]
mod config;
#[path = "root_runtime_authority/harness.rs"]
mod harness;
#[allow(dead_code)]
#[path = "../../../tests/proxy_runtime_authority/material.rs"]
mod material;
#[allow(dead_code)]
#[path = "../../../tests/proxy_runtime_operation/support.rs"]
mod operation;
#[allow(dead_code)]
#[path = "../../../tests/../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
#[allow(dead_code)]
#[path = "../../../tests/proxy_operation_recovery/support.rs"]
mod recovery;
use super::root_browser::support;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Live,
    Disabled,
    Partial,
    Missing,
    Occupied,
    Immediate,
}

macro_rules! cases {
    ($(($name:ident, $case:ident)),+ $(,)?) => { $(
        #[test]
        fn $name() {
            let selector = concat!("startup::tests::root_runtime_authority::", stringify!($name));
            harness::run(Case::$case, selector);
        }
    )+ };
}
cases! {
    (production_root_registers_actual_tls_pg_callback, Live),
    (unconfigured_production_root_has_no_callback_route, Disabled),
    (partial_configuration_refuses_before_listener_start, Partial),
    (missing_initial_metadata_refuses_before_listener_start, Missing),
    (occupied_listener_retains_and_cleans_authority_workers, Occupied),
    (immediate_shutdown_cleans_workers_before_any_callback, Immediate),
}
