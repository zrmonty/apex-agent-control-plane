//! Actual binary-root startup regressions, not a separately assembled BFF.
//!
//! Main registers this module under `postgres` and owns Cargo execution. Each
//! test re-executes its exact libtest selector with child-only environment.
//! Required fixtures are the owned loopback PG/Keycloak and trusted-host PKI;
//! missing fixtures fail, never skip. Windows additionally requires the existing
//! `test-support` ACL waiver, which is not production permission evidence.
//!
//! A child checks zero root-named PG connections AFTER run_until returns, then
//! waits for its parent to observe the same fact while it is still alive.
//! No RED/GREEN execution is claimed by adding these tests. In particular, a
//! missing material-loader implementation is not root-lifecycle TDD evidence.
//! This covers neither external HTTPS termination nor connected NATS/Valkey,
//! runtime provisioning, refresh races, or complete Task 3 acceptance.

use postgres::{Client, NoTls};

#[allow(dead_code)]
#[path = "../../../tests/browser_session_store/support.rs"]
mod database;
#[path = "../../../tests/browser_keycloak_flow/login.rs"]
mod login;

#[path = "root_browser/child.rs"]
mod child;
#[path = "root_browser/config.rs"]
mod config;
#[path = "root_browser/flow.rs"]
mod flow;
#[path = "root_browser/harness.rs"]
mod harness;
#[path = "root_browser/pg.rs"]
mod pg;
#[path = "root_browser/support.rs"]
pub(super) mod support;
#[path = "root_browser/ui.rs"]
mod ui;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Live,
    BrowserJourney,
    Immediate,
    Disabled,
    OccupiedBrowser,
    OccupiedControl,
    WrongCa,
    WrongName,
}

impl Case {
    fn browser(self) -> bool {
        self != Self::Disabled
    }
}

macro_rules! root_test {
    ($name:ident, $case:ident) => {
        #[test]
        fn $name() {
            harness::run(
                Case::$case,
                concat!("startup::tests::root_browser::", stringify!($name)),
            );
        }
    };
}

root_test!(
    root_browser_pkce_session_scopes_and_persistent_management,
    Live
);
root_test!(
    root_browser_chromium_create_reload_outage_restart_logout,
    BrowserJourney
);
root_test!(
    root_browser_immediate_shutdown_releases_postgres_owners,
    Immediate
);
root_test!(
    root_browser_disabled_shutdown_releases_postgres_owners,
    Disabled
);
root_test!(
    root_browser_occupied_browser_port_releases_owners,
    OccupiedBrowser
);
root_test!(
    root_browser_occupied_control_port_releases_owners,
    OccupiedControl
);
root_test!(
    root_browser_wrong_management_ca_cleans_up_after_spawn,
    WrongCa
);
root_test!(
    root_browser_wrong_management_name_cleans_up_after_spawn,
    WrongName
);
