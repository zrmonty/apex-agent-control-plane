use super::{Case, flow, pg, support};
use std::{
    cell::Cell,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    time::{Duration, Instant},
};

pub(super) fn run(case: Case) {
    // Never print panic payloads: upstream assertions may contain URLs, cookies,
    // or server bodies. Preserve only a stable category and source location.
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if payload.contains("Cannot start a runtime") || payload.contains("Cannot drop a runtime") {
            eprintln!("ROOT_BROWSER_ENTERED_RUNTIME_PANIC");
        }
        if let Some(location) = info.location() {
            // Source basename only: no machine paths or panic payload. The
            // parent accepts only bounded Rust filenames and numeric lines.
            let file = location
                .file()
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("unknown.rs");
            eprintln!("ROOT_BROWSER_PANIC {}:{}", file, location.line());
        } else {
            eprintln!("ROOT_BROWSER_PANIC");
        }
    }));
    support::require_platform();
    assert!(tokio::runtime::Handle::try_current().is_err());
    let root_app = support::required(support::ROOT_APP);
    let observer_url = support::required(support::OBSERVER);
    let mut observer = pg::observer(&observer_url);
    assert_eq!(pg::connections(&mut observer, &root_app), 0);
    let control: SocketAddr = support::required("APEX_CONTROL_BIND_ADDR").parse().unwrap();
    let browser: SocketAddr = support::required(support::BROWSER_ADDR).parse().unwrap();
    assert!(control.ip().is_loopback() && browser.ip().is_loopback());
    assert!(control.port() != 0 && browser.port() != 0);
    let pki = support::Pki::require();
    let entered = Cell::new(None::<Instant>);
    let completed = Cell::new(false);
    let outcome = if case == Case::BrowserJourney {
        super::ui::run(control, browser, &pki, &mut observer, &root_app);
        Ok(())
    } else {
        crate::startup::service::run_until(async {
            entered.set(Some(Instant::now()));
            // This first poll is in the supervisor, after actual gRPC task spawn.
            pg::assert_active(observer_url.clone(), root_app.clone(), case.browser());
            match case {
                Case::Live => flow::live(control, browser, &pki).await,
                Case::Immediate => {}
                Case::Disabled => {
                    flow::control_ready(control, &pki).await;
                    assert!(
                        TcpListener::bind(browser).is_ok(),
                        "disabled browser unexpectedly bound HTTP"
                    );
                }
                Case::WrongCa | Case::WrongName => std::future::pending::<()>().await,
                Case::OccupiedBrowser | Case::OccupiedControl => {
                    panic!("occupied socket must fail before supervisor")
                }
                Case::BrowserJourney => unreachable!(),
            }
            completed.set(true);
        })
    };
    // This point is inside the still-running exact-test child, not after exit.
    assert!(tokio::runtime::Handle::try_current().is_err());
    pg::wait_for_zero(&mut observer, &root_app);
    pg::assert_schema(&mut observer, case.browser());
    match case {
        Case::BrowserJourney => {
            assert!(outcome.is_ok());
            pg::assert_logout(&mut observer);
        }
        Case::Live | Case::Disabled | Case::Immediate => {
            assert!(
                outcome.is_ok(),
                "production root normal shutdown returned an error"
            );
            assert!(
                entered.get().is_some() && completed.get(),
                "shutdown future did not finish the live probes"
            );
            if case == Case::Live {
                pg::assert_logout(&mut observer);
            }
        }
        Case::OccupiedBrowser | Case::OccupiedControl => {
            assert!(entered.get().is_none());
            let error = outcome.expect_err("occupied listener must fail startup");
            assert!(
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse),
                "must fail for the occupied socket, not missing material or fixture configuration"
            );
        }
        Case::WrongCa | Case::WrongName => {
            let started = entered
                .get()
                .expect("bridge test must reach supervisor after gRPC spawn");
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "bridge error cleanup exceeded its bound"
            );
            assert!(!completed.get());
            let error = outcome.expect_err("wrong management TLS identity must fail closed");
            assert!(
                error.to_string() == "browser management mTLS connection unavailable",
                "expected post-spawn management bridge error, not a material-loader error"
            );
        }
    }
    if case != Case::OccupiedControl {
        assert!(
            TcpListener::bind(control).is_ok(),
            "root control socket survived shutdown"
        );
    }
    if case != Case::OccupiedBrowser {
        assert!(
            TcpListener::bind(browser).is_ok(),
            "root browser socket survived shutdown"
        );
    }
    println!("{}", support::CLEAN);
    std::io::stdout().flush().unwrap();
    // Parent verifies zero connections independently while this child is alive.
    // Its hard deadline and RAII kill/reap guard bound a lost acknowledgement.
    let mut ack = [0];
    std::io::stdin()
        .read_exact(&mut ack)
        .expect("parent did not acknowledge live cleanup");
    assert_eq!(ack, [b'!']);
}
