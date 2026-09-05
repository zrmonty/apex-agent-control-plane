use super::{
    Case, config,
    pki::{self, Pki},
};
use apex_control_plane_api::proto::{
    CheckRuntimeAuthorityRequest, runtime_authority_service_client::RuntimeAuthorityServiceClient,
};
use apex_durability::PostgresClientOps;
use std::{
    cell::Cell,
    io::{Read, Write},
    time::{Duration, Instant},
};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

pub(super) fn connections(url: &str, name: &str) -> i64 {
    let mut client =
        apex_durability::connect_postgres_for_worker(url).expect("bounded real root observer");
    client.query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND pid<>pg_backend_pid()",
        &[&name]).unwrap().get(0)
}

pub(super) fn run(case: Case) {
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            let file = location
                .file()
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("unknown.rs");
            eprintln!("ROOT_AUTHORITY_PANIC {file}:{}", location.line());
        } else {
            eprintln!("ROOT_AUTHORITY_PANIC");
        }
    }));
    super::support::require_platform();
    apex_control_plane_api::install_rustls_provider();
    let url = std::env::var("APEX_CONTROL_POSTGRES_URL").unwrap();
    let name = std::env::var(config::APPLICATION).unwrap();
    assert_eq!(connections(&url, &name), 0);
    let pki = Pki::require();
    let request: CheckRuntimeAuthorityRequest =
        serde_json::from_slice(&std::fs::read(std::env::var_os(config::QUERY).unwrap()).unwrap())
            .unwrap();
    let expected = request.clone();
    let address = std::env::var("APEX_CONTROL_BIND_ADDR").unwrap();
    let entered = Cell::new(false);
    let callback = Cell::new(None);
    let result = crate::startup::service::run_until(async {
        entered.set(true);
        if case == Case::Immediate {
            let (url, name) = (url.clone(), name.clone());
            let actual = std::thread::spawn(move || connections(&url, &name))
                .join()
                .unwrap();
            assert!(
                actual >= 4,
                "real authority worker initialized before first callback"
            );
        }
        if matches!(case, Case::Live | Case::Disabled) {
            let tls = ClientTlsConfig::new()
                .domain_name("control-plane-api")
                .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
                .identity(pki.identity("trusted-host", pki::AGENT));
            let endpoint = Endpoint::from_shared(format!("https://{address}"))
                .unwrap()
                .tls_config(tls)
                .unwrap()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(6));
            let channel = tokio::time::timeout(Duration::from_secs(8), endpoint.connect())
                .await
                .unwrap()
                .unwrap();
            let response = RuntimeAuthorityServiceClient::new(channel)
                .check_runtime_authority(request)
                .await;
            callback.set(Some(response));
        }
    });
    assert!(tokio::runtime::Handle::try_current().is_err());
    let until = Instant::now() + Duration::from_secs(8);
    while connections(&url, &name) != 0 {
        assert!(
            Instant::now() < until,
            "root connections outlived run_until"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    match case {
        Case::Live => {
            assert!(result.is_ok() && entered.get());
            let snapshot = callback
                .take()
                .unwrap()
                .expect("production root must register real callback")
                .into_inner();
            assert_eq!(snapshot.target, expected.target);
            assert_eq!(snapshot.operation_id, expected.operation_id);
            assert_eq!(snapshot.command_id, expected.command_id);
            assert_eq!(snapshot.agent_identity_id, "live-agent");
            assert_eq!(snapshot.observed_controller_identity_id, "live-controller");
            assert!(snapshot.checked_at_unix_us < snapshot.lease_expires_at_unix_us);
        }
        Case::Disabled => {
            assert!(result.is_ok() && entered.get());
            assert_eq!(
                callback.take().unwrap().unwrap_err().code(),
                tonic::Code::Unimplemented
            );
        }
        Case::Immediate => assert!(result.is_ok() && entered.get()),
        Case::Partial | Case::Missing => assert!(
            result.is_err() && !entered.get(),
            "invalid explicit authority must fail before serving"
        ),
        Case::Occupied => {
            assert!(!entered.get());
            assert!(
                result
                    .unwrap_err()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse)
            );
        }
    }
    println!("{}", config::CLEAN);
    std::io::stdout().flush().unwrap();
    let mut ack = [0];
    std::io::stdin().read_exact(&mut ack).unwrap();
    assert_eq!(ack, [b'!']);
}
