use super::{Client, NoTls, database};
use apex_control_plane_api::{CreateProxy, ExactScope, PostgresProxyStore, ProxyId, ProxyStore};
use std::time::{Duration, Instant};

pub(super) fn named_url(raw: &str, application: &str) -> String {
    let config: postgres::Config = raw.parse().expect("invalid owned PG fixture URL");
    assert!(database::is_loopback_config(&config));
    assert_eq!(
        config.get_ports().len(),
        1,
        "explicit owned PG port is required"
    );
    assert!(
        matches!(
            (config.get_ports()[0], config.get_dbname()),
            (55439, Some("apex_working_mcp")) | (15432, Some("apex_proxy_journal"))
        ),
        "PG must be the exact local or dedicated CI port/database fixture pair"
    );
    let mut url = url::Url::parse(raw).expect("PG fixture must use a URL");
    let pairs: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key != "application_name" && key != "connect_timeout")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(pairs)
        .append_pair("application_name", application)
        .append_pair("connect_timeout", "5");
    url.into()
}

pub(super) fn observer(url: &str) -> Client {
    let config: postgres::Config = url.parse().unwrap();
    assert!(database::is_loopback_config(&config));
    assert!(
        config
            .get_application_name()
            .is_some_and(|name| name.starts_with("apex_rb_observer_"))
    );
    let mut client = config
        .connect(NoTls)
        .expect("owned PG observer unavailable");
    client
        .batch_execute("SET statement_timeout = '5s'")
        .unwrap();
    client
}

pub(super) fn connections(client: &mut Client, application: &str) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND application_name = $1",
            &[&application],
        )
        .unwrap()
        .get(0)
}

pub(super) fn wait_for_zero(client: &mut Client, application: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if connections(client, application) == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "root PG connections survived run_until return"
        );
        // Poll actual server-side connection state, not elapsed-time readiness.
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn assert_active(url: String, application: String, browser: bool) {
    // Called by the shutdown future, but blocking PG construction/destruction
    // occurs on a plain OS thread, never inside an entered Tokio runtime.
    std::thread::spawn(move || {
        let mut client = observer(&url);
        assert!(connections(&mut client, &application) >= if browser { 4 } else { 3 });
        assert_schema(&mut client, browser);
    })
    .join()
    .expect("root PG observation failed");
}

pub(super) fn assert_schema(client: &mut Client, browser: bool) {
    for table in ["apex_event_outbox", "apex_control_inbox", "mcp_proxies"] {
        assert!(
            client
                .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
                .unwrap()
                .get::<_, bool>(0)
        );
    }
    assert_eq!(
        client
            .query_one(
                "SELECT to_regclass('apex_browser_sessions') IS NOT NULL",
                &[]
            )
            .unwrap()
            .get::<_, bool>(0),
        browser,
        "disabled browser must not open browser storage; enabled root must initialize it"
    );
}

pub(super) fn seed(url: &str, id: &str) {
    // This separate fixture owner is dropped before spawning the root child.
    // It cannot keep a root Arc alive or mask final-owner destruction.
    let store =
        PostgresProxyStore::connect(url).expect("owned persistent proxy fixture unavailable");
    store
        .create(CreateProxy {
            request_id: uuid::Uuid::now_v7().to_string(),
            scope: ExactScope {
                workspace_id: "acme".into(),
                namespace_id: "prod".into(),
            },
            proxy_id: ProxyId::new(id).unwrap(),
            display_name: "Root startup persisted proxy".into(),
            slug: "root-startup-persisted".into(),
            description: None,
            owner: None,
        })
        .unwrap();
}

pub(super) fn assert_logout(client: &mut Client) {
    let row = client
        .query_one(
            "SELECT count(*), count(token_ciphertext) FROM apex_browser_sessions",
            &[],
        )
        .unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        1,
        "real callback must persist one session"
    );
    assert_eq!(
        row.get::<_, i64>(1),
        0,
        "logout must erase persisted provider material"
    );
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM mcp_proxies", &[])
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}
