use postgres::{Client, NoTls};

const PREFIX: &str = "working_publish_capabilities_";

/// Only a fresh schema belongs to this test; never reset shared fixture tables.
pub struct Database {
    pub url: String,
    base_url: String,
    schema: String,
}

impl Database {
    pub fn new() -> Self {
        let base_url = std::env::var("APEX_PROXY_JOURNAL_TEST_DATABASE_URL")
            .expect("required disposable PostgreSQL: APEX_PROXY_JOURNAL_TEST_DATABASE_URL");
        let config: postgres::Config = base_url.parse().expect("fixture PostgreSQL URL");
        assert!(base_url.starts_with("postgres://") || base_url.starts_with("postgresql://"));
        assert!(!config.get_hosts().is_empty());
        assert!(
            config.get_hosts().iter().all(|host| match host {
                postgres::config::Host::Tcp(host) => host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()),
                #[cfg(unix)]
                postgres::config::Host::Unix(_) => false,
            }),
            "publication fixture must be loopback-only"
        );
        assert!(
            config.get_options().is_none(),
            "fixture owns search_path options"
        );
        let schema = format!("{PREFIX}{}", uuid::Uuid::now_v7().simple());
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let mut client =
            Client::connect(&base_url, NoTls).expect("required dedicated PostgreSQL unavailable");
        client
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap();
        Self {
            url,
            base_url,
            schema,
        }
    }

    pub fn snapshot(&self) -> Vec<Vec<String>> {
        let mut client = Client::connect(&self.url, NoTls).unwrap();
        // All columns, not just row counts: catches pointer, revision, transition,
        // and idempotency rewrites. Table names are fixed, never request-selected.
        [
            "mcp_proxies",
            "mcp_proxy_revisions",
            "mcp_proxy_lifecycle_transitions",
            "mcp_proxy_idempotency",
        ]
        .into_iter()
        .map(|table| {
            client
                .query(
                    &format!(
                        "SELECT row_to_json(t)::text FROM {table} t ORDER BY row_to_json(t)::text"
                    ),
                    &[],
                )
                .unwrap()
                .into_iter()
                .map(|row| row.get(0))
                .collect()
        })
        .collect()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // Exact generated UUIDv7 target only; no database or supplied schema deletion.
        let owned = self.schema.strip_prefix(PREFIX).is_some_and(|suffix| {
            uuid::Uuid::parse_str(suffix)
                .is_ok_and(|id| id.get_version_num() == 7 && id.simple().to_string() == suffix)
        });
        if owned && let Ok(mut client) = Client::connect(&self.base_url, NoTls) {
            let result = client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
            if !std::thread::panicking() {
                result.expect("cleanup of exact test-owned publication schema");
            }
        }
    }
}
