use super::{Client, NoTls};

pub struct Database {
    pub url: String,
    base_url: String,
    schema: String,
}

impl Database {
    pub fn new() -> Self {
        let base_url = std::env::var("APEX_BROWSER_SESSION_TEST_DATABASE_URL").expect(
            "required disposable loopback PostgreSQL: APEX_BROWSER_SESSION_TEST_DATABASE_URL",
        );
        let config: postgres::Config = base_url.parse().unwrap();
        assert!(
            is_loopback_config(&config),
            "session test database must be loopback-only"
        );
        let schema = format!("working_browser_{}", uuid::Uuid::now_v7().simple());
        Client::connect(&base_url, NoTls)
            .expect("required session test PostgreSQL unavailable")
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        Self {
            url,
            base_url,
            schema,
        }
    }
    pub fn client(&self) -> Client {
        Client::connect(&self.url, NoTls).unwrap()
    }
}

// hostaddr overrides a TCP host's network destination. Check both lists before
// connecting or creating a schema, even when every supplied host is loopback.
pub fn is_loopback_config(config: &postgres::Config) -> bool {
    !config.get_hosts().is_empty()
        && config.get_hosts().iter().all(|host| match host {
            postgres::config::Host::Tcp(host) => host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => false,
        })
        && config
            .get_hostaddrs()
            .iter()
            .all(std::net::IpAddr::is_loopback)
}
impl Drop for Database {
    fn drop(&mut self) {
        if self.schema.starts_with("working_browser_")
            && self
                .schema
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            && let Ok(mut client) = Client::connect(&self.base_url, NoTls)
        {
            let _ = client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
        }
    }
}
