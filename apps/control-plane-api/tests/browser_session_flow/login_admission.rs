//! HTTP ordering over the real shared admission row. Provider port 1 is
//! deliberately unavailable: a saturated request must never become an OIDC 503.
use super::fixture::{Fixture, Http};
use apex_control_plane_api::browser::{security::OpaqueToken, sessions::BrowserSessionStore};

fn exhaust(client: &mut postgres::Client) {
    assert_eq!(client.execute(
        "WITH sampled AS (SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint AS now_us)
         UPDATE apex_browser_login_admission SET clock_us=sampled.now_us,
             tat_us=sampled.now_us+60000000 FROM sampled WHERE singleton=1", &[],
    ).unwrap(), 1);
}

#[test]
fn shared_login_quota_precedes_provider_and_cannot_be_reset_by_browser_headers() {
    let fixture = Fixture::new();
    // Independent workers/connections represent separate edge replicas.
    let second = BrowserSessionStore::connect(&fixture.database.url).unwrap();
    let (one, two) = fixture.runtime.block_on(async {
        (Http::start(fixture.sessions.clone()).await, Http::start(second).await)
    });
    let mut database = fixture.database.client();
    for edge in [&one, &two] {
        for use_cookie in [false, true] {
            exhaust(&mut database);
            fixture.runtime.block_on(async {
                let mut request = edge.client.get(format!("{}/auth/login", edge.origin))
                    .header("x-forwarded-for", "203.0.113.7, 127.0.0.1")
                    .header("forwarded", "for=192.0.2.8");
                if use_cookie {
                    request = request.header("cookie", format!("__Host-apex_login={}",
                        OpaqueToken::generate().unwrap().expose_secret()));
                }
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), 429, "quota must precede unavailable provider");
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert!(!response.headers().contains_key("location"));
                assert!(!response.headers().contains_key("set-cookie"));
                assert!(response.headers().contains_key("content-security-policy"));
            });
            assert_eq!(database.query_one("SELECT count(*) FROM apex_browser_login_attempts", &[])
                .unwrap().get::<_, i64>(0), 0);
            assert_eq!(database.query_one("SELECT count(*) FROM apex_browser_login_admission", &[])
                .unwrap().get::<_, i64>(0), 1);
        }
    }
    fixture.runtime.block_on(async { one.shutdown().await; two.shutdown().await; });
}

#[test]
fn provider_failure_spends_admission_without_creating_attempt_or_retrying() {
    let fixture = Fixture::new();
    let edge = fixture.runtime.block_on(Http::start(fixture.sessions.clone()));
    fixture.runtime.block_on(async {
        let response = edge.client.get(format!("{}/auth/login", edge.origin)).send().await.unwrap();
        assert_eq!(response.status(), 503);
        assert!(!response.headers().contains_key("location"));
        assert!(!response.headers().contains_key("set-cookie"));
    });
    let mut database = fixture.database.client();
    let row = database.query_one("SELECT tat_us, clock_us FROM apex_browser_login_admission WHERE singleton=1", &[]).unwrap();
    let clock: i64 = row.get(1);
    assert!(clock > 0);
    assert_eq!(row.get::<_, i64>(0), clock + 1_000_000, "exactly one admission is spent");
    assert_eq!(database.query_one("SELECT count(*) FROM apex_browser_login_attempts", &[])
        .unwrap().get::<_, i64>(0), 0);
    fixture.runtime.block_on(edge.shutdown());
}
