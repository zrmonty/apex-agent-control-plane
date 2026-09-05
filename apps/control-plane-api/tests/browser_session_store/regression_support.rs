use super::*;
use std::{
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Job = Box<dyn FnOnce(&mut PostgresSessionStore) + Send>;
const WAIT: Duration = Duration::from_secs(10);

// A test-owned synchronous thread: construction, every operation, and drop
// occur on that thread. This does not use or test the separately owned actor.
pub struct StoreWorker {
    jobs: Option<Sender<Job>>,
    thread: Option<JoinHandle<()>>,
    pub application: String,
}

impl StoreWorker {
    pub fn new(db: &Database, repeatable_read: bool) -> Self {
        let application = format!("session_regression_{}", uuid::Uuid::now_v7().simple());
        let mut url = url::Url::parse(&db.url).unwrap();
        let mut pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let config: postgres::Config = db.url.parse().unwrap();
        let mut options = config.get_options().unwrap_or_default().to_owned();
        if repeatable_read {
            options.push_str(" -c default_transaction_isolation=repeatable\\ read");
        }
        pairs.retain(|(key, _)| key != "options" && key != "application_name");
        pairs.push(("options".into(), options.clone()));
        pairs.push(("application_name".into(), application.clone()));
        url.query_pairs_mut().clear().extend_pairs(pairs);
        // URL's form serializer writes spaces as '+', but postgres::Config
        // only percent-decodes URI parameters. Preserve escaped option spaces
        // as %20; literal '+' values are already encoded as %2B.
        let query = url.query().unwrap().replace('+', "%20");
        url.set_query(Some(&query));
        let url = url.to_string();
        let parsed: postgres::Config = url.parse().unwrap();
        assert!(
            parsed.get_options() == Some(options.as_str()),
            "worker startup options must survive PostgreSQL URI decoding"
        );
        if repeatable_read {
            // Probe only the owned fixture before starting the worker. A
            // connection/configuration failure is not quota-regression RED.
            let mut probe = Client::connect(&url, NoTls)
                .expect("owned Repeatable Read fixture startup probe failed");
            let isolation: String = probe
                .query_one("SHOW default_transaction_isolation", &[])
                .unwrap()
                .get(0);
            assert_eq!(isolation, "repeatable read");
        }
        let (jobs, receiver) = mpsc::channel::<Job>();
        let (ready, initialized) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut store = match PostgresSessionStore::connect(&url) {
                Ok(store) => store,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            if ready.send(Ok(())).is_err() {
                return;
            }
            while let Ok(job) = receiver.recv() {
                job(&mut store);
            }
        });
        let worker = Self {
            jobs: Some(jobs),
            thread: Some(thread),
            application,
        };
        initialized.recv_timeout(WAIT).unwrap().unwrap();
        worker
    }

    pub fn submit<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut PostgresSessionStore) -> T + Send + 'static,
    ) -> Receiver<T> {
        let (sender, receiver) = mpsc::channel();
        let sent = self.jobs.as_ref().unwrap().send(Box::new(move |store| {
            let _ = sender.send(job(store));
        }));
        assert!(sent.is_ok(), "store regression thread is unavailable");
        receiver
    }

    pub fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut PostgresSessionStore) -> T + Send + 'static,
    ) -> T {
        receive(self.submit(job))
    }
}

impl Drop for StoreWorker {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let joined = thread.join();
            if !std::thread::panicking() {
                assert!(joined.is_ok(), "store regression thread panicked");
            }
        }
    }
}

pub fn receive<T>(receiver: Receiver<T>) -> T {
    match receiver.recv_timeout(WAIT) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => panic!("store regression operation exceeded deadline"),
        Err(RecvTimeoutError::Disconnected) => panic!("store regression thread disconnected"),
    }
}

pub fn observer(db: &Database) -> Client {
    let mut client = db.client();
    client
        .batch_execute("SET statement_timeout='5s'; SET lock_timeout='2s'")
        .unwrap();
    client
}

pub fn db_now(client: &mut Client) -> i64 {
    client
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .unwrap()
        .get(0)
}

pub fn wait_for_blocker(client: &mut Client, application: &str, blocker_pid: i32) {
    let stop = Instant::now() + Duration::from_secs(1);
    loop {
        let blocked: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                 WHERE datname=current_database() AND application_name=$1
                 AND $2=ANY(pg_blocking_pids(pid)))",
                &[&application, &blocker_pid],
            )
            .unwrap()
            .get(0);
        if blocked {
            return;
        }
        assert!(
            Instant::now() < stop,
            "operation never reached the held row/capacity lock"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

// Start near the middle of a database second: floor(now)+2 then leaves about
// 1.4 seconds to reach the lock, below the production two-second lock timeout.
pub fn expiry_window(client: &mut Client) -> i64 {
    let stop = Instant::now() + Duration::from_secs(3);
    loop {
        let epoch: f64 = client
            .query_one(
                "SELECT extract(epoch FROM clock_timestamp())::double precision",
                &[],
            )
            .unwrap()
            .get(0);
        if (0.5..0.65).contains(&epoch.fract()) {
            return epoch.floor() as i64 + 2;
        }
        assert!(
            Instant::now() < stop,
            "could not synchronize the database clock"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

pub fn cross_expiry(client: &mut Client, expiry: i64) {
    assert!(
        db_now(client) < expiry,
        "waiter was not established before expiry"
    );
    client
        .query_one(
            "SELECT pg_sleep(GREATEST(0::double precision,
             $1::bigint::double precision-extract(epoch FROM clock_timestamp())::double precision)+0.025)",
            &[&expiry],
        )
        .unwrap();
    assert!(db_now(client) >= expiry);
}

pub fn terminate(worker: &StoreWorker, client: &mut Client) {
    let rows = client
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
             WHERE datname=current_database() AND application_name=$1 AND pid<>pg_backend_pid()",
            &[&worker.application],
        )
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "terminate only this fixture's named store connection"
    );
    assert!(rows[0].get::<_, bool>(0));
    // The current-thread driver observes closure when its next operation polls.
    assert!(worker.run(|store| store.load(digest(240))).is_err());
}

pub fn login(key: LookupDigest, browser: LookupDigest, expiry: i64) -> NewLoginAttempt {
    NewLoginAttempt {
        state: key,
        browser,
        issuer: "https://issuer.example/realm".into(),
        client_id: "apex-browser".into(),
        expires_at: expiry,
        envelope: envelope(key, EnvelopePurpose::LoginAttempt, expiry),
    }
}
