use super::*;

const WAIT: Duration = Duration::from_secs(5);
pub(super) type ResultValue = Result<Option<i32>, &'static str>;

pub(super) fn setup(phase: Phase) -> (Arc<Fixture>, Arc<Journal>, Record) {
    let fixture = Arc::new(Fixture::new());
    let path = fixture.root.join("journal");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Arc::new(Journal::open(&path).unwrap());
    let mut record = crate::execution::health_record::tests::record();
    record.container_id = "a".repeat(64);
    journal.health_transition(None, &record).unwrap();
    for next_phase in [Phase::Created, Phase::StartIntent, Phase::Finished] {
        if record.phase == phase {
            break;
        }
        let next = Record {
            exec_id: "b".repeat(64),
            phase: next_phase,
            ..record.clone()
        };
        journal.health_transition(Some(&record), &next).unwrap();
        record = next;
    }
    (fixture, journal, record)
}

pub(super) fn persisted(journal: &Journal, record: &Record, phase: Phase) {
    let actual = journal.health_record(&record.binding).unwrap().unwrap();
    assert_eq!(actual.phase, phase);
    // Compare the full original correlation, including attempt, target, fencing,
    // hashes, process instance, container and exec; only the phase may change.
    assert!(
        actual
            == Record {
                phase,
                ..record.clone()
            }
    );
}

pub(super) fn reopen(fixture: &Fixture, journal: Arc<Journal>) -> Arc<Journal> {
    assert_eq!(Arc::strong_count(&journal), 1, "worker still owns journal");
    drop(journal);
    Arc::new(Journal::open(&fixture.root.join("journal")).unwrap())
}

pub(super) fn inspect_reply(running: bool, exit: i32, pid: u32) -> Vec<u8> {
    response(
        200,
        serde_json::to_vec(&inspection(running, exit, pid)).unwrap(),
    )
}

/// Every peer uses the existing protected fixture's actual HTTP accept/read path.
/// The response gate makes assertions happen while a real inspect is outstanding.
pub(super) struct Peer {
    arrived: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: Option<JoinHandle<Request>>,
}
impl Peer {
    pub(super) fn hold(fixture: &Fixture, reply: Vec<u8>) -> Self {
        let (arrive, arrived) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let thread = fixture.handle(move |mut stream| {
            let request = read_request(&mut stream);
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = arrive.send(());
            // A failed assertion or vanished controller cannot leave a peer held.
            if released.recv_timeout(WAIT).is_ok() {
                let _ = stream.write_all(&reply);
            }
            request
        });
        Self {
            arrived,
            release,
            thread: Some(thread),
        }
    }
    pub(super) fn wait(&self) {
        self.arrived
            .recv_timeout(WAIT)
            .expect("daemon request did not arrive");
    }
    pub(super) fn answer(mut self, method_path: &str) {
        self.release.send(()).unwrap();
        let request = self.thread.take().unwrap().join().unwrap();
        assert_eq!(request.line, format!("{method_path} HTTP/1.1"));
        if method_path.starts_with("GET ") {
            assert!(request.body.is_null());
        }
    }
    pub(super) fn inspect(self, record: &Record) {
        self.answer(&format!("GET /v1.47/exec/{}/json", record.exec_id));
    }
    pub(super) fn start(
        mut self,
        fixture: &Fixture,
        record: &Record,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
        self.release.send(()).unwrap();
        let result = fixture.engine.health_start(
            &record.exec_id,
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        );
        let request = self.thread.take().unwrap().join().unwrap();
        assert_eq!(
            request.line,
            format!("POST /v1.47/exec/{}/start HTTP/1.1", record.exec_id)
        );
        assert_eq!(
            request.body,
            serde_json::json!({"Detach": false, "Tty": false})
        );
        result
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Holds concrete production dependencies until physical completion or shutdown.
/// Drop sends the real shutdown signal and joins even during assertion unwinding.
pub(super) struct Job {
    pub shutdown: watch::Sender<bool>,
    result: mpsc::Receiver<ResultValue>,
    thread: Option<JoinHandle<()>>,
}
impl Job {
    pub(super) fn spawn(
        fixture: &Arc<Fixture>,
        journal: &Arc<Journal>,
        record: &Record,
        recovering: bool,
    ) -> Self {
        let fixture = Arc::clone(fixture);
        let journal = Arc::clone(journal);
        let record = record.clone();
        let (shutdown, receiver) = watch::channel(false);
        let (send, result) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = if recovering {
                recover_exec(&fixture.engine, &journal, &receiver, &record).map(|()| None)
            } else {
                finish_exec(&fixture.engine, &journal, &receiver, &record).map(Some)
            };
            let _ = send.send(result);
        });
        Self {
            shutdown,
            result,
            thread: Some(thread),
        }
    }
    pub(super) fn pending(&self) {
        assert_eq!(self.result.try_recv(), Err(mpsc::TryRecvError::Empty));
    }
    pub(super) fn result(mut self) -> ResultValue {
        let result = self
            .result
            .recv_timeout(WAIT)
            .expect("physical worker did not finish");
        self.thread.take().unwrap().join().unwrap();
        result
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn no_dispatch(fixture: &Fixture) {
    assert_eq!(
        fixture.listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
