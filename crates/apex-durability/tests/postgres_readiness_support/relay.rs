//! A real PostgreSQL connection relay that can blackhole established traffic.
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct Relay {
    pub port: u16,
    stall: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Relay {
    pub fn new(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stall = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        let (stalled, stopping, peer_closed) = (stall.clone(), stop.clone(), closed.clone());
        let worker = thread::spawn(move || {
            let client = loop {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((client, _)) => break client,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("relay accept: {error}"),
                }
            };
            let server = TcpStream::connect_timeout(&upstream, Duration::from_secs(2)).unwrap();
            for stream in [&client, &server] {
                stream
                    .set_read_timeout(Some(Duration::from_millis(50)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_millis(250)))
                    .unwrap();
            }
            let mut client_read = client.try_clone().unwrap();
            let mut server_write = server.try_clone().unwrap();
            thread::scope(|scope| {
                scope.spawn(|| {
                    pump(
                        &mut client_read,
                        &mut server_write,
                        &stalled,
                        &stopping,
                        Some(&peer_closed),
                    )
                });
                pump(&mut { server }, &mut { client }, &stalled, &stopping, None);
            });
        });
        Self {
            port,
            stall,
            stop,
            closed,
            worker: Some(worker),
        }
    }

    pub fn stall(&self) {
        self.stall.store(true, Ordering::SeqCst);
    }

    pub fn assert_peer_closed(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self.closed.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            self.closed.load(Ordering::SeqCst),
            "deadline must close the owned socket"
        );
    }
}

fn pump(
    input: &mut TcpStream,
    output: &mut TcpStream,
    stall: &AtomicBool,
    stop: &AtomicBool,
    closed: Option<&AtomicBool>,
) {
    let mut buffer = [0u8; 8192];
    while !stop.load(Ordering::SeqCst) {
        match input.read(&mut buffer) {
            Ok(0) => {
                if let Some(closed) = closed {
                    closed.store(true, Ordering::SeqCst);
                }
                stop.store(true, Ordering::SeqCst);
            }
            Ok(count) => {
                if !stall.load(Ordering::SeqCst) && output.write_all(&buffer[..count]).is_err() {
                    stop.store(true, Ordering::SeqCst);
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
