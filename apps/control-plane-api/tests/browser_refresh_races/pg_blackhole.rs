//! Owned loopback PostgreSQL transport fault only. No data/identity assertions
//! use this peer: it acknowledges startup/setup, then withholds the selected reply.
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Clone, Copy)]
pub enum Stall {
    Startup,
    Query,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    StartupWithheld,
    QueryWithheld,
    Closed,
    ProtocolFailed,
}

pub struct Blackhole {
    pub address: SocketAddr,
    pub events: mpsc::Receiver<Event>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Blackhole {
    pub fn start(stall: Stall) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let (events, receiver) = mpsc::sync_channel(4);
        let thread = thread::spawn(move || {
            if serve(listener, stall, &stopping, &events).is_err() {
                let _ = events.send(Event::ProtocolFailed);
            }
        });
        Self {
            address,
            events: receiver,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                assert!(result.is_ok(), "owned PG peer failed");
            }
        }
    }
}

fn serve(
    listener: TcpListener,
    stall: Stall,
    stopping: &AtomicBool,
    events: &mpsc::SyncSender<Event>,
) -> Result<(), ()> {
    let mut peer = loop {
        if stopping.load(Ordering::SeqCst) {
            return Ok(());
        }
        match listener.accept() {
            Ok((peer, address)) if address.ip().is_loopback() => break peer,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // Only polls accept/teardown; actual protocol bytes trigger the stall.
                thread::sleep(Duration::from_millis(5));
            }
            _ => return Err(()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|_| ())?;
    peer.set_write_timeout(Some(Duration::from_millis(250)))
        .map_err(|_| ())?;
    peer.set_nodelay(true).map_err(|_| ())?;
    let mut buffered = Vec::new();
    let mut state = Protocol::Startup;
    let mut total = 0usize;
    while !stopping.load(Ordering::SeqCst) {
        let mut bytes = [0u8; 1024];
        match peer.read(&mut bytes) {
            Ok(0) => {
                let _ = events.send(Event::Closed);
                return Ok(());
            }
            Ok(count) => {
                total += count;
                if total > 16 * 1024 {
                    return Err(());
                }
                if matches!(state, Protocol::Withholding) {
                    continue;
                }
                buffered.extend_from_slice(&bytes[..count]);
                advance(&mut peer, &mut buffered, &mut state, stall, events)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                let _ = events.send(Event::Closed);
                return Ok(());
            }
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

enum Protocol {
    Startup,
    Setup,
    Query,
    Withholding,
}

fn advance(
    peer: &mut TcpStream,
    bytes: &mut Vec<u8>,
    state: &mut Protocol,
    stall: Stall,
    events: &mpsc::SyncSender<Event>,
) -> Result<(), ()> {
    if matches!(state, Protocol::Startup) {
        if bytes.len() < 8 {
            return Ok(());
        }
        let length = usize::try_from(u32::from_be_bytes(bytes[..4].try_into().map_err(|_| ())?))
            .map_err(|_| ())?;
        if !(8..=16384).contains(&length) || bytes[4..8] != [0, 3, 0, 0] {
            return Err(());
        }
        if bytes.len() < length {
            return Ok(());
        }
        drop(bytes.drain(..length));
        if matches!(stall, Stall::Startup) {
            events.send(Event::StartupWithheld).map_err(|_| ())?;
            *state = Protocol::Withholding;
            return Ok(());
        }
        // AuthenticationOk, ReadyForQuery. Fixed test username, no credentials.
        peer.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I")
            .map_err(|_| ())?;
        *state = Protocol::Setup;
    }
    while bytes.len() >= 5 {
        let length = usize::try_from(u32::from_be_bytes(bytes[1..5].try_into().map_err(|_| ())?))
            .map_err(|_| ())?;
        if !(4..16384).contains(&length) {
            return Err(());
        }
        let end = length + 1;
        if bytes.len() < end {
            return Ok(());
        }
        if matches!(state, Protocol::Setup) && bytes[0] == b'Q' {
            if &bytes[5..end] != b"SET statement_timeout='1s'; SET lock_timeout='1s'\0" {
                return Err(());
            }
            // Let both existing helper setup statements finish. The fault must
            // occur at the actual snapshot query, not an earlier SET statement.
            peer.write_all(b"C\0\0\0\x08SET\0C\0\0\0\x08SET\0Z\0\0\0\x05I")
                .map_err(|_| ())?;
            drop(bytes.drain(..end));
            *state = Protocol::Query;
        } else if matches!(state, Protocol::Query) && bytes[0] == b'P' {
            // Extended-protocol Parse contains the real snapshot query. Never
            // acknowledge it: server-side SQL timeouts cannot repair lost I/O.
            events.send(Event::QueryWithheld).map_err(|_| ())?;
            bytes.clear();
            *state = Protocol::Withholding;
            return Ok(());
        } else {
            return Err(());
        }
    }
    Ok(())
}
