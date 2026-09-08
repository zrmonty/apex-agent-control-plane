use super::*;
use crate::config::{Directory, ExecutionConfig};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    thread::JoinHandle,
};

pub(in crate::execution) struct Fixture {
    pub engine: Engine,
    pub root: PathBuf,
    pub listener: UnixListener,
}
pub(in crate::execution) struct Request {
    pub line: String,
    pub body: serde_json::Value,
}
impl Fixture {
    pub fn new() -> Self {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "fixture requires root"
        );
        let root = PathBuf::from("/tmp").join(format!("health-exec-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let config = root.join("config");
        fs::create_dir(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let paths = ExecutionConfig {
            journal_root: root.join("journal"),
            staging_root: root.join("stage"),
            material_root: root.join("material"),
            docker_executable: "/bin/false".into(),
            docker_socket: socket.clone(),
            docker_config_root: config.clone(),
            cosign_executable: "/bin/false".into(),
            cosign_cache_root: root.join("cosign"),
            network_profile: None,
        };
        let engine = Engine {
            executable: fs::File::open("/bin/false").unwrap().into(),
            config: Directory::open(&config).unwrap(),
            paths,
            socket: super::super::super::socket(&socket).unwrap(),
            mount: super::super::super::mount::Profile::Private,
        };
        Self {
            engine,
            root,
            listener,
        }
    }
    pub fn serve(&self, reply: Vec<u8>, fragment: usize) -> JoinHandle<Request> {
        self.handle(move |mut stream| {
            let request = read_request(&mut stream);
            for chunk in reply.chunks(fragment) {
                if stream.write_all(chunk).is_err() {
                    break;
                }
                std::thread::yield_now();
            }
            request
        })
    }
    pub fn handle(
        &self,
        f: impl FnOnce(UnixStream) -> Request + Send + 'static,
    ) -> JoinHandle<Request> {
        let listener = self.listener.try_clone().unwrap();
        std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        return f(stream);
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(self.root.parent().unwrap(), std::path::Path::new("/tmp"));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("health-exec-")
        );
        fs::remove_dir_all(&self.root).unwrap();
    }
}
pub(in crate::execution) fn read_request(stream: &mut UnixStream) -> Request {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 8192);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let length = headers
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(|v| v.parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(length < 4096);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Request {
        line: headers.lines().next().unwrap().into(),
        body: if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        },
    }
}
pub(in crate::execution) fn response(status: u16, bytes: Vec<u8>) -> Vec<u8> {
    let mut reply = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/vnd.docker.raw-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
    reply.extend(bytes);
    reply
}
pub(in crate::execution) fn frame(stream: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![stream, 0, 0, 0];
    result.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    result.extend(bytes);
    result
}
pub(in crate::execution) fn inspection(running: bool, exit: i32, pid: u32) -> serde_json::Value {
    json!({"CanRemove": false, "DetachKeys": "", "ID": exec(), "ContainerID": container(), "Running": running, "ExitCode": exit, "Pid": pid,
        "OpenStdin": false, "OpenStdout": true, "OpenStderr": true,
        "ProcessConfig": {"entrypoint": "/usr/local/bin/node", "arguments": ["/app/apps/mcp-gateway/dist/managed/health-process.js"], "user": "10001:10001", "privileged": false, "tty": false}})
}
