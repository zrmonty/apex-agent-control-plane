//! Fixed daemon exec health transport. Stream closure is not completion evidence.
use super::{Engine, inspect::Json};
use reqwest::{Client, Method, Response};
use serde_json::json;
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

mod stream;
const ERROR: &str = "RUNTIME_ENGINE_HEALTH_REFUSED";
const NODE: &str = "/usr/local/bin/node";
const PROCESS: &str = "/app/apps/mcp-gateway/dist/managed/health-process.js";
const CREATE_LIMIT: usize = 4096;
const INSPECT_LIMIT: usize = 16384;

#[derive(Debug, PartialEq, Eq)]
pub(in crate::execution) struct ExecState {
    pub(in crate::execution) running: bool,
    // Docker reports null before an exit has been observed. Never invent success.
    pub(in crate::execution) exit_code: Option<i32>,
    pub(in crate::execution) pid: u32,
}

impl Engine {
    /// Create exactly one fixed exec. An ambiguous error must never trigger a retry.
    pub(in crate::execution) fn health_create(
        &self,
        container: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<String, &'static str> {
        exact_id(container)?;
        self.health_io(deadline, cancelled, async {
            let body = json!({
                "Cmd": [NODE, PROCESS], "User": "10001:10001",
                "WorkingDir": "/app/apps/mcp-gateway", "AttachStdin": false,
                "AttachStdout": true, "AttachStderr": true, "Tty": false, "Privileged": false
            });
            let reply = self
                .health_request(
                    Method::POST,
                    &format!("/containers/{container}/exec"),
                    Some(body),
                    201,
                    deadline,
                    cancelled,
                )
                .await?;
            let bytes = self
                .health_body(reply, CREATE_LIMIT, deadline, cancelled)
                .await?;
            let value = Json::bounded(&bytes, CREATE_LIMIT).map_err(|_| ERROR)?;
            let object = value.0.as_object().filter(|o| o.len() == 1).ok_or(ERROR)?;
            let id = object
                .get("Id")
                .and_then(serde_json::Value::as_str)
                .ok_or(ERROR)?;
            exact_id(id)?;
            Ok(id.to_owned())
        })
    }
    /// Bytes/EOF say nothing about daemon completion. Errors do not stop the exec.
    pub(in crate::execution) fn health_start(
        &self,
        exec: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        exact_id(exec)?;
        self.health_io(deadline, cancelled, async {
            let mut reply = self
                .health_request(
                    Method::POST,
                    &format!("/exec/{exec}/start"),
                    Some(json!({"Detach": false, "Tty": false})),
                    200,
                    deadline,
                    cancelled,
                )
                .await?;
            let mut stream = stream::Multiplex::new();
            loop {
                self.health_guard(deadline, cancelled)?;
                let chunk = reply.chunk().await.map_err(|_| ERROR);
                self.health_guard(deadline, cancelled)?;
                let Some(chunk) = chunk? else { break };
                stream.push(&chunk)?;
            }
            stream.finish()
        })
    }
    /// Return the exact daemon observation; the caller owns intent/completion policy.
    pub(in crate::execution) fn health_inspect(
        &self,
        exec: &str,
        container: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ExecState, &'static str> {
        exact_id(exec)?;
        exact_id(container)?;
        self.health_io(deadline, cancelled, async {
            let reply = self
                .health_request(
                    Method::GET,
                    &format!("/exec/{exec}/json"),
                    None,
                    200,
                    deadline,
                    cancelled,
                )
                .await?;
            let bytes = self
                .health_body(reply, INSPECT_LIMIT, deadline, cancelled)
                .await?;
            let value = Json::bounded(&bytes, INSPECT_LIMIT).map_err(|_| ERROR)?;
            let v = &value.0;
            let p = &v["ProcessConfig"];
            if v["ID"].as_str() != Some(exec)
                || v["ContainerID"].as_str() != Some(container)
                || v["OpenStdin"] != false
                || v["OpenStdout"] != true
                || v["OpenStderr"] != true
                || p["entrypoint"] != NODE
                || p["arguments"] != json!([PROCESS])
                || p["user"] != "10001:10001"
                || p["privileged"] != false
                || p["tty"] != false
            {
                return Err(ERROR);
            }
            Ok(ExecState {
                running: v["Running"].as_bool().ok_or(ERROR)?,
                exit_code: match v.get("ExitCode").ok_or(ERROR)? {
                    serde_json::Value::Null => None,
                    value => Some(
                        value
                            .as_i64()
                            .and_then(|n| i32::try_from(n).ok())
                            .ok_or(ERROR)?,
                    ),
                },
                pid: v["Pid"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or(ERROR)?,
            })
        })
    }

    fn health_guard(&self, deadline: Instant, cancelled: &AtomicBool) -> Result<(), &'static str> {
        if cancelled.load(Ordering::Acquire) {
            return Err("RUNTIME_ENGINE_COMMAND_CANCELLED");
        }
        if Instant::now() >= deadline {
            return Err("RUNTIME_ENGINE_COMMAND_DEADLINE");
        }
        self.check().map_err(|_| ERROR)
    }

    // Called on the existing physical worker. No detached I/O thread may outlive it.
    fn health_io<T>(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
        operation: impl Future<Output = Result<T, &'static str>>,
    ) -> Result<T, &'static str> {
        self.health_guard(deadline, cancelled)?;
        // Fail closed instead of panicking if accidentally wired onto a Tokio worker.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ERROR);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ERROR)?;
        let result = runtime.block_on(async {
            let operation = std::pin::pin!(operation);
            let mut operation = operation;
            let expiry = tokio::time::sleep_until(deadline.into());
            tokio::pin!(expiry);
            loop {
                self.health_guard(deadline, cancelled)?;
                tokio::select! {
                    biased;
                    _ = &mut expiry => return Err("RUNTIME_ENGINE_COMMAND_DEADLINE"),
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                    result = &mut operation => return result,
                }
            }
        });
        // Dropping the operation/client aborts HTTP I/O, never the daemon exec.
        // No blocking work/DNS is spawned by this fixed Unix transport.
        runtime.shutdown_timeout(Duration::ZERO);
        self.health_guard(deadline, cancelled)?;
        result
    }

    async fn health_request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        status: u16,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Response, &'static str> {
        self.health_guard(deadline, cancelled)?;
        let client = Client::builder()
            .unix_socket(self.paths.docker_socket.as_path())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| ERROR)?;
        self.health_guard(deadline, cancelled)?;
        // The authority is fixed and never resolved: reqwest routes only to the
        // original protected Unix socket. No context, proxy, or TCP fallback.
        let mut request = client
            .request(method, format!("http://localhost/v1.47{path}"))
            .timeout(deadline.saturating_duration_since(Instant::now()))
            .header(reqwest::header::CONNECTION, "close");
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&body).map_err(|_| ERROR)?);
        }
        self.health_guard(deadline, cancelled)?;
        let response = request.send().await.map_err(|_| ERROR);
        self.health_guard(deadline, cancelled)?;
        let response = response?;
        if response.status().as_u16() != status {
            return Err(ERROR);
        }
        Ok(response)
    }

    async fn health_body(
        &self,
        mut reply: Response,
        limit: usize,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if reply.content_length().is_some_and(|n| n > limit as u64) {
            return Err(ERROR);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
        loop {
            self.health_guard(deadline, cancelled)?;
            let chunk = reply.chunk().await.map_err(|_| ERROR);
            self.health_guard(deadline, cancelled)?;
            let Some(chunk) = chunk? else {
                return Ok(bytes);
            };
            if chunk.len() > limit - bytes.len() {
                return Err(ERROR);
            }
            bytes.extend_from_slice(&chunk);
        }
    }
}

fn exact_id(id: &str) -> Result<(), &'static str> {
    if crate::shapes::hex_hash(id) {
        Ok(())
    } else {
        Err(ERROR)
    }
}

#[cfg(test)]
mod native;
#[cfg(test)]
mod null_exit;
#[cfg(test)]
pub(in crate::execution) mod tests;
