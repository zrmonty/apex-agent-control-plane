use super::*;
use apex_control_plane_api::browser::telemetry::{Action, BrowserTelemetry, Status};
use std::io::{self, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct FailedOutput;
impl Write for FailedOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("private-writer-error"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn metrics_http_exposes_browser_loss_without_using_observation_destination() {
    let (telemetry, owner) = BrowserTelemetry::with_writer(FailedOutput).unwrap();
    let metrics =
        Arc::new(GatewayRuntimeMetrics::default().with_browser_observations(telemetry.clone()));
    telemetry.export(
        &telemetry
            .begin(Action::Session)
            .finish(Status::Unauthorized),
    );
    assert!(owner.shutdown(Duration::from_secs(1)).complete);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve_metrics_connection(stream, metrics).await;
            });
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            server.await.unwrap();
            response
        })
        .await
        .unwrap()
    });
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("apex_browser_observation_dropped_records_total 1\n"));
    assert!(response.contains("apex_browser_observation_exporter_errors_total 1\n"));
    assert!(!response.contains("private-writer-error"));
}
