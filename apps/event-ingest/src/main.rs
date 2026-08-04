//! Apex event-ingest process entrypoint.

mod startup;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    apex_event_ingest::install_rustls_provider();
    startup::run().await
}
