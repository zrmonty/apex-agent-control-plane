//! Apex event-ingest process entrypoint.

mod startup;

// Deliberately NOT `#[tokio::main]`. Startup constructs blocking clients that
// own their own runtimes and call `Runtime::block_on` internally (the NATS
// JetStream client is the first one). Running that construction on a thread
// that already has a tokio runtime entered panics with "Cannot start a runtime
// from within a runtime", which made the binary unable to start at all.
// Construction therefore happens on the plain main thread, and `startup::run`
// builds a runtime itself only for the parts that need one (the reaper, the
// replay worker, and serving gRPC).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    apex_event_ingest::install_rustls_provider();
    startup::run()
}
