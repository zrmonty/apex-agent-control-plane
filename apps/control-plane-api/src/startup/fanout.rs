//! JetStream fanout wiring for the OOB control gateway.
//!
//! [`crate::startup::service::run`] builds the durable outbox and the tonic
//! server; this module builds the thing that drains that outbox onward, so an
//! accepted `stop`/`pause`/`inject` becomes an actual `control` event in the
//! queryable trace instead of a row nobody reads.
//!
//! The publisher stack is `apex_durability`'s, unmodified and unforked:
//! [`AsyncNatsJetStreamClient`] -> [`NatsJetStreamTransport`] ->
//! [`RetryingJetStreamTransport`] -> [`JetStreamPublisher`], the same four
//! layers `apps/event-ingest/src/startup/service.rs` composes. What is new
//! here is *when* that stack is built.
//!
//! # Why the connection is lazy
//!
//! `event-ingest` connects to NATS during startup and refuses to come up if it
//! cannot: for the ingest data path, a gateway that cannot publish is a
//! gateway that should not be accepting. The OOB control gateway is the exact
//! opposite case. ADR-0006 requires it to be reachable and functional *while
//! the primary data path is degraded*, and `deploy/compose/compose.yaml`
//! deliberately gives it no `depends_on: jetstream` for that reason. Doing
//! what `event-ingest` does here would silently convert JetStream into a
//! startup dependency of the control channel and undo that.
//!
//! So the split is: **configuration** is validated eagerly at startup
//! (`NatsTlsConfig::validate` -- path confinement, symlink refusal, private
//! key permissions; all local filesystem work, no network), and the
//! **connection** is established on the fanout worker's first tick and
//! rebuilt by the client itself thereafter. A misconfigured broker client
//! fails startup loudly; an unreachable one does not fail anything at all, it
//! just defers delivery -- which is precisely the behaviour
//! `replay.rs::fanout_worker_retries_after_a_transient_publish_failure`
//! already asserts against a flaky publisher.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use apex_control_plane_api::{
    ControlOutboxBackend, GatewayRuntimeMetrics, GatewayShutdown,
    spawn_fanout_worker_with_metrics_and_shutdown,
};
use apex_durability::{
    AsyncNatsJetStreamClient, EventPublisher, GatewayError, IngestRequest, JetStreamPublisher,
    NatsJetStreamTransport, NatsTlsConfig, PublishOutcome, RetryingJetStreamTransport,
};

use super::env::{fanout_interval, nats_config, nats_retry_attempts};

/// The concrete publisher stack, spelled once so the lazy wrapper and its
/// builder cannot drift apart.
type ControlJetStreamPublisher = JetStreamPublisher<
    RetryingJetStreamTransport<NatsJetStreamTransport<AsyncNatsJetStreamClient>>,
>;

/// An [`EventPublisher`] that connects on first publish rather than at
/// construction.
///
/// Every failure path returns an error to the caller instead of panicking or
/// blocking indefinitely. The fanout worker treats an error as "leave the row
/// pending and retry next tick", so a control command is never lost, never
/// marked complete without having been published, and never held up by this
/// connection attempt on the accept path -- nothing on the accept path calls
/// this type at all.
pub(crate) struct LazyJetStreamPublisher {
    config: NatsTlsConfig,
    trusted_base: PathBuf,
    retry_attempts: usize,
    inner: Option<ControlJetStreamPublisher>,
}

impl LazyJetStreamPublisher {
    pub(crate) fn new(config: NatsTlsConfig, trusted_base: PathBuf, retry_attempts: usize) -> Self {
        Self {
            config,
            trusted_base,
            retry_attempts,
            inner: None,
        }
    }
}

impl EventPublisher for LazyJetStreamPublisher {
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        if self.inner.is_none() {
            // Deliberately not cached-on-failure: the tick interval is already
            // the retry pace, and `AsyncNatsJetStreamClient` has its own
            // rebuild cooldown once a connection has existed.
            self.inner = Some(connect_off_runtime(
                &self.config,
                &self.trusted_base,
                self.retry_attempts,
            )?);
        }
        let publisher = self.inner.as_mut().ok_or_else(GatewayError::internal)?;
        publisher.publish(event)
    }
}

fn build_publisher(
    config: &NatsTlsConfig,
    trusted_base: &Path,
    retry_attempts: usize,
) -> Result<ControlJetStreamPublisher, GatewayError> {
    let client = AsyncNatsJetStreamClient::connect(config, trusted_base)?;
    let transport = NatsJetStreamTransport::new(client, config.clone(), trusted_base)?;
    let transport = RetryingJetStreamTransport::new(transport, retry_attempts)?;
    Ok(JetStreamPublisher::new(transport))
}

/// Builds the client on a plain, unmanaged thread.
///
/// `AsyncNatsJetStreamClient::connect` bottoms out in `Runtime::block_on`,
/// which panics when called on a thread that already has a tokio runtime
/// entered -- and this is reached from inside the fanout worker's `tokio`
/// task. `apps/event-ingest/src/nats/client.rs::rebuild_after_failure` runs
/// its own rebuild off-thread for exactly this reason; this is the same
/// hazard at first connect rather than at reconnect.
fn connect_off_thread(
    config: &NatsTlsConfig,
    trusted_base: &Path,
    retry_attempts: usize,
) -> Result<ControlJetStreamPublisher, GatewayError> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| build_publisher(config, trusted_base, retry_attempts))
            .join()
            .unwrap_or_else(|_| Err(GatewayError::internal()))
    })
}

fn connect_off_runtime(
    config: &NatsTlsConfig,
    trusted_base: &Path,
    retry_attempts: usize,
) -> Result<ControlJetStreamPublisher, GatewayError> {
    // Joining the scoped thread above blocks this one for up to the NATS
    // connect timeout (5s), and during a broker outage that happens on every
    // tick. Announcing it lets the multi-thread runtime migrate other tasks
    // off this worker, so a JetStream outage cannot degrade the accept path
    // this service exists to keep available. `block_in_place` panics on a
    // current-thread runtime, hence the flavor check -- the same guard
    // `event-ingest`'s NATS client applies around its own blocking publish.
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(|| connect_off_thread(config, trusted_base, retry_attempts))
        }
        _ => connect_off_thread(config, trusted_base, retry_attempts),
    }
}

/// Everything the fanout worker needs, resolved before a runtime exists.
///
/// Split from spawning because [`super::service::run`] is synchronous by
/// design (see its doc comment): construction happens with no runtime
/// entered, and `tokio::spawn` requires one. This half touches only the
/// environment and the filesystem.
#[derive(Clone)]
pub(crate) struct ControlFanout {
    publisher: Arc<tokio::sync::Mutex<LazyJetStreamPublisher>>,
    interval: std::time::Duration,
}

impl ControlFanout {
    /// Spawns the worker. Must be called with a runtime entered.
    ///
    /// The returned handle must be bound to a live variable for the process
    /// lifetime by the caller. Dropping a `JoinHandle` detaches rather than
    /// aborts the task in tokio, so a dropped handle would not stop delivery
    /// today -- but relying on that would make "who owns this worker"
    /// invisible, and a later `abort_on_drop` wrapper or `JoinSet` would
    /// silently switch off command delivery with no code change anywhere near
    /// this file.
    pub(crate) fn spawn(
        self,
        backend: Arc<ControlOutboxBackend>,
        metrics: Arc<GatewayRuntimeMetrics>,
        shutdown: GatewayShutdown,
    ) -> tokio::task::JoinHandle<()> {
        println!(
            "apex-control-plane-api fanout worker started (tick {}s)",
            self.interval.as_secs()
        );
        spawn_fanout_worker_with_metrics_and_shutdown(
            backend,
            self.publisher,
            self.interval,
            Some(metrics),
            Some(shutdown),
        )
    }
}

/// Resolves and validates the fanout configuration, or returns `None` when no
/// broker is configured. Opens no socket -- see this module's header.
pub(crate) fn prepare_control_fanout(
    trusted_base: &Path,
) -> Result<Option<ControlFanout>, Box<dyn std::error::Error>> {
    let Some(config) = nats_config()? else {
        // Loud, on stderr, for the same reason the empty operator-token table
        // is: a control gateway whose commands are recorded but never
        // delivered looks completely healthy from the outside. Every
        // SubmitCommand still succeeds; `delivered` is simply always false and
        // no `control` event ever reaches ClickHouse.
        eprintln!(
            "control-plane-api: APEX_CONTROL_NATS_URL is not set; accepted commands stay durably pending and never reach the queryable trace"
        );
        return Ok(None);
    };
    // Eager, offline validation: path confinement under the trusted base,
    // symlink refusal, private-key permission policy, and the `tls://` scheme.
    // No socket is opened here -- see this module's header for why that
    // distinction is load-bearing.
    config.validate(trusted_base).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "APEX_CONTROL_NATS_* configuration rejected: {}",
                error.code.public_code()
            ),
        )
    })?;
    let interval = fanout_interval()?;
    let retry_attempts = nats_retry_attempts()?;
    let publisher = Arc::new(tokio::sync::Mutex::new(LazyJetStreamPublisher::new(
        config,
        trusted_base.to_path_buf(),
        retry_attempts,
    )));
    Ok(Some(ControlFanout {
        publisher,
        interval,
    }))
}
