//! Production process owner. The refresh thread is retained through physical exit.
use super::*;
use crate::config::{Directory, deployment::Deployment};
use std::path::{Path, PathBuf};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

/// Run the Linux production process from a fixed, protected absolute directory.
/// Configured execution provisions dormant resources, never operational readiness.
///
/// # Errors
/// Static refusals for invalid configuration, missing authority, or listener failure.
pub fn run(path: &Path) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "RUNTIME_STARTUP_UNAVAILABLE")?;
    runtime.block_on(run_async(path.to_owned()))
}

async fn run_async(path: PathBuf) -> Result<(), &'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    // Register signals before beginning any deployment read or connection.
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|_| "RUNTIME_SIGNAL_UNAVAILABLE")?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|_| "RUNTIME_SIGNAL_UNAVAILABLE")?;
    let (shutdown, stopped) = watch::channel(false);
    let (bootstrap, loaded) = oneshot::channel();
    let mut bootstrap = Some(bootstrap);
    let mut directory = None;
    let mut fingerprint = None;
    let mut restart_required = false;
    let reader = owner::Reader::start(move || {
        let result = (|| {
            if restart_required {
                return Err(owner::UNAVAILABLE);
            }
            if directory.is_none() {
                directory = Some(Directory::open(&path)?);
            }
            let (deployment, metadata) =
                Deployment::load(directory.as_ref().ok_or(owner::UNAVAILABLE)?, fingerprint)?;
            if fingerprint.is_some_and(|f| f != deployment.fingerprint) {
                restart_required = true;
                return Err(owner::UNAVAILABLE);
            }
            fingerprint = Some(deployment.fingerprint);
            if let Some(sender) = bootstrap.take() {
                let _ = sender.send(Ok(deployment));
            }
            Ok(metadata)
        })();
        if let Err(code) = result {
            if code == "RUNTIME_RESTART_REQUIRED" {
                restart_required = true;
            }
            if let Some(sender) = bootstrap.take() {
                let _ = sender.send(Err(code));
            }
        }
        result
    })?;
    let shared = Arc::clone(&reader.shared);
    let session = session(loaded, shared, stopped, reader.publication.clone());
    tokio::pin!(session);
    let result = tokio::select! {
        result=&mut session=>result,
        _=terminate.recv()=>{let _=shutdown.send(true);session.await},
        _=interrupt.recv()=>{let _=shutdown.send(true);session.await},
    };
    let _ = shutdown.send(true);
    // Joining is intentional, even for a stalled regular-file read: no detached
    // replacement worker and no "timeout completed" claim before physical exit.
    drop(reader);
    result
}

pub(super) async fn session(
    loaded: oneshot::Receiver<Result<Deployment, &'static str>>,
    shared: owner::Shared,
    mut stopped: watch::Receiver<bool>,
    publication: watch::Receiver<bool>,
) -> Result<(), &'static str> {
    let ingress_shutdown = stopped.clone();
    let startup = async {
        let deployment = loaded.await.map_err(|_| "RUNTIME_CONFIG_UNAVAILABLE")??;
        let authority = RuntimeAuthorityClient::connect(deployment.authority_config())
            .await
            .map_err(|_| "RUNTIME_AUTHORITY_UNAVAILABLE")?;
        prepare_listener(deployment, authority, shared, ingress_shutdown, publication).await
    };
    let (router, incoming) = tokio::select! {
        result=tokio::time::timeout(BUDGET,startup)=>result.map_err(|_|"RUNTIME_STARTUP_DEADLINE")??,
        _=stopped.changed()=>return Ok(()),
    };
    if *stopped.borrow() {
        return Ok(());
    }
    router
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = stopped.changed().await;
        })
        .await
        .map_err(|_| "RUNTIME_LISTENER_FAILED")
}

// Keep the post-connect publication/bind phase explicit so its scheduling boundary
// can be tested with the actual protected deployment and a completed TLS connection.
pub(super) async fn prepare_listener(
    mut deployment: Deployment,
    authority: RuntimeAuthorityClient,
    shared: owner::Shared,
    stopped: watch::Receiver<bool>,
    mut publication: watch::Receiver<bool>,
) -> Result<(tonic::transport::server::Router, TcpIncoming), &'static str> {
    // The first physical read may still be finishing after bootstrap delivery
    // and authority connect. Stay within session's original deadline/shutdown
    // select while awaiting explicit publication; never poll/sleep for metadata.
    publication
        .wait_for(|published| *published)
        .await
        .map_err(|_| "RUNTIME_CONFIG_UNAVAILABLE")?;
    owner::snapshot(&shared)?;
    let incoming =
        TcpIncoming::bind(deployment.config.listen).map_err(|_| "RUNTIME_LISTEN_UNAVAILABLE")?;
    let tls = deployment.server_tls();
    let authority = Arc::new(authority);
    let execution = deployment
        .resources
        .take()
        .map(|resources| {
            crate::execution::Facility::start(
                resources,
                Arc::clone(&authority),
                Arc::clone(&shared),
                deployment.config.installation_id.clone(),
                stopped.clone(),
            )
        })
        .transpose()?;
    let ingress = Ingress {
        authority,
        installation: deployment.config.installation_id.clone(),
        shared,
        slots: Semaphore::new(8),
        shutdown: stopped,
        execution,
    };
    let router = router(ingress, tls)?;
    drop(deployment);
    Ok((router, incoming))
}
