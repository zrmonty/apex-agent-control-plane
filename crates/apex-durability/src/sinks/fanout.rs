use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread;

use super::traits::{ArchivePublisher, ClickHousePublisher};
use crate::{
    EventPublisher, GatewayError, IngestRequest, JetStreamPublisher, JetStreamTransport,
    PublishOutcome,
};

pub struct DurableFanoutPublisher<J: JetStreamTransport, C, A> {
    jetstream: JetStreamPublisher<J>,
    clickhouse: C,
    archive: A,
    parallel_sinks: bool,
}

impl<J, C, A> DurableFanoutPublisher<J, C, A>
where
    J: JetStreamTransport,
    C: ClickHousePublisher,
    A: ArchivePublisher,
{
    pub fn new(jetstream: J, clickhouse: C, archive: A) -> Self {
        Self {
            jetstream: JetStreamPublisher::new(jetstream),
            clickhouse,
            archive,
            parallel_sinks: false,
        }
    }

    /// Builds a fanout that overlaps the independent downstream writes for a
    /// single event. Each sink remains an idempotent retry unit at the outbox
    /// boundary, and any failed result still causes the event to be retried.
    pub fn with_parallel_sinks(jetstream: J, clickhouse: C, archive: A) -> Self {
        Self {
            jetstream: JetStreamPublisher::new(jetstream),
            clickhouse,
            archive,
            parallel_sinks: true,
        }
    }

    pub fn jetstream(&self) -> &JetStreamPublisher<J> {
        &self.jetstream
    }

    pub fn clickhouse(&self) -> &C {
        &self.clickhouse
    }

    pub fn archive(&self) -> &A {
        &self.archive
    }
}

impl<J, C, A> EventPublisher for DurableFanoutPublisher<J, C, A>
where
    J: JetStreamTransport + Send,
    C: ClickHousePublisher + Send,
    A: ArchivePublisher + Send,
{
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        if self.parallel_sinks {
            return self.publish_parallel(event);
        }
        catch_unwind(AssertUnwindSafe(|| self.jetstream.publish(event)))
            .map_err(|_| GatewayError::internal())??;
        let clickhouse = catch_unwind(AssertUnwindSafe(|| self.clickhouse.write_event(event)))
            .map_err(|_| GatewayError::internal())?;
        clickhouse?;
        catch_unwind(AssertUnwindSafe(|| self.archive.write_event(event)))
            .map_err(|_| GatewayError::internal())??;
        // A fanout has no memory of previous events, so reaching here always
        // means this call did the work. Only an outbox-backed publisher can
        // report AlreadyComplete.
        Ok(PublishOutcome::Published)
    }
}

impl<J, C, A> DurableFanoutPublisher<J, C, A>
where
    J: JetStreamTransport + Send,
    C: ClickHousePublisher + Send,
    A: ArchivePublisher + Send,
{
    fn publish_parallel(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        let (jetstream, clickhouse, archive) =
            (&mut self.jetstream, &mut self.clickhouse, &mut self.archive);
        let (jetstream_result, clickhouse_result, archive_result) = thread::scope(|scope| {
            let jetstream =
                scope.spawn(
                    || match catch_unwind(AssertUnwindSafe(|| jetstream.publish(event))) {
                        Ok(result) => result,
                        Err(_) => Err(GatewayError::internal()),
                    },
                );
            let clickhouse = scope.spawn(|| {
                match catch_unwind(AssertUnwindSafe(|| clickhouse.write_event(event))) {
                    Ok(result) => result,
                    Err(_) => Err(GatewayError::internal()),
                }
            });
            let archive = scope.spawn(|| {
                match catch_unwind(AssertUnwindSafe(|| archive.write_event(event))) {
                    Ok(result) => result,
                    Err(_) => Err(GatewayError::internal()),
                }
            });
            (
                join_scoped(jetstream),
                join_scoped(clickhouse),
                join_scoped(archive),
            )
        });
        jetstream_result?;
        clickhouse_result?;
        archive_result?;
        Ok(PublishOutcome::Published)
    }
}

fn join_scoped<T>(
    handle: thread::ScopedJoinHandle<'_, Result<T, GatewayError>>,
) -> Result<T, GatewayError> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(GatewayError::internal()),
    }
}
