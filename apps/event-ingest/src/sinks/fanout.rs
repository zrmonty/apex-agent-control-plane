use std::panic::{AssertUnwindSafe, catch_unwind};

use super::traits::{ArchivePublisher, ClickHousePublisher};
use crate::{EventPublisher, GatewayError, IngestRequest, JetStreamPublisher, JetStreamTransport};

pub struct DurableFanoutPublisher<J: JetStreamTransport, C, A> {
    jetstream: JetStreamPublisher<J>,
    clickhouse: C,
    archive: A,
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
    J: JetStreamTransport,
    C: ClickHousePublisher,
    A: ArchivePublisher,
{
    fn publish(&mut self, event: &IngestRequest) -> Result<(), GatewayError> {
        catch_unwind(AssertUnwindSafe(|| self.jetstream.publish(event)))
            .map_err(|_| GatewayError::internal())??;
        let clickhouse = catch_unwind(AssertUnwindSafe(|| self.clickhouse.write_event(event)))
            .map_err(|_| GatewayError::internal())?;
        clickhouse?;
        catch_unwind(AssertUnwindSafe(|| self.archive.write_event(event)))
            .map_err(|_| GatewayError::internal())?
    }
}
