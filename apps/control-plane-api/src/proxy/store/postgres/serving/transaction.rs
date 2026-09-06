use super::*;
use crate::{ExactScope, ProxyId};
use postgres::{Row, types::ToSql};

pub(super) fn refused() -> ProxyError {
    ProxyError::new(
        "MANAGED_REGISTRY_REFUSED",
        "Managed registry metadata refused.",
    )
}
pub(super) fn positive(value: u64) -> Result<i64, ProxyError> {
    if value == 0 {
        return Err(refused());
    }
    i64::try_from(value).map_err(|_| refused())
}
pub(super) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(in crate::proxy::store::postgres) struct BindingKey {
    pub scope: ExactScope,
    pub proxy: ProxyId,
    pub instance: Uuid,
    pub installation: Uuid,
}
impl BindingKey {
    pub fn new(binding: &proto::ManagedDeploymentBinding) -> Result<Self, ProxyError> {
        let target = binding.target.as_ref().ok_or_else(refused)?;
        positive(target.generation)?;
        positive(target.fencing_token)?;
        journal::request_uuid(&target.revision_id)?;
        if !digest(&binding.config_hash) || !digest(&binding.launch_context_hash) {
            return Err(refused());
        }
        let key = Self {
            scope: ExactScope {
                workspace_id: target.workspace_id.clone(),
                namespace_id: target.namespace_id.clone(),
            },
            proxy: ProxyId::new(&target.proxy_id)?,
            instance: journal::request_uuid(&binding.process_instance_id)?,
            installation: journal::request_uuid(&binding.installation_id)?,
        };
        super::super::super::shared::validate_scope(&key.scope)?;
        Ok(key)
    }
    pub fn scoped(&self) -> journal::Target<'_> {
        journal::Target {
            scope: &self.scope,
            proxy_id: &self.proxy,
        }
    }
}

/// All SQL is synchronous inside main's future bounded physical worker. The
/// connection guard outlives rollback/commit; cancellation never detaches SQL.
pub(in crate::proxy::store::postgres) struct CheckedTransaction<
    'a,
    'b,
    F: Fn() -> Result<(), ProxyError>,
> {
    tx: PostgresTransaction<'a>,
    key: &'b BindingKey,
    check: &'b F,
    pub locked: Row,
    valid_until: Option<i64>,
}
impl<'a, 'b, F: Fn() -> Result<(), ProxyError>> CheckedTransaction<'a, 'b, F> {
    pub fn new(
        mut tx: PostgresTransaction<'a>,
        key: &'b BindingKey,
        check: &'b F,
    ) -> Result<Self, ProxyError> {
        check()?;
        let locked = journal::lock_proxy(&mut tx, key.scoped())?;
        check()?;
        Ok(Self {
            tx,
            key,
            check,
            locked,
            valid_until: None,
        })
    }
    pub fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, ProxyError> {
        (self.check)()?;
        let rows = self
            .tx
            .query(sql, params)
            .map_err(|_| configuration_error())?;
        (self.check)()?;
        Ok(rows)
    }
    pub fn one(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Row, ProxyError> {
        let mut rows = self.query(sql, params)?;
        if rows.len() != 1 {
            return Err(refused());
        }
        rows.pop().ok_or_else(refused)
    }
    pub fn execute(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, ProxyError> {
        (self.check)()?;
        let rows = self
            .tx
            .execute(sql, params)
            .map_err(|_| configuration_error())?;
        (self.check)()?;
        Ok(rows)
    }
    pub fn now(&mut self) -> Result<i64, ProxyError> {
        Ok(self
            .one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
                &[],
            )?
            .get(0))
    }
    pub fn lease(&mut self, lease: &LeasedProxyOperation) -> Result<(), ProxyError> {
        let op = &lease.operation;
        let scope = op.scope.as_ref().ok_or_else(refused)?;
        if scope.workspace_id != self.key.scope.workspace_id
            || scope.namespace_id != self.key.scope.namespace_id
            || scope.proxy_id != self.key.proxy.to_string()
            || !journal::bounded_identifier(&lease.worker_id)
            || !journal::matches_live_target(&self.locked, op)?
        {
            return Err(refused());
        }
        let now = self.now()?;
        (self.check)()?;
        let expiry = journal::exact_live_lease_expiry(
            &mut self.tx,
            self.key.scoped(),
            &journal::request_uuid(&op.operation_id)?,
            positive(op.generation)?,
            &lease.worker_id,
            positive(lease.fencing_token)?,
            now,
        )?
        .ok_or_else(refused)?;
        (self.check)()?;
        let row = self.one("SELECT current_result FROM mcp_proxy_operations WHERE proxy_id=$1 AND operation_id=$2 AND generation=$3 AND revision_id=$4 AND observed_state IN (1,2,6,7)", &[self.key.proxy.as_uuid(), &journal::request_uuid(&op.operation_id)?, &positive(op.generation)?, &journal::request_uuid(&op.revision_id)?])?;
        let stored = proto::ProxyOperation::decode(row.get::<_, Vec<u8>>(0).as_slice())
            .map_err(|_| refused())?;
        if stored != *op {
            return Err(refused());
        }
        if self.now()? >= expiry {
            return Err(refused());
        }
        Ok(())
    }
    pub fn require_valid_until(&mut self, until: i64) {
        self.valid_until = Some(self.valid_until.map_or(until, |old| old.min(until)));
    }
    pub fn finish(mut self, lease: Option<&LeasedProxyOperation>) -> Result<(), ProxyError> {
        if let Some(lease) = lease {
            self.lease(lease)?;
        }
        if let Some(until) = self.valid_until
            && self.now()? >= until
        {
            return Err(refused());
        }
        (self.check)()?;
        self.tx.commit().map_err(|_| configuration_error())?;
        (self.check)()
    }
    pub fn deployment(
        &mut self,
        key: &BindingKey,
        binding: &proto::ManagedDeploymentBinding,
    ) -> Result<Row, ProxyError> {
        let row = self.one("SELECT d.*,s.epoch,s.selected_instance FROM mcp_proxy_deployments d JOIN mcp_proxy_serving_selection s ON s.proxy_id=d.proxy_id WHERE d.instance_id=$1 AND d.proxy_id=$2 AND s.installation_id=$3", &[&key.instance,key.proxy.as_uuid(),&key.installation])?;
        if row.get::<_, Vec<u8>>("binding_bytes") != binding.encode_to_vec() {
            return Err(refused());
        }
        Ok(row)
    }
}
