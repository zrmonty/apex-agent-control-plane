use super::*;
use crate::proxy::{McpProxyRevision, ProxyRedactionStatus, ProxyRevisionId};

pub(super) fn select(
    tx: &mut PostgresTransaction<'_>,
    input: &ManagedLifecycleInput,
    source: McpProxyRevision,
    now: u64,
) -> Result<McpProxyRevision, ProxyError> {
    match &input.action {
        Action::Rollback { target_revision_id } => {
            let target = query_revision_row(tx, &input.proxy_id, target_revision_id)?
                .ok_or_else(ProxyError::revision_not_found)?;
            if !target.published
                || matches!(
                    target.revision.lifecycle_state,
                    State::Retired | State::Retiring
                )
            {
                return Err(ProxyError::invalid_lifecycle_transition());
            }
            super::super::super::publish_capabilities::validate_publish_capabilities(
                &target.revision.spec,
            )?;
            Ok(target.revision)
        }
        Action::Rotate { secret_refs } => {
            let mut spec = source.spec;
            rotate_exact_domain(&mut spec, secret_refs)?;
            super::super::super::publish_capabilities::validate_publish_capabilities(&spec)?;
            let revision = super::super::super::shared::build_revision(
                input.proxy_id.clone(),
                ProxyRevisionId::new(&input.request_id)?,
                spec,
                input.actor_id.clone(),
                State::Draft,
                ProxyRedactionStatus::Redacted,
                u128::from(now),
            )?;
            tx.execute("INSERT INTO mcp_proxy_revisions (proxy_id,revision_id,spec_json,config_hash,lifecycle_state,
                redaction_status,created_by,created_at_micros,created_at,is_published)
                VALUES ($1,$2,$3,$4,'draft','redacted',$5,$6,$7,TRUE)",
                &[input.proxy_id.as_uuid(), revision.revision_id.as_uuid(),
                &super::super::super::shared::spec_json(&revision.spec), &revision.config_hash,
                &revision.created_by, &i64::try_from(now).map_err(|_| configuration_error())?, &revision.created_at])
                .map_err(|_| configuration_error())?;
            Ok(revision)
        }
        Action::Pause | Action::Retire => Ok(source),
        _ => {
            super::super::super::publish_capabilities::validate_publish_capabilities(&source.spec)?;
            Ok(source)
        }
    }
}

// The existing flat API carries no old-to-new mapping. It can rotate exactly
// one distinct outbound credential domain, never assign credentials by order.
fn rotate_exact_domain(
    spec: &mut crate::proxy::ProxySpec,
    replacements: &[crate::proxy::SecretRef],
) -> Result<(), ProxyError> {
    let [replacement] = replacements else {
        return Err(ProxyError::invalid_proxy_spec(
            "Rotation requires one unambiguous credential domain.",
        ));
    };
    let existing: std::collections::BTreeSet<_> = spec
        .upstreams
        .iter()
        .flat_map(|u| u.credential_ref.iter().chain(u.secret_refs.iter()))
        .chain(spec.cli_profiles.iter().flat_map(|p| p.secret_refs.iter()))
        .chain(
            spec.auth_bindings
                .iter()
                .flat_map(|b| b.outbound_credential_ref.iter()),
        )
        .map(|r| r.as_str().to_owned())
        .collect();
    if existing.len() != 1 {
        return Err(ProxyError::invalid_proxy_spec(
            "Rotation requires one unambiguous credential domain.",
        ));
    }
    let rewrite = |reference: &mut crate::proxy::SecretRef| {
        if existing.contains(reference.as_str()) {
            *reference = replacement.clone();
        }
    };
    for upstream in &mut spec.upstreams {
        for reference in upstream
            .credential_ref
            .iter_mut()
            .chain(upstream.secret_refs.iter_mut())
        {
            rewrite(reference);
        }
    }
    for profile in &mut spec.cli_profiles {
        for reference in &mut profile.secret_refs {
            rewrite(reference);
        }
    }
    for binding in &mut spec.auth_bindings {
        if let Some(reference) = &mut binding.outbound_credential_ref {
            rewrite(reference);
        }
    }
    Ok(())
}
