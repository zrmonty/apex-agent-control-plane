//! Registration is a prerequisite to start, not readiness or serving authority.
use crate::{execution::record::Installed, proto::RuntimeLaunchAttestation};

pub(in crate::execution) fn before_start(
    installation: &str,
    installed: &Installed,
    required: bool,
    check: &mut impl FnMut() -> Result<(), &'static str>,
    register: &mut impl FnMut(&RuntimeLaunchAttestation) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    if !required || installed.paired_containers.is_none() {
        return Err("RUNTIME_REGISTRATION_REFUSED");
    }
    check()?;
    let attestation = installed
        .attestation(installation)?
        .ok_or("RUNTIME_INSTANCE_ATTESTATION_REFUSED")?;
    register(&attestation)?;
    // Current policy, sealed bytes and whole-operation budget still have to
    // hold after the network callback, including idempotent recovery receipts.
    check()
}
