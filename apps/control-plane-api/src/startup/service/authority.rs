//! Optional callback owner, retained by the synchronous production root.
use crate::startup::env::{self, RuntimeAuthorityEnv};
use apex_control_plane_api::{RuntimeAuthorityOwner, RuntimeAuthorityPolicyFiles};
use std::{io, path::Path};

pub(super) fn prepare(
    settings: Option<RuntimeAuthorityEnv>,
    base: &Path,
) -> Result<Option<RuntimeAuthorityOwner>, io::Error> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let database = env::control_postgres_url()?.ok_or_else(unavailable)?;
    let files = RuntimeAuthorityPolicyFiles::new(
        base.to_owned(),
        settings.peer_policy_file,
        settings.enrollment_file,
    )
    .map_err(|_| unavailable())?;
    RuntimeAuthorityOwner::new(files, &database)
        .map(Some)
        .map_err(|_| unavailable())
}

pub(super) fn finish(owner: Option<&mut RuntimeAuthorityOwner>) -> Result<(), io::Error> {
    if owner.is_some_and(|owner| !owner.shutdown().cleanup_complete) {
        return Err(io::Error::other(
            "runtime authority cleanup was not observed complete",
        ));
    }
    Ok(())
}

fn unavailable() -> io::Error {
    io::Error::other("runtime authority configuration unavailable")
}

type RootResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn report_cleanup(
    primary: RootResult,
    cleanup: Result<(), io::Error>,
    diagnostic: &mut impl io::Write,
) -> RootResult {
    if cleanup.is_err() {
        // Always report before propagating the independent primary error. Never
        // print either error's message, source chain, path or connection string.
        if writeln!(diagnostic, "RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE").is_err() {
            return Err(io::Error::other(
                "RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE (diagnostic output failed)",
            )
            .into());
        }
        return primary.and(Err(io::Error::other(
            "RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE",
        )
        .into()));
    }
    primary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_cleanup_is_reported_even_when_primary_startup_already_failed() {
        let mut diagnostic = Vec::new();
        let result = report_cleanup(
            Err(io::Error::other("PRIMARY-PRIVATE-CANARY").into()),
            Err(io::Error::other("CLEANUP-PRIVATE-CANARY")),
            &mut diagnostic,
        );
        assert_eq!(result.unwrap_err().to_string(), "PRIMARY-PRIVATE-CANARY");
        assert_eq!(
            String::from_utf8(diagnostic).unwrap(),
            "RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE\n"
        );
    }

    #[test]
    fn incomplete_cleanup_alone_is_a_failure_but_complete_cleanup_is_quiet() {
        let mut diagnostic = Vec::new();
        assert!(report_cleanup(Ok(()), Ok(()), &mut diagnostic).is_ok());
        assert!(diagnostic.is_empty());
        let result = report_cleanup(
            Ok(()),
            Err(io::Error::other("PRIVATE-CANARY")),
            &mut diagnostic,
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE"
        );
        assert_eq!(
            String::from_utf8(diagnostic).unwrap(),
            "RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE\n"
        );
    }
}
