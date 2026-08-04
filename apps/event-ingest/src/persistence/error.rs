use crate::security::FindingError;

#[derive(Debug)]
pub enum FindingPersistenceError {
    Io,
    InvalidPath,
    OversizedJournal,
    MalformedRecord,
    Store(FindingError),
}

impl FindingPersistenceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io => "SECURITY_FINDING_JOURNAL_IO",
            Self::InvalidPath => "SECURITY_FINDING_JOURNAL_PATH_INVALID",
            Self::OversizedJournal => "SECURITY_FINDING_JOURNAL_TOO_LARGE",
            Self::MalformedRecord => "SECURITY_FINDING_JOURNAL_RECORD_INVALID",
            Self::Store(_) => "SECURITY_FINDING_JOURNAL_STORE_REJECTED",
        }
    }
}

impl std::fmt::Display for FindingPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (summary, cause, next) = match self {
            Self::Io => (
                "The security finding journal could not be read or durably written.",
                "The filesystem returned an I/O failure while opening, replaying, or syncing the journal.",
                "Check the path, permissions, disk health, and available space before retrying.",
            ),
            Self::InvalidPath => (
                "The security finding journal path is outside the trusted persistence boundary.",
                "The base or journal path is missing, symlinked, non-directory, relative, or escapes the configured base.",
                "Use an absolute regular-file path inside the configured trusted base directory.",
            ),
            Self::OversizedJournal => (
                "The security finding journal exceeds a configured safety limit.",
                "The journal or one record is larger than the bounded replay limits.",
                "Rotate or archive the journal through the retention workflow, then retry with a bounded file.",
            ),
            Self::MalformedRecord => (
                "The security finding journal contains an invalid record.",
                "A JSONL record could not be decoded or serialized without violating the finding contract.",
                "Quarantine the journal, identify the first malformed line, and restore from a trusted immutable copy.",
            ),
            Self::Store(error) => {
                return write!(
                    f,
                    "{}: persistence rejected the finding. Cause: {}",
                    self.code(),
                    error
                );
            }
        };
        write!(
            f,
            "{}: {} Cause: {} Next: {}",
            self.code(),
            summary,
            cause,
            next
        )
    }
}

impl std::error::Error for FindingPersistenceError {}
