//! Restart-safe security finding journal.

mod error;
mod journal;

#[cfg(test)]
mod tests;

pub use error::FindingPersistenceError;
pub use journal::FindingJournal;
