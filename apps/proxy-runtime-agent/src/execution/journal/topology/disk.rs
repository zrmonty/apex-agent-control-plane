use super::super::document;
use super::{Document, ERROR};
use crate::config::Directory;

pub(super) fn load(root: &Directory, name: &str) -> Result<Option<Document>, &'static str> {
    document::load(root, name, 262_144, Document::validate).map_err(|_| ERROR)
}
pub(super) fn save(root: &Directory, name: &str, d: &Document) -> Result<(), &'static str> {
    document::save(root, name, d, 262_144, Document::validate).map_err(|_| ERROR)
}
#[cfg(test)]
pub(super) use document::FAIL_POINT;
