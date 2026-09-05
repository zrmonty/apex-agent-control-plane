//! Pure seam regressions; no Docker, runtime, network, filesystem or lease owner.

#[path = "runtime_boundary/extract.rs"]
mod extract;
#[path = "runtime_boundary/owned.rs"]
mod owned;
#[path = "runtime_boundary/owned_rejections.rs"]
mod owned_rejections;
#[path = "runtime_boundary/support.rs"]
mod support;
#[path = "runtime_boundary/target.rs"]
mod target;
#[path = "runtime_boundary/wire.rs"]
mod wire;
