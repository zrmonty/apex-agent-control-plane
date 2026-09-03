//! Platform-specific private-key permission probes.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::private_key_permissions_restricted;

#[cfg(not(windows))]
mod non_windows;
#[cfg(not(windows))]
pub use non_windows::private_key_permissions_restricted;


