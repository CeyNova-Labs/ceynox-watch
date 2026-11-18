//! Sensors: the platform-specific part that observes processes and turns
//! what they do into [`Event`](crate::event::Event)s.

use std::fmt;

#[cfg(any(target_os = "linux", test))]
pub mod btf;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub mod dns;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub mod privdrop;
#[cfg(target_os = "linux")]
pub mod procfs;

#[cfg(any(target_os = "macos", test))]
pub mod macos;
#[cfg(any(target_os = "macos", test))]
pub mod pktap;
#[cfg(not(target_os = "linux"))]
mod unsupported;

#[cfg(target_os = "linux")]
pub use linux::Sensor;
#[cfg(not(target_os = "linux"))]
pub use unsupported::Sensor;

/// Which processes to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Everything on the machine.
    All,
    /// These processes, their existing descendants, and whatever they start.
    Pids(Vec<u32>),
}

// Only the Linux sensor has use for these.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct Options {
    pub scope: Scope,
    /// Size of the kernel-to-user event buffer. Rounded up to a power of two.
    pub buffer_bytes: u32,
}

/// Why a sensor could not start or keep running, in words meant for the
/// person at the terminal.
#[derive(Debug)]
pub struct SensorError(pub String);

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SensorError {}

impl SensorError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}
