//! Stands in where there is no sensor that can attach to running processes:
//! on macOS (which watches commands through the sandbox instead, see
//! `macos.rs`) and on platforms not supported at all. It has the shape of
//! the Linux sensor so the rest of the program builds unchanged.

use super::{Options, SensorError};
use crate::event::Event;

#[derive(Debug)]
pub struct Sensor;

impl Sensor {
    pub fn start(opts: &Options) -> Result<Self, SensorError> {
        let Options { scope: _, buffer_bytes: _ } = opts;
        Err(SensorError::new(if cfg!(target_os = "macos") {
            "watching processes that are already running (--pid, --all) works on Linux only. \
             On macOS, start the command under ceynox-watch: ceynox-watch -- <command>"
                .to_string()
        } else {
            format!("ceynox-watch does not support {} yet", std::env::consts::OS)
        }))
    }

    pub fn poll(
        &mut self,
        _timeout_ms: u32,
        _wake: Option<std::os::fd::BorrowedFd<'_>>,
        _sink: &mut dyn FnMut(Event),
    ) -> Result<(), SensorError> {
        Ok(())
    }

    pub fn drain(&mut self, _sink: &mut dyn FnMut(Event)) {}
}
