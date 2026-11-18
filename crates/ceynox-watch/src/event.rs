//! What a sensor reports. One [`Event`] per thing a process did, the same on
//! every platform, and the unit of the `--json` output (one object per line).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    pub pid: u32,
    #[serde(flatten)]
    pub what: What,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum What {
    /// A new process, still running its parent's program.
    Fork { ppid: u32 },
    /// The process started running a program.
    Exec {
        ppid: u32,
        uid: u32,
        /// The program, as an absolute path when it could be resolved.
        exe: String,
        argv: Vec<String>,
        /// Working directory at the time, when it could be read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// `true` when this describes a process that was already running
        /// when watching began, rather than an exec that was observed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        existing: bool,
    },
    Exit {
        /// Exit status, when the process exited by itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        /// The signal that killed it, otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },
    /// A file or directory was opened.
    Open {
        path: String,
        /// Opened for writing (including create and truncate).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        write: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        dir: bool,
    },
    /// An outgoing connection was attempted, or datagrams were sent.
    Connect {
        peer: Peer,
        /// The host name this address was last looked up by, when a DNS
        /// reply carrying it was seen.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// The sensor could not keep up and this many events were dropped.
    Lost { count: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "net", rename_all = "snake_case")]
pub enum Peer {
    Ip {
        ip: IpAddr,
        port: u16,
        proto: Proto,
    },
    /// A UNIX-domain socket. `path` starts with `@` for an abstract socket.
    Unix {
        path: String,
    },
    /// An internet peer of which only the port is known. Reported where the
    /// sensor cannot see addresses (macOS without packet capture).
    Port {
        port: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
    Other,
}
