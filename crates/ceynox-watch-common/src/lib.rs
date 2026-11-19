//! Record layouts shared by the kernel programs and the loader.
//!
//! Everything here crosses the kernel/user boundary through one BPF ring
//! buffer, so every type is `#[repr(C)]`, fixed layout, and free of pointers.
//! Records start with a [`Head`]; `Head::kind` says which record follows.
//!
//! [`Exec`] and [`Open`] end in a large byte buffer of which only a prefix is
//! meaningful. The kernel side sends just that prefix, so the loader must read
//! those two by length, never by `size_of`.
#![no_std]
#![forbid(unsafe_code)]

/// Kernel `TASK_COMM_LEN`.
pub const COMM_LEN: usize = 16;
/// Longest path the kernel will hand back (`PATH_MAX`).
pub const PATH_CAP: usize = 4096;
/// Bytes of `argv` kept per exec. Longer command lines are cut here.
pub const ARGV_CAP: usize = 4096;
/// Bytes kept of the path passed to `execve`.
pub const EXEC_NAME_CAP: usize = 256;
/// `sizeof(sockaddr_un.sun_path)`.
pub const UNIX_PATH_CAP: usize = 108;

pub const KIND_FORK: u32 = 1;
pub const KIND_EXEC: u32 = 2;
pub const KIND_EXIT: u32 = 3;
pub const KIND_OPEN: u32 = 4;
pub const KIND_CONNECT: u32 = 5;
pub const KIND_SEND: u32 = 6;
pub const KIND_CLOSE: u32 = 7;

/// Slots of the per-CPU `LOST` counter array: records that did not fit in
/// the ring buffer, by class.
pub const LOST_PROC: u32 = 0;
pub const LOST_FILE: u32 = 1;
pub const LOST_NET: u32 = 2;
pub const LOST_SLOTS: u32 = 3;

/// Start of every record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Head {
    /// One of the `KIND_*` constants.
    pub kind: u32,
    /// Process id (the kernel's tgid) the record is about.
    pub pid: u32,
    /// `CLOCK_MONOTONIC` nanoseconds.
    pub ts: u64,
}

/// A new process (not a new thread). `head.pid` is the child.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Fork {
    pub head: Head,
    pub ppid: u32,
    pub _pad: u32,
}

/// A process ended. `code` is the raw wait status: exit code in bits 8..16,
/// terminating signal in the low 7 bits.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Exit {
    pub head: Head,
    pub code: u32,
    pub _pad: u32,
}

/// A successful `execve`. Sent truncated to [`Exec::HEAD_LEN`]` + argv_len`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Exec {
    pub head: Head,
    pub ppid: u32,
    pub uid: u32,
    /// Bytes of `argv` that follow: the arguments, each NUL-terminated.
    pub argv_len: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
    /// The path given to `execve`, NUL-terminated. May be relative.
    pub filename: [u8; EXEC_NAME_CAP],
    pub argv: [u8; ARGV_CAP],
}

impl Exec {
    pub const HEAD_LEN: usize = core::mem::offset_of!(Exec, argv);
}

/// A file or directory was opened. Sent truncated to
/// [`Open::HEAD_LEN`]` + path_len`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Open {
    pub head: Head,
    /// `file->f_flags`: the `open(2)` flags.
    pub flags: u32,
    /// `inode->i_mode`: file type and permission bits.
    pub mode: u32,
    /// Bytes of `path` that follow, including the terminating NUL.
    pub path_len: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
    /// Absolute path as the kernel resolves it (symlinks followed).
    pub path: [u8; PATH_CAP],
}

impl Open {
    pub const HEAD_LEN: usize = core::mem::offset_of!(Open, path);
}

/// An outgoing connection attempt ([`KIND_CONNECT`]) or a datagram sent to a
/// peer ([`KIND_SEND`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sock {
    pub head: Head,
    /// Address family: `AF_INET` (2), `AF_INET6` (10) or `AF_UNIX` (1).
    pub family: u16,
    /// Destination port, host byte order. 0 for `AF_UNIX`.
    pub port: u16,
    /// Socket type: `SOCK_STREAM` (1), `SOCK_DGRAM` (2), `SOCK_RAW` (3)...
    pub sock_type: u16,
    /// `AF_UNIX` only: bytes of `unix_path` that are part of the address.
    pub unix_len: u16,
    /// IPv4 in the first four bytes, or a full IPv6 address.
    pub addr: [u8; 16],
    pub comm: [u8; COMM_LEN],
    /// `AF_UNIX` only: the socket path. A leading NUL is an abstract socket.
    pub unix_path: [u8; UNIX_PATH_CAP],
    pub _pad2: [u8; 4],
}

/// A TCP connection that was reported by [`KIND_CONNECT`] has been closed.
/// Carries how much went each way. `head.pid` is the process that opened
/// the connection, which is not always the one closing it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Closed {
    pub head: Head,
    /// Address family: `AF_INET` (2) or `AF_INET6` (10).
    pub family: u16,
    /// Destination port, host byte order.
    pub port: u16,
    /// `sk_shutdown` at the time: [`RCV_SHUTDOWN`] once the peer has said
    /// it is done sending, [`SEND_SHUTDOWN`] once we have.
    pub shutdown: u8,
    /// Non-zero when our end-of-data marker has been acknowledged.
    pub fin_acked: u8,
    pub _pad: u16,
    /// IPv4 in the first four bytes, or a full IPv6 address.
    pub addr: [u8; 16],
    /// The kernel's count of acknowledged bytes. Besides data it counts one
    /// for the opening handshake, and one for our end-of-data marker when
    /// `fin_acked` is set.
    pub sent: u64,
    /// The kernel's count of received bytes. Besides data it counts one for
    /// the peer's end-of-data marker when `shutdown` has [`RCV_SHUTDOWN`].
    pub received: u64,
}

pub const RCV_SHUTDOWN: u8 = 1;
pub const SEND_SHUTDOWN: u8 = 2;

/// What the programs remember about an open connection, keyed by its
/// kernel socket, so that its closing can be tied back to who opened it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Conn {
    pub pid: u32,
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 16],
}

/// Byte offsets of the kernel struct fields the programs read.
///
/// Rust BPF programs have no CO-RE relocations, so the loader looks these up
/// in the running kernel's BTF (`/sys/kernel/btf/vmlinux`) and writes them
/// into the program's read-only data before loading it. That keeps one
/// compiled object correct across kernel versions and configurations.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Offsets {
    pub task_pid: u32,
    pub task_tgid: u32,
    pub task_real_parent: u32,
    pub task_group_leader: u32,
    pub task_thread_pid: u32,
    /// `struct pid`: nesting depth of its namespace, and the per-level ids.
    pub pid_level: u32,
    pub pid_numbers: u32,
    /// `struct upid`: one (id, namespace) pair of `pid.numbers`.
    pub upid_nr: u32,
    pub upid_ns: u32,
    pub upid_size: u32,
    pub task_exit_code: u32,
    pub task_mm: u32,
    pub mm_arg_start: u32,
    pub mm_arg_end: u32,
    pub bprm_filename: u32,
    pub file_f_path: u32,
    pub file_f_flags: u32,
    pub file_f_inode: u32,
    pub inode_i_mode: u32,
    pub socket_sk: u32,
    pub socket_type: u32,
    pub sk_family: u32,
    pub sk_daddr: u32,
    pub sk_dport: u32,
    pub sk_v6_daddr: u32,
    pub msghdr_name: u32,
    /// `struct tcp_sock`: the byte counters. Zero when the kernel has no
    /// such field, in which case transfers are not reported.
    pub tcp_bytes_acked: u32,
    pub tcp_bytes_received: u32,
    /// For telling data apart from the handshake bytes in those counters.
    /// Zero when not available; the counts are then high by one or two.
    pub sk_shutdown: u32,
    pub tcp_snd_una: u32,
    pub tcp_write_seq: u32,
}

/// Load-time settings, written into the program's read-only data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Non-zero: report every process. Zero: only those in the `TRACKED` map
    /// and the processes they start.
    pub all: u32,
    /// The watcher's own pid, as it sees it. Its activity is never reported.
    pub self_pid: u32,
    /// Device and inode of the watcher's `/proc/self/ns/pid`: the pid
    /// namespace whose process ids the records are expressed in.
    pub ns_dev: u32,
    pub ns_ino: u32,
    pub off: Offsets,
}

/// Number of `u32` words in a [`Config`].
pub const CONFIG_WORDS: usize = 35;
const _: () = assert!(core::mem::size_of::<Config>() == CONFIG_WORDS * 4);

impl Config {
    pub const fn zeroed() -> Self {
        Self::from_words([0; CONFIG_WORDS])
    }

    /// The in-memory layout as words, for writing into the program's data.
    pub const fn to_words(&self) -> [u32; CONFIG_WORDS] {
        let o = &self.off;
        [
            self.all,
            self.self_pid,
            self.ns_dev,
            self.ns_ino,
            o.task_pid,
            o.task_tgid,
            o.task_real_parent,
            o.task_group_leader,
            o.task_thread_pid,
            o.pid_level,
            o.pid_numbers,
            o.upid_nr,
            o.upid_ns,
            o.upid_size,
            o.task_exit_code,
            o.task_mm,
            o.mm_arg_start,
            o.mm_arg_end,
            o.bprm_filename,
            o.file_f_path,
            o.file_f_flags,
            o.file_f_inode,
            o.inode_i_mode,
            o.socket_sk,
            o.socket_type,
            o.sk_family,
            o.sk_daddr,
            o.sk_dport,
            o.sk_v6_daddr,
            o.msghdr_name,
            o.tcp_bytes_acked,
            o.tcp_bytes_received,
            o.sk_shutdown,
            o.tcp_snd_una,
            o.tcp_write_seq,
        ]
    }

    pub const fn from_words(w: [u32; CONFIG_WORDS]) -> Self {
        Self {
            all: w[0],
            self_pid: w[1],
            ns_dev: w[2],
            ns_ino: w[3],
            off: Offsets {
                task_pid: w[4],
                task_tgid: w[5],
                task_real_parent: w[6],
                task_group_leader: w[7],
                task_thread_pid: w[8],
                pid_level: w[9],
                pid_numbers: w[10],
                upid_nr: w[11],
                upid_ns: w[12],
                upid_size: w[13],
                task_exit_code: w[14],
                task_mm: w[15],
                mm_arg_start: w[16],
                mm_arg_end: w[17],
                bprm_filename: w[18],
                file_f_path: w[19],
                file_f_flags: w[20],
                file_f_inode: w[21],
                inode_i_mode: w[22],
                socket_sk: w[23],
                socket_type: w[24],
                sk_family: w[25],
                sk_daddr: w[26],
                sk_dport: w[27],
                sk_v6_daddr: w[28],
                msghdr_name: w[29],
                tcp_bytes_acked: w[30],
                tcp_bytes_received: w[31],
                sk_shutdown: w[32],
                tcp_snd_una: w[33],
                tcp_write_seq: w[34],
            },
        }
    }
}

/// What the kernel side learned about the watcher at start-up: one value of
/// the `WATCHER` map, as `[ready, level, namespace, host pid]`.
///
/// Process ids differ per pid namespace. The kernel works in the root
/// namespace's ids; the watcher, which may be inside a container, needs its
/// own. `level` and `namespace` identify the watcher's namespace so that
/// every record can carry the id the watcher would see.
pub type Watcher = [u64; 4];
pub const WATCHER_READY: usize = 0;
pub const WATCHER_LEVEL: usize = 1;
pub const WATCHER_NS: usize = 2;
pub const WATCHER_HOST_PID: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    /// `to_words` must list the fields in declaration order, because the
    /// kernel side reads the words back as a `Config`.
    #[test]
    fn words_match_the_struct_layout() {
        let mut w = [0u32; CONFIG_WORDS];
        let mut i = 0;
        while i < CONFIG_WORDS {
            w[i] = 100 + i as u32;
            i += 1;
        }
        let cfg = Config::from_words(w);
        assert_eq!(cfg.to_words(), w);
        let base = &cfg as *const Config as usize;
        assert_eq!(&cfg.all as *const u32 as usize - base, 0);
        assert_eq!(&cfg.ns_ino as *const u32 as usize - base, 3 * 4);
        assert_eq!(&cfg.off.task_pid as *const u32 as usize - base, 4 * 4);
        assert_eq!(&cfg.off.upid_size as *const u32 as usize - base, 13 * 4);
        assert_eq!(&cfg.off.msghdr_name as *const u32 as usize - base, 29 * 4);
        assert_eq!(&cfg.off.tcp_bytes_received as *const u32 as usize - base, 31 * 4);
        assert_eq!(&cfg.off.tcp_write_seq as *const u32 as usize - base, (CONFIG_WORDS - 1) * 4);
        assert_eq!(cfg.off.tcp_write_seq, 100 + CONFIG_WORDS as u32 - 1);
    }
}
