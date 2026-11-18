//! Kernel side of ceynox-watch.
//!
//! Six small programs report what processes do, into one ring buffer:
//!
//! | Program    | Hook                                   | Record            |
//! |------------|----------------------------------------|-------------------|
//! | `on_fork`  | BTF tracepoint `sched_process_fork`    | `Fork`            |
//! | `on_exec`  | BTF tracepoint `sched_process_exec`    | `Exec`            |
//! | `on_exit`  | BTF tracepoint `sched_process_exit`    | `Exit`            |
//! | `on_open`  | fentry `security_file_open`            | `Open`            |
//! | `on_connect` | fentry `security_socket_connect`     | `Sock` (connect)  |
//! | `on_send`  | fentry `security_socket_sendmsg`       | `Sock` (datagram) |
//!
//! A seventh, `dns_replies`, is a socket filter. The loader attaches it to a
//! packet socket of its own, where it selects DNS replies so that addresses
//! can be shown with the names they were looked up by. A socket filter only
//! decides what that one socket receives; it cannot touch the traffic.
//!
//! File and network activity is hooked at the kernel's security layer rather
//! than at system-call entry. Every way of opening a file or reaching a peer
//! passes through those functions (`open`, `openat2`, `io_uring`, `execve`
//! loading a binary...), and the kernel hands over the path it resolved,
//! so a relative path, a symlink or a racing rename cannot hide the target.
//!
//! The programs only observe. They never change a return value, and they
//! write nothing but their own maps.
//!
//! Which processes are reported is decided here, in the kernel: either all
//! of them, or the ones in `TRACKED` plus everything those start. Nothing
//! about an unwatched process leaves the kernel.
//!
//! Process ids are per pid namespace. The kernel helpers speak the root
//! namespace's ids ("host" below), while the watcher may run in a container
//! and know processes by different numbers. Records therefore carry ids as
//! the watcher sees them, and a process the watcher's namespace cannot see
//! is never reported. See `Watcher`.
#![no_std]
#![no_main]

use aya_ebpf::{
    Global,
    cty::{c_char, c_void},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, generated,
    },
    macros::{btf_tracepoint, fentry, map, socket_filter},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{BtfTracePointContext, FEntryContext, SkBuffContext},
};
use ceynox_watch_common::{
    ARGV_CAP, COMM_LEN, Config, Exec, Exit, Fork, Head, KIND_CONNECT, KIND_EXEC, KIND_EXIT, KIND_FORK, KIND_OPEN,
    KIND_SEND, LOST_FILE, LOST_NET, LOST_PROC, LOST_SLOTS, Offsets, Open, PATH_CAP, Sock, UNIX_PATH_CAP,
    WATCHER_HOST_PID, WATCHER_LEVEL, WATCHER_NS, WATCHER_READY, Watcher,
};

// ---- maps and load-time settings --------------------------------------------

/// Every record, in the order it happened. The loader sets the real size.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Host pids being watched (unused when `Config::all` is set). `on_fork`
/// adds children and `on_exit` removes the dead.
#[map]
static TRACKED: HashMap<u32, u8> = HashMap::with_max_entries(65536, 0);

/// Pids the loader asked to watch, in the watcher's own numbering. The
/// first time such a process is seen it moves to `TRACKED`.
#[map]
static SEED: HashMap<u32, u8> = HashMap::with_max_entries(65536, 0);

/// Entry 0: how many `SEED` entries the loader wrote. While it is zero the
/// seed lookup is skipped.
#[map]
static SEEDED: Array<u32> = Array::with_max_entries(1, 0);

/// Entry 0: the watcher's pid namespace, filled in by `learn_watcher`.
#[map]
static WATCHER: Array<Watcher> = Array::with_max_entries(1, 0);

/// Records dropped because the ring buffer was full, per `LOST_*` class.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(LOST_SLOTS, 0);

/// Staging for the two large records: the BPF stack is 512 bytes.
#[map]
static EXEC_BUF: PerCpuArray<Exec> = PerCpuArray::with_max_entries(1, 0);
#[map]
static OPEN_BUF: PerCpuArray<Open> = PerCpuArray::with_max_entries(1, 0);

/// When a process last had a datagram to a peer reported, so a stream of
/// packets to one destination is one record per window, not one per packet.
#[map]
static SENT: LruHashMap<Peer, u64> = LruHashMap::with_max_entries(16384, 0);

/// Written by the loader before the programs are loaded.
#[unsafe(no_mangle)]
static CONFIG: Global<Config> = Global::new(Config::zeroed());

#[repr(C)]
#[derive(Clone, Copy)]
struct Peer {
    pid: u32,
    port: u16,
    family: u16,
    addr: [u8; 16],
}

const SEND_WINDOW_NS: u64 = 5_000_000_000;

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: u16 = 1;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

// ---- small helpers -----------------------------------------------------------

#[inline(always)]
fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// The watcher's namespace, once known.
#[inline(always)]
fn watcher() -> Option<Watcher> {
    let w = *WATCHER.get(0)?;
    (w[WATCHER_READY] != 0).then_some(w)
}

#[inline(always)]
fn current_task() -> *const u8 {
    // SAFETY: the helper takes no arguments and cannot fail.
    (unsafe { generated::bpf_get_current_task() }) as *const u8
}

/// The process id of `task` as the watcher sees it, or `None` when the
/// process is outside the watcher's pid namespace.
///
/// A `struct pid` holds one id per namespace level it is visible in:
/// `numbers[0]` for the root namespace, `numbers[level]` for its own.
#[inline(always)]
fn pid_for_watcher(o: &Offsets, w: &Watcher, task: *const u8) -> Option<u32> {
    let leader = kptr(task, o.task_group_leader);
    let pid = kptr(leader, o.task_thread_pid);
    let level = kread::<u32>(pid, o.pid_level)? as u64;
    let want = w[WATCHER_LEVEL];
    // Namespaces nest at most 32 deep; the bound also keeps the index small.
    if want > level || want > 32 {
        return None;
    }
    let upid = pid.wrapping_add(o.pid_numbers as usize + want as usize * o.upid_size as usize);
    if kread::<u64>(upid, o.upid_ns)? != w[WATCHER_NS] {
        return None;
    }
    kread::<u32>(upid, o.upid_nr)
}

/// The current process's id for the records, if it is one we report.
#[inline(always)]
fn subject(cfg: &Config) -> Option<u32> {
    let w = watcher()?;
    let host = current_pid();
    if host as u64 == w[WATCHER_HOST_PID] {
        return None;
    }
    let task = current_task();
    // SAFETY: the value is a plain byte that is only tested for presence.
    if cfg.all != 0 || unsafe { TRACKED.get(&host) }.is_some() {
        return pid_for_watcher(&cfg.off, &w, task);
    }
    // Not watched yet. Was it asked for by the loader?
    if SEEDED.get(0).copied().unwrap_or(0) == 0 {
        return None;
    }
    let pid = pid_for_watcher(&cfg.off, &w, task)?;
    // SAFETY: as above.
    unsafe { SEED.get(&pid) }?;
    TRACKED.insert(&host, &1, 0).ok()?;
    let _ = SEED.remove(&pid);
    Some(pid)
}

/// Runs until the watcher has been identified: when the current process is
/// the watcher itself, record its namespace level, namespace and host pid.
///
/// The watcher is recognised with `bpf_get_ns_current_pid_tgid`, which
/// answers only for a task whose own namespace is the one named by
/// `Config::ns_dev` / `ns_ino`, with the id that task has there.
#[inline(always)]
fn learn_watcher(cfg: &Config) {
    let mut me = aya_ebpf::bindings::bpf_pidns_info { pid: 0, tgid: 0 };
    // SAFETY: `me` is a valid, correctly sized out-parameter.
    let rc = unsafe {
        generated::bpf_get_ns_current_pid_tgid(
            cfg.ns_dev as u64,
            cfg.ns_ino as u64,
            &mut me,
            core::mem::size_of::<aya_ebpf::bindings::bpf_pidns_info>() as u32,
        )
    };
    if rc != 0 || me.tgid != cfg.self_pid {
        return;
    }
    let o = &cfg.off;
    let pid = kptr(kptr(current_task(), o.task_group_leader), o.task_thread_pid);
    let Some(level) = kread::<u32>(pid, o.pid_level) else {
        return;
    };
    if level > 32 {
        return;
    }
    let upid = pid.wrapping_add(o.pid_numbers as usize + level as usize * o.upid_size as usize);
    let Some(ns) = kread::<u64>(upid, o.upid_ns) else {
        return;
    };
    if let Some(slot) = WATCHER.get_ptr_mut(0) {
        let mut w: Watcher = [0; 4];
        w[WATCHER_LEVEL] = level as u64;
        w[WATCHER_NS] = ns;
        w[WATCHER_HOST_PID] = current_pid() as u64;
        w[WATCHER_READY] = 1;
        // SAFETY: `slot` is the map's only value. A concurrent writer could
        // only be another thread of the watcher writing the same contents.
        unsafe { *slot = w };
    }
}

#[inline(always)]
fn head(kind: u32, pid: u32) -> Head {
    // SAFETY: the helper takes no arguments and cannot fail.
    Head { kind, pid, ts: unsafe { generated::bpf_ktime_get_ns() } }
}

#[inline(always)]
fn comm() -> [u8; COMM_LEN] {
    bpf_get_current_comm().unwrap_or([0; COMM_LEN])
}

#[inline(always)]
fn lost(class: u32) {
    if let Some(n) = LOST.get_ptr_mut(class) {
        // SAFETY: a per-CPU slot, only touched by the program on this CPU.
        unsafe { *n += 1 };
    }
}

/// Read a `T` from kernel memory at `base + off`. `None` on a null base or a
/// faulting read; the helper never touches memory it cannot read safely.
#[inline(always)]
fn kread<T>(base: *const u8, off: u32) -> Option<T> {
    if base.is_null() {
        return None;
    }
    // SAFETY: bpf_probe_read_kernel validates the address itself and returns
    // an error instead of faulting. `wrapping_add` only computes the address.
    unsafe { bpf_probe_read_kernel(base.wrapping_add(off as usize) as *const T).ok() }
}

#[inline(always)]
fn kptr(base: *const u8, off: u32) -> *const u8 {
    kread::<u64>(base, off).unwrap_or(0) as *const u8
}

// ---- processes ----------------------------------------------------------------

/// `sched_process_fork(struct task_struct *parent, struct task_struct *child)`.
/// Runs in the parent, once the child is fully set up.
#[btf_tracepoint(function = "sched_process_fork")]
pub fn on_fork(ctx: BtfTracePointContext) -> i32 {
    let cfg = CONFIG.load();
    let o = &cfg.off;
    let Some(ppid) = subject(&cfg) else {
        return 0;
    };
    let child: *const u8 = ctx.arg(1);
    let (Some(tid), Some(host)) = (kread::<u32>(child, o.task_pid), kread::<u32>(child, o.task_tgid)) else {
        return 0;
    };
    if tid != host {
        return 0; // a new thread, not a new process
    }
    if cfg.all == 0 && TRACKED.insert(&host, &1, 0).is_err() {
        // Table full: the child goes unwatched. Count it as lost activity.
        lost(LOST_PROC);
        return 0;
    }
    let Some(w) = watcher() else {
        return 0;
    };
    let Some(pid) = pid_for_watcher(o, &w, child) else {
        return 0;
    };
    match EVENTS.reserve::<Fork>(0) {
        Some(mut slot) => {
            slot.write(Fork { head: head(KIND_FORK, pid), ppid, _pad: 0 });
            slot.submit(0);
        }
        None => lost(LOST_PROC),
    }
    0
}

/// `sched_process_exec(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)`.
/// Runs after a successful exec, in the new image.
#[btf_tracepoint(function = "sched_process_exec")]
pub fn on_exec(ctx: BtfTracePointContext) -> i32 {
    let cfg = CONFIG.load();
    let o = &cfg.off;
    let Some(pid) = subject(&cfg) else {
        return 0;
    };
    let task: *const u8 = ctx.arg(0);
    let bprm: *const u8 = ctx.arg(2);
    let Some(buf) = EXEC_BUF.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: `buf` points at this CPU's staging value, a whole `Exec`, which
    // no other program instance can touch while this one runs.
    let ev = unsafe { &mut *buf };

    ev.head = head(KIND_EXEC, pid);
    // 0 when the parent is outside the watcher's namespace.
    ev.ppid = watcher().and_then(|w| pid_for_watcher(o, &w, kptr(task, o.task_real_parent))).unwrap_or(0);
    ev.uid = bpf_get_current_uid_gid() as u32;
    ev._pad = 0;
    ev.comm = comm();

    ev.filename[0] = 0;
    let name = kptr(bprm, o.bprm_filename);
    if !name.is_null() {
        // SAFETY: the helper bounds the copy to the destination and fails
        // cleanly on an unreadable source.
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(name, &mut ev.filename) };
    }

    // argv is the bytes between mm->arg_start and mm->arg_end, in the new
    // image's own memory.
    ev.argv_len = 0;
    let mm = kptr(task, o.task_mm);
    let start = kread::<u64>(mm, o.mm_arg_start).unwrap_or(0);
    let end = kread::<u64>(mm, o.mm_arg_end).unwrap_or(0);
    if start != 0 && end > start {
        let mut n = end - start;
        if n > ARGV_CAP as u64 {
            n = ARGV_CAP as u64;
        }
        // SAFETY: `n` is at most ARGV_CAP, the size of the destination; the
        // helper fails cleanly if the user memory is not readable.
        let rc = unsafe {
            generated::bpf_probe_read_user(ev.argv.as_mut_ptr() as *mut c_void, n as u32, start as *const c_void)
        };
        if rc == 0 {
            ev.argv_len = n as u32;
        }
    }

    let mut len = ev.argv_len as usize;
    if len > ARGV_CAP {
        len = ARGV_CAP;
    }
    // SAFETY: `Exec::HEAD_LEN + len` is within the staging value.
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, Exec::HEAD_LEN + len) };
    if EVENTS.output(bytes, 0).is_err() {
        lost(LOST_PROC);
    }
    0
}

/// `sched_process_exit(struct task_struct *p, ...)`. Runs in the exiting
/// task, once per thread; the thread-group leader's exit stands for the
/// process.
#[btf_tracepoint(function = "sched_process_exit")]
pub fn on_exit(_ctx: BtfTracePointContext) -> i32 {
    let cfg = CONFIG.load();
    let ids = bpf_get_current_pid_tgid();
    let host = (ids >> 32) as u32;
    if ids as u32 != host {
        return 0;
    }
    let Some(pid) = subject(&cfg) else {
        return 0;
    };
    if cfg.all == 0 {
        let _ = TRACKED.remove(&host);
    }
    let code = kread::<u32>(current_task(), cfg.off.task_exit_code).unwrap_or(0);
    match EVENTS.reserve::<Exit>(0) {
        Some(mut slot) => {
            slot.write(Exit { head: head(KIND_EXIT, pid), code, _pad: 0 });
            slot.submit(0);
        }
        None => lost(LOST_PROC),
    }
    0
}

// ---- files --------------------------------------------------------------------

/// `int security_file_open(struct file *file)`: every open of every kind.
#[fentry(function = "security_file_open")]
pub fn on_open(ctx: FEntryContext) -> i32 {
    let cfg = CONFIG.load();
    let o = &cfg.off;
    if watcher().is_none() {
        learn_watcher(&cfg);
        return 0;
    }
    let Some(pid) = subject(&cfg) else {
        return 0;
    };
    let file: *const u8 = ctx.arg(0);

    // Regular files and directories only: pipes, sockets and device nodes
    // (terminals, /dev/null) are not file access in the sense we report.
    let mode = kread::<u16>(kptr(file, o.file_f_inode), o.inode_i_mode).unwrap_or(0) as u32;
    if mode & S_IFMT != S_IFREG && mode & S_IFMT != S_IFDIR {
        return 0;
    }

    let Some(buf) = OPEN_BUF.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: this CPU's staging value, a whole `Open`; see `on_exec`.
    let ev = unsafe { &mut *buf };

    // `&file->f_path`, resolved by the kernel to an absolute path.
    let path = file.wrapping_add(o.file_f_path as usize) as *const aya_ebpf::bindings::path;
    // SAFETY: `path` is the kernel-typed `struct path` inside the `struct
    // file` argument; the helper writes at most PATH_CAP bytes into `ev.path`.
    let n = unsafe { generated::bpf_d_path(path, ev.path.as_mut_ptr() as *mut c_char, PATH_CAP as u32) };
    if n <= 0 || n > PATH_CAP as i64 {
        return 0;
    }
    let len = n as usize;

    ev.head = head(KIND_OPEN, pid);
    ev.flags = kread::<u32>(file, o.file_f_flags).unwrap_or(0);
    ev.mode = mode;
    ev.path_len = len as u32;
    ev._pad = 0;
    ev.comm = comm();

    // SAFETY: `len` is in 1..=PATH_CAP, so the slice stays inside the value.
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, Open::HEAD_LEN + len) };
    if EVENTS.output(bytes, 0).is_err() {
        lost(LOST_FILE);
    }
    0
}

// ---- network ------------------------------------------------------------------

/// Destination of a socket call, as much as its address family tells us.
struct Dest {
    family: u16,
    port: u16,
    addr: [u8; 16],
}

/// Decode a kernel `sockaddr_in` / `sockaddr_in6`.
#[inline(always)]
fn inet_dest(sa: *const u8, family: u16) -> Option<Dest> {
    // sockaddr_in:  family @0, be16 port @2, addr[4]  @4
    // sockaddr_in6: family @0, be16 port @2, flowinfo @4, addr[16] @8
    let port = u16::from_be(kread::<u16>(sa, 2)?);
    let mut addr = [0u8; 16];
    if family == AF_INET {
        let a = kread::<[u8; 4]>(sa, 4)?;
        addr[0] = a[0];
        addr[1] = a[1];
        addr[2] = a[2];
        addr[3] = a[3];
    } else if family == AF_INET6 {
        addr = kread::<[u8; 16]>(sa, 8)?;
    } else {
        return None;
    }
    Some(Dest { family, port, addr })
}

#[inline(always)]
fn emit_sock(kind: u32, pid: u32, sock_type: u16, d: &Dest, unix: Option<(*const u8, u16)>) {
    let Some(mut slot) = EVENTS.reserve::<Sock>(0) else {
        lost(LOST_NET);
        return;
    };
    let ev = slot.as_mut_ptr();
    // SAFETY: `ev` is the reserved, correctly sized and aligned record. Every
    // field is written before it is submitted.
    unsafe {
        (*ev).head = head(kind, pid);
        (*ev).family = d.family;
        (*ev).port = d.port;
        (*ev).sock_type = sock_type;
        (*ev).unix_len = 0;
        (*ev).addr = d.addr;
        (*ev).comm = comm();
        (*ev).unix_path = [0; UNIX_PATH_CAP];
        (*ev)._pad2 = [0; 4];
        if let Some((src, len)) = unix {
            // The kernel copied the address into a `sockaddr_storage`, so a
            // full-size read stays inside it; `unix_len` says what counts.
            if generated::bpf_probe_read_kernel(
                (*ev).unix_path.as_mut_ptr() as *mut c_void,
                UNIX_PATH_CAP as u32,
                src as *const c_void,
            ) == 0
            {
                (*ev).unix_len = len;
            }
        }
    }
    slot.submit(0);
}

/// `int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)`.
///
/// Stream connections and every UNIX-socket connect are reported here.
/// Internet datagram sockets are reported by `on_send` instead: `connect` on
/// one sends nothing (resolvers use it just to pick a source address).
#[fentry(function = "security_socket_connect")]
pub fn on_connect(ctx: FEntryContext) -> i32 {
    let cfg = CONFIG.load();
    let o = &cfg.off;
    let Some(pid) = subject(&cfg) else {
        return 0;
    };
    let sock: *const u8 = ctx.arg(0);
    let sa: *const u8 = ctx.arg(1);
    let addrlen: i32 = ctx.arg(2);
    let Some(family) = kread::<u16>(sa, 0) else {
        return 0;
    };
    let sock_type = kread::<u16>(sock, o.socket_type).unwrap_or(0);

    if family == AF_UNIX {
        if addrlen <= 2 {
            return 0;
        }
        let mut len = (addrlen - 2) as u32;
        if len > UNIX_PATH_CAP as u32 {
            len = UNIX_PATH_CAP as u32;
        }
        let d = Dest { family, port: 0, addr: [0; 16] };
        emit_sock(KIND_CONNECT, pid, sock_type, &d, Some((sa.wrapping_add(2), len as u16)));
    } else if sock_type == SOCK_STREAM
        && let Some(d) = inet_dest(sa, family)
    {
        emit_sock(KIND_CONNECT, pid, sock_type, &d, None);
    }
    0
}

/// `int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)`.
///
/// Internet datagrams (UDP, raw). The peer is the address given to the call,
/// or the socket's connected peer when none was given.
#[fentry(function = "security_socket_sendmsg")]
pub fn on_send(ctx: FEntryContext) -> i32 {
    let cfg = CONFIG.load();
    let o = &cfg.off;
    let Some(pid) = subject(&cfg) else {
        return 0;
    };
    let sock: *const u8 = ctx.arg(0);
    let msg: *const u8 = ctx.arg(1);
    let sock_type = kread::<u16>(sock, o.socket_type).unwrap_or(0);
    if sock_type == SOCK_STREAM {
        return 0;
    }
    let sk = kptr(sock, o.socket_sk);
    let Some(family) = kread::<u16>(sk, o.sk_family) else {
        return 0;
    };
    if family != AF_INET && family != AF_INET6 {
        return 0;
    }

    let name = kptr(msg, o.msghdr_name);
    let dest = if !name.is_null() {
        // An AF_INET6 socket may be given an AF_INET address and vice versa:
        // trust the address's own family.
        kread::<u16>(name, 0).and_then(|f| inet_dest(name, f))
    } else {
        let port = u16::from_be(kread::<u16>(sk, o.sk_dport).unwrap_or(0));
        let mut addr = [0u8; 16];
        if family == AF_INET {
            let a = kread::<[u8; 4]>(sk, o.sk_daddr).unwrap_or([0; 4]);
            addr[0] = a[0];
            addr[1] = a[1];
            addr[2] = a[2];
            addr[3] = a[3];
        } else {
            addr = kread::<[u8; 16]>(sk, o.sk_v6_daddr).unwrap_or([0; 16]);
        }
        Some(Dest { family, port, addr })
    };
    let Some(d) = dest else {
        return 0;
    };

    let key = Peer { pid, port: d.port, family: d.family, addr: d.addr };
    // SAFETY: the helper takes no arguments and cannot fail.
    let now = unsafe { generated::bpf_ktime_get_ns() };
    // SAFETY: the value is a plain u64 copied out immediately.
    if let Some(last) = unsafe { SENT.get(&key) }
        && now.wrapping_sub(*last) < SEND_WINDOW_NS
    {
        return 0;
    }
    let _ = SENT.insert(&key, &now, 0);
    emit_sock(KIND_SEND, pid, sock_type, &d, None);
    0
}

// ---- names ---------------------------------------------------------------------

/// Keep a packet for the loader's packet socket only if it is UDP sent from
/// port 53. The socket is of the `SOCK_DGRAM` kind, so the data starts at
/// the IP header.
#[socket_filter]
pub fn dns_replies(ctx: SkBuffContext) -> i64 {
    if from_port_53(&ctx).unwrap_or(false) { -1 } else { 0 }
}

#[inline(always)]
fn from_port_53(ctx: &SkBuffContext) -> Option<bool> {
    const UDP: u8 = 17;
    let first: u8 = ctx.load(0).ok()?;
    let udp_at = match first >> 4 {
        4 => {
            if ctx.load::<u8>(9).ok()? != UDP {
                return Some(false);
            }
            ((first & 0x0f) as usize) * 4
        }
        6 => {
            if ctx.load::<u8>(6).ok()? != UDP {
                return Some(false);
            }
            40
        }
        _ => return Some(false),
    };
    Some(u16::from_be(ctx.load::<u16>(udp_at).ok()?) == 53)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The helpers used above are GPL-only, so the object must declare a
/// GPL-compatible license to load.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
