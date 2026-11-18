//! The Linux sensor: loads the kernel programs, reads their records from the
//! ring buffer and turns them into [`Event`]s.

use std::{
    collections::{HashMap, HashSet},
    fs,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf},
    programs::{BtfTracePoint, FEntry, SocketFilter},
};
use ceynox_watch_common as wire;
use rustix::{
    event::{PollFd, PollFlags, poll},
    fd::{BorrowedFd, OwnedFd},
    net::{AddressFamily, RecvFlags, SocketType, eth, recv, socket},
    time::{ClockId, Timespec, clock_gettime},
};

use super::{Options, Scope, SensorError, btf::Btf, dns, procfs};
use crate::event::{Event, Peer, Proto, What};

/// The kernel programs, compiled by `build.rs`.
static PROGRAMS: &[u8] = aya::include_bytes_aligned!(env!("CEYNOX_WATCH_BPF_OBJECT"));

const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

const TRACEPOINTS: [(&str, &str); 3] =
    [("on_fork", "sched_process_fork"), ("on_exec", "sched_process_exec"), ("on_exit", "sched_process_exit")];
const FUNCTIONS: [(&str, &str); 3] = [
    ("on_open", "security_file_open"),
    ("on_connect", "security_socket_connect"),
    ("on_send", "security_socket_sendmsg"),
];

// open(2) flags; the same values on every architecture Linux BPF targets.
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// Addresses remembered with the name they were looked up by.
const MAX_NAMES: usize = 8192;

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: u16 = 1;
const SOCK_DGRAM: u16 = 2;

pub struct Sensor {
    /// Owns the loaded programs and their attachments; dropping it detaches.
    _ebpf: Ebpf,
    ring: RingBuf<MapData>,
    lost: PerCpuArray<MapData, u64>,
    lost_seen: u64,
    /// Add to a kernel timestamp (monotonic ns) to get Unix-epoch ns.
    epoch_offset_ns: i128,
    /// Processes already described to the consumer.
    known: HashSet<u32>,
    describe_unknown: bool,
    /// Events produced while starting (the processes already running).
    backlog: Vec<Event>,
    /// Each process's most recent open, to drop the echo described in
    /// [`Sensor::is_echo`].
    last_open: HashMap<u32, (u64, bool, String)>,
    /// A packet socket that receives DNS replies only. `None` when it could
    /// not be set up; addresses are then shown without names.
    dns_socket: Option<OwnedFd>,
    names: HashMap<IpAddr, String>,
}

impl std::fmt::Debug for Sensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sensor").field("known", &self.known.len()).finish_non_exhaustive()
    }
}

fn fail(what: &str, err: impl std::fmt::Display) -> SensorError {
    SensorError::new(format!("{what}: {err}"))
}

impl Sensor {
    /// Load and attach the kernel programs. Needs root (or CAP_BPF and
    /// CAP_PERFMON). When this returns, the scope is being watched.
    pub fn start(opts: &Options) -> Result<Self, SensorError> {
        if !rustix::process::geteuid().is_root() {
            return Err(SensorError::new("loading the kernel programs needs root"));
        }
        let raw_btf = fs::read(KERNEL_BTF).map_err(|e| {
            SensorError::new(format!(
                "cannot read {KERNEL_BTF} ({e}). ceynox-watch needs a kernel built with \
                 type information (CONFIG_DEBUG_INFO_BTF), which every mainstream \
                 distribution has shipped since about 2021"
            ))
        })?;
        let offsets = resolve_offsets(&raw_btf)?;

        // Process ids in the records are expressed in this namespace: ours.
        let ns = rustix::fs::stat("/proc/self/ns/pid").map_err(|e| fail("/proc/self/ns/pid", e))?;
        let narrow = |v: u64| u32::try_from(v).map_err(|_| SensorError::new("unexpected pid namespace id"));
        let config = wire::Config {
            all: u32::from(opts.scope == Scope::All),
            self_pid: std::process::id(),
            ns_dev: narrow(ns.st_dev)?,
            ns_ino: narrow(ns.st_ino)?,
            off: offsets,
        };
        let words = config.to_words();
        let buffer = opts.buffer_bytes.max(64 * 1024).next_power_of_two();

        let mut ebpf = EbpfLoader::new()
            .override_global("CONFIG", &words[..], true)
            .map_max_entries("EVENTS", buffer)
            .load(PROGRAMS)
            .map_err(|e| fail("the kernel refused the programs", e))?;

        let kernel_btf = aya::Btf::from_sys_fs().map_err(|e| fail("reading kernel type information", e))?;
        for (prog, tracepoint) in TRACEPOINTS {
            let p: &mut BtfTracePoint = program(&mut ebpf, prog)?;
            p.load(tracepoint, &kernel_btf).map_err(|e| attach_error(tracepoint, e))?;
            p.attach().map_err(|e| attach_error(tracepoint, e))?;
        }
        for (prog, function) in FUNCTIONS {
            let p: &mut FEntry = program(&mut ebpf, prog)?;
            p.load(function, &kernel_btf).map_err(|e| attach_error(function, e))?;
            p.attach().map_err(|e| attach_error(function, e))?;
        }

        // Nothing is reported until the kernel side has seen us open a file
        // and learned which pid namespace we are in. Do that now.
        let _ = fs::read("/proc/self/stat");
        let watcher: Array<_, wire::Watcher> =
            Array::try_from(map(&ebpf, "WATCHER")?).map_err(|e| fail("opening the watcher record", e))?;
        let ready = watcher.get(&0, 0).is_ok_and(|w| w[wire::WATCHER_READY] != 0);
        if !ready {
            return Err(SensorError::new("the kernel programs could not identify this process's pid namespace"));
        }

        // Ask for the processes in scope. Each is picked up the first time
        // it does anything at all, so nothing it does can be missed.
        let mut known = HashSet::new();
        let mut backlog = Vec::new();
        if let Scope::Pids(roots) = &opts.scope {
            let mut seed: BpfHashMap<_, u32, u8> =
                BpfHashMap::try_from(map_mut(&mut ebpf, "SEED")?).map_err(|e| fail("opening the watch list", e))?;
            let now = unix_ms();
            let mut count = 0u32;
            for pid in procfs::with_descendants(roots) {
                if !procfs::alive(pid) {
                    if roots.contains(&pid) {
                        return Err(SensorError::new(format!("no process with pid {pid}")));
                    }
                    continue;
                }
                seed.insert(&pid, &1, 0).map_err(|e| fail("adding to the watch list", e))?;
                count += 1;
                if let Some(what) = procfs::describe(pid) {
                    known.insert(pid);
                    backlog.push(Event { ts: now, pid, what });
                }
            }
            let mut seeded: Array<_, u32> =
                Array::try_from(map_mut(&mut ebpf, "SEEDED")?).map_err(|e| fail("opening the watch list", e))?;
            seeded.set(0, &count, 0).map_err(|e| fail("arming the watch list", e))?;
        }

        let dns_socket = dns_socket(&mut ebpf);
        let ring = RingBuf::try_from(take(&mut ebpf, "EVENTS")?).map_err(|e| fail("opening the event buffer", e))?;
        let lost = PerCpuArray::try_from(take(&mut ebpf, "LOST")?).map_err(|e| fail("opening the loss counters", e))?;

        let real = clock_gettime(ClockId::Realtime);
        let mono = clock_gettime(ClockId::Monotonic);
        Ok(Self {
            _ebpf: ebpf,
            ring,
            lost,
            lost_seen: 0,
            epoch_offset_ns: nanos(&real) - nanos(&mono),
            known,
            describe_unknown: opts.scope == Scope::All,
            backlog,
            last_open: HashMap::new(),
            dns_socket,
            names: HashMap::new(),
        })
    }

    /// Wait up to `timeout_ms` for events and pass every one available to
    /// `sink`, oldest first. The wait also ends when `wake` hangs up or
    /// reports an error.
    pub fn poll(
        &mut self,
        timeout_ms: u32,
        wake: Option<BorrowedFd<'_>>,
        sink: &mut dyn FnMut(Event),
    ) -> Result<(), SensorError> {
        for ev in self.backlog.drain(..) {
            sink(ev);
        }
        let timeout =
            Timespec { tv_sec: i64::from(timeout_ms / 1000), tv_nsec: i64::from(timeout_ms % 1000) * 1_000_000 };
        let mut fds = vec![PollFd::new(&self.ring, PollFlags::IN)];
        if let Some(dns) = &self.dns_socket {
            fds.push(PollFd::new(dns, PollFlags::IN));
        }
        if let Some(wake) = &wake {
            fds.push(PollFd::new(wake, PollFlags::empty()));
        }
        let res = poll(&mut fds, Some(&timeout));
        drop(fds);
        match res {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(fail("waiting for events", e)),
        }
        self.drain(sink);
        Ok(())
    }

    /// Pass on everything currently in the buffer without waiting.
    pub fn drain(&mut self, sink: &mut dyn FnMut(Event)) {
        // Names first: a reply is on the wire before the program that asked
        // can connect to the address in it.
        self.read_names();
        loop {
            // Decode inside the match so the buffer slot is released before
            // anything else borrows `self`.
            let decoded = match self.ring.next() {
                Some(item) => decode(&item),
                None => break,
            };
            let Some((pid, mono_ns, mut what)) = decoded else {
                continue;
            };
            if let What::Connect { peer: Peer::Ip { ip, .. }, name } = &mut what {
                *name = self.names.get(ip).cloned();
            }
            if self.is_echo(pid, mono_ns, &what) {
                continue;
            }
            let ts = self.to_unix_ms(mono_ns);
            match &what {
                What::Fork { .. } | What::Exec { .. } => {
                    self.known.insert(pid);
                }
                What::Exit { .. } => {
                    self.known.remove(&pid);
                    self.last_open.remove(&pid);
                }
                _ => {
                    // First sight of a process that predates us: say what it is.
                    if self.describe_unknown
                        && self.known.insert(pid)
                        && let Some(what) = procfs::describe(pid)
                    {
                        sink(Event { ts, pid, what });
                    }
                }
            }
            sink(Event { ts, pid, what });
        }
        let total = self.lost_total();
        if total > self.lost_seen {
            sink(Event { ts: unix_ms(), pid: 0, what: What::Lost { count: total - self.lost_seen } });
            self.lost_seen = total;
        }
    }

    /// Take in every DNS reply waiting on the packet socket.
    fn read_names(&mut self) {
        let Some(sock) = &self.dns_socket else {
            return;
        };
        let mut packet = [0u8; 2048];
        // Bounded so a flood of replies cannot starve the event buffer.
        for _ in 0..256 {
            let Ok((len, _)) = recv(sock, &mut packet[..], RecvFlags::DONTWAIT) else {
                break;
            };
            let Some(reply) = dns::dns_payload(&packet[..len.min(packet.len())]).and_then(dns::parse_reply) else {
                continue;
            };
            if self.names.len() + reply.addrs.len() > MAX_NAMES {
                self.names.clear();
            }
            for addr in reply.addrs {
                self.names.insert(addr, reply.name.clone());
            }
        }
    }

    /// Is this open the kernel repeating the previous one?
    ///
    /// On a stacked filesystem (overlayfs, which is what containers use) one
    /// `open` makes the kernel open the file a second time in the layer that
    /// really holds it, and the security hook runs for both. The second
    /// arrives from the same process, for the same path, within microseconds.
    fn is_echo(&mut self, pid: u32, mono_ns: u64, what: &What) -> bool {
        const WINDOW_NS: u64 = 1_000_000;
        let What::Open { path, write, .. } = what else {
            return false;
        };
        if let Some((at, w, p)) = self.last_open.get_mut(&pid) {
            if *w == *write && p == path && mono_ns.saturating_sub(*at) < WINDOW_NS {
                *at = mono_ns;
                return true;
            }
            *at = mono_ns;
            *w = *write;
            p.clone_from(path);
        } else {
            self.last_open.insert(pid, (mono_ns, *write, path.clone()));
        }
        false
    }

    fn lost_total(&self) -> u64 {
        (0..wire::LOST_SLOTS)
            .filter_map(|slot| self.lost.get(&slot, 0).ok())
            .map(|per_cpu| per_cpu.iter().sum::<u64>())
            .sum()
    }

    fn to_unix_ms(&self, mono_ns: u64) -> u64 {
        u64::try_from((i128::from(mono_ns) + self.epoch_offset_ns) / 1_000_000).unwrap_or(0)
    }
}

/// Open a packet socket that the `dns_replies` filter narrows to DNS
/// replies. Best effort: without it, everything else still works.
fn dns_socket(ebpf: &mut Ebpf) -> Option<OwnedFd> {
    let filter: &mut SocketFilter = program(ebpf, "dns_replies").ok()?;
    filter.load().ok()?;
    let sock = socket(AddressFamily::PACKET, SocketType::DGRAM, Some(eth::ALL)).ok()?;
    filter.attach(&sock).ok()?;
    // The socket saw every packet between being created and being filtered.
    let mut scratch = [0u8; 2048];
    while recv(&sock, &mut scratch[..], RecvFlags::DONTWAIT).is_ok() {}
    Some(sock)
}

fn nanos(t: &Timespec) -> i128 {
    i128::from(t.tv_sec) * 1_000_000_000 + i128::from(t.tv_nsec)
}

fn unix_ms() -> u64 {
    u64::try_from(nanos(&clock_gettime(ClockId::Realtime)) / 1_000_000).unwrap_or(0)
}

fn program<'a, T>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut T, SensorError>
where
    &'a mut T: TryFrom<&'a mut aya::programs::Program>,
{
    ebpf.program_mut(name)
        .ok_or_else(|| SensorError::new(format!("program {name} missing from the object")))?
        .try_into()
        .map_err(|_| SensorError::new(format!("program {name} has an unexpected type")))
}

fn map<'a>(ebpf: &'a Ebpf, name: &str) -> Result<&'a aya::maps::Map, SensorError> {
    ebpf.map(name).ok_or_else(|| SensorError::new(format!("map {name} missing from the object")))
}

fn map_mut<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut aya::maps::Map, SensorError> {
    ebpf.map_mut(name).ok_or_else(|| SensorError::new(format!("map {name} missing from the object")))
}

fn take(ebpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map, SensorError> {
    ebpf.take_map(name).ok_or_else(|| SensorError::new(format!("map {name} missing from the object")))
}

fn attach_error(hook: &str, err: impl std::fmt::Display) -> SensorError {
    SensorError::new(format!(
        "could not attach to {hook}: {err}. ceynox-watch needs Linux 5.11 or newer on \
         x86-64 and 6.0 or newer on arm64"
    ))
}

fn resolve_offsets(raw: &[u8]) -> Result<wire::Offsets, SensorError> {
    let btf = Btf::parse(raw).map_err(|e| fail(KERNEL_BTF, e))?;
    let at = |strukt: &str, field: &str| btf.field_offset(strukt, field).map_err(|e| fail(KERNEL_BTF, e));
    // `struct sock` starts with its `struct sock_common`, in which the
    // address fields live.
    let common = at("sock", "__sk_common")?;
    Ok(wire::Offsets {
        task_pid: at("task_struct", "pid")?,
        task_tgid: at("task_struct", "tgid")?,
        task_real_parent: at("task_struct", "real_parent")?,
        task_group_leader: at("task_struct", "group_leader")?,
        task_thread_pid: at("task_struct", "thread_pid")?,
        pid_level: at("pid", "level")?,
        pid_numbers: at("pid", "numbers")?,
        upid_nr: at("upid", "nr")?,
        upid_ns: at("upid", "ns")?,
        upid_size: btf.struct_size("upid").map_err(|e| fail(KERNEL_BTF, e))?,
        task_exit_code: at("task_struct", "exit_code")?,
        task_mm: at("task_struct", "mm")?,
        mm_arg_start: at("mm_struct", "arg_start")?,
        mm_arg_end: at("mm_struct", "arg_end")?,
        bprm_filename: at("linux_binprm", "filename")?,
        file_f_path: at("file", "f_path")?,
        file_f_flags: at("file", "f_flags")?,
        file_f_inode: at("file", "f_inode")?,
        inode_i_mode: at("inode", "i_mode")?,
        socket_sk: at("socket", "sk")?,
        socket_type: at("socket", "type")?,
        sk_family: common + at("sock_common", "skc_family")?,
        sk_daddr: common + at("sock_common", "skc_daddr")?,
        sk_dport: common + at("sock_common", "skc_dport")?,
        sk_v6_daddr: common + at("sock_common", "skc_v6_daddr")?,
        msghdr_name: at("msghdr", "msg_name")?,
    })
}

// ---- record decoding ----------------------------------------------------------
//
// Records are read field by field at their declared offsets with bounds
// checks, so a short or unexpected record is skipped, never misread.

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Bytes up to the first NUL (or all of them), as text.
fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// One ring-buffer record as `(pid, monotonic ns, event)`.
fn decode(b: &[u8]) -> Option<(u32, u64, What)> {
    let kind = u32_at(b, offset_of!(wire::Head, kind))?;
    let pid = u32_at(b, offset_of!(wire::Head, pid))?;
    let ts = u64_at(b, offset_of!(wire::Head, ts))?;
    let what = match kind {
        wire::KIND_FORK => What::Fork { ppid: u32_at(b, offset_of!(wire::Fork, ppid))? },
        wire::KIND_EXIT => {
            let status = u32_at(b, offset_of!(wire::Exit, code))?;
            let signal = (status & 0x7f) as i32;
            if signal != 0 {
                What::Exit { code: None, signal: Some(signal) }
            } else {
                What::Exit { code: Some(((status >> 8) & 0xff) as i32), signal: None }
            }
        }
        wire::KIND_EXEC => decode_exec(b, pid)?,
        wire::KIND_OPEN => decode_open(b)?,
        wire::KIND_CONNECT | wire::KIND_SEND => decode_sock(b)?,
        _ => return None,
    };
    Some((pid, ts, what))
}

fn decode_exec(b: &[u8], pid: u32) -> Option<What> {
    let argv_len = u32_at(b, offset_of!(wire::Exec, argv_len))? as usize;
    let argv = b.get(wire::Exec::HEAD_LEN..wire::Exec::HEAD_LEN.checked_add(argv_len)?)?;
    let name_at = offset_of!(wire::Exec, filename);
    let filename = c_str(b.get(name_at..name_at + wire::EXEC_NAME_CAP)?);
    Some(What::Exec {
        ppid: u32_at(b, offset_of!(wire::Exec, ppid))?,
        uid: u32_at(b, offset_of!(wire::Exec, uid))?,
        // /proc gives the resolved path; the kernel record has what was
        // passed to execve, which is all there is once the process is gone.
        exe: procfs::exe(pid).unwrap_or(filename),
        argv: procfs::split_args(argv),
        cwd: procfs::cwd(pid),
        existing: false,
    })
}

fn decode_open(b: &[u8]) -> Option<What> {
    let flags = u32_at(b, offset_of!(wire::Open, flags))?;
    let mode = u32_at(b, offset_of!(wire::Open, mode))?;
    let len = u32_at(b, offset_of!(wire::Open, path_len))? as usize;
    let path = b.get(wire::Open::HEAD_LEN..wire::Open::HEAD_LEN.checked_add(len)?)?;
    let path = c_str(path);
    // A file with no name left (unlinked, or a filesystem's internal
    // temporary) is not something a reader can act on. In-memory files
    // reopened by name are kept: running one is a known trick.
    if path.ends_with(" (deleted)") && !path.starts_with("/memfd:") {
        return None;
    }
    Some(What::Open {
        path,
        write: flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND) != 0,
        dir: mode & S_IFMT == S_IFDIR,
    })
}

fn decode_sock(b: &[u8]) -> Option<What> {
    if b.len() < size_of::<wire::Sock>() {
        return None;
    }
    let family = u16_at(b, offset_of!(wire::Sock, family))?;
    let port = u16_at(b, offset_of!(wire::Sock, port))?;
    let sock_type = u16_at(b, offset_of!(wire::Sock, sock_type))?;
    let addr_at = offset_of!(wire::Sock, addr);
    let addr: [u8; 16] = b.get(addr_at..addr_at + 16)?.try_into().ok()?;
    let proto = match sock_type {
        SOCK_STREAM => Proto::Tcp,
        SOCK_DGRAM => Proto::Udp,
        _ => Proto::Other,
    };
    let peer = match family {
        AF_INET => Peer::Ip { ip: IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])), port, proto },
        AF_INET6 => {
            let v6 = Ipv6Addr::from(addr);
            // An IPv4 peer reached through an IPv6 socket.
            let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
            Peer::Ip { ip, port, proto }
        }
        AF_UNIX => {
            let len = usize::from(u16_at(b, offset_of!(wire::Sock, unix_len))?).min(wire::UNIX_PATH_CAP);
            let path_at = offset_of!(wire::Sock, unix_path);
            let raw = b.get(path_at..path_at + len)?;
            let path = match raw.split_first() {
                // Abstract namespace: a leading NUL, then an arbitrary name.
                Some((0, name)) => format!("@{}", String::from_utf8_lossy(name).trim_end_matches('\0')),
                _ => c_str(raw),
            };
            if path.is_empty() || path == "@" {
                return None;
            }
            Peer::Unix { path }
        }
        _ => return None,
    };
    Some(What::Connect { peer, name: None })
}
