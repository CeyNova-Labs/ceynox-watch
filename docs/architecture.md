# How ceynox-watch works

Short version: a sensor turns what processes do into events, and everything else (the live lines, the summary, baselines, reports) is computed from that one stream. Linux and macOS have different sensors and share the rest.

## The pieces

| Piece | Runs as | Does |
|---|---|---|
| `ceynox-watch` | you | parses options, starts the others, prints |
| the helper (`__sensor`) | root, then you | Linux only. Loads the kernel programs, then drops root and forwards events |
| the stand-in (`__exec`) | you | waits until the sensor is ready, then becomes your command |
| the kernel programs | in the kernel | Linux only. Record events into a ring buffer |

All three processes are the same binary in different modes. Your command never runs as root and never holds a file descriptor of the helper.

## Linux

Eight eBPF programs, written in Rust with [aya](https://aya-rs.dev):

| Event | Hook | Kind |
|---|---|---|
| process forked, program started, process exited | `sched_process_fork`, `sched_process_exec`, `sched_process_exit` | BTF tracepoint |
| file opened | `security_file_open` | fentry |
| connection made, datagram sent | `security_socket_connect`, `security_socket_sendmsg` | fentry |
| connection closed, with byte counts | `tcp_close` | fentry |
| DNS reply seen | a packet socket the helper opens | socket filter |

**Why the security hooks.** Files and sockets are hooked where the kernel checks access, not at system-call entry. Every route to opening a file passes there (`open`, `openat2`, `io_uring`, `execve`), and the kernel supplies the path it resolved.

**Which processes.** The filter is in the kernel: the watched process and everything it starts. Nothing about any other process leaves the kernel. Process ids are translated into the pid namespace ceynox-watch runs in, so it works inside a container.

**Host names.** The socket filter passes DNS replies to the helper, which remembers which name each address was looked up by.

**The programs only observe.** Tracepoint and fentry programs cannot change what the kernel does. The socket filter decides only what the helper's own socket receives.

## macOS

There is no eBPF. The command runs under the system's `sandbox-exec` with a profile that allows everything and asks for a report of program starts, forks, catalog reads, writes and connections. The kernel writes those reports to the system log, and ceynox-watch reads them with `log stream`, picking out its own by a tag unique to the run.

The reports do not say which process started which, so the tree is rebuilt from the order of reports and the process table. With `--hosts`, the system's `tcpdump` is run through `sudo` to add addresses and names; no code of ours runs as root.

## Privileges

1. `ceynox-watch` starts the stand-in, which blocks on a lock.
2. It starts the helper through `sudo`. The helper loads the kernel programs and tells them which process to watch.
3. The helper becomes you again, keeps one capability (`CAP_BPF`, to read loss counters) and sets `no_new_privs`. The end-to-end tests check this.
4. The lock is released and the stand-in becomes your command.

`--all` is the exception: describing other users' processes needs root, so the helper keeps it.

## From events to output

- `report.rs` builds the process tree and attributes each process to a package, from where it runs (`node_modules/<name>`, a pip build directory, a Cargo build script) or how it was started (`npx <name>`).
- `classify.rs` holds the catalog: one table of path patterns, one of host names.
- `baseline.rs` reduces a run to four sets (programs, hosts, catalog findings, areas written) and compares two of them.
- `render.rs` and `export.rs` print it: terminal, Markdown, HTML.

## Choices that look odd, and why

| Choice | Why |
|---|---|
| Kernel programs in Rust, not C | One language, and one set of record layouts compiled by both sides |
| Field offsets are looked up by our own reader of `/sys/kernel/btf/vmlinux` and passed in as numbers | The Rust eBPF toolchain does not emit the relocations that let a loader patch offsets (CO-RE), so the loader resolves them at start-up. One binary still runs across kernel versions |
| Kernel memory is read with explicit helper calls and pointer arithmetic | A consequence of the row above. Every `unsafe` block states why it is sound, and the kernel's verifier checks the program regardless |
| The binary re-runs itself as `__sensor` and `__exec` | It keeps the privileged part small and separate, and guarantees the command cannot start before it is being watched |
| macOS uses `sandbox-exec`, which Apple marks deprecated | It is the only way to observe without root, a system extension or an entitlement. If Apple removes it, the macOS sensor needs replacing |
| arm64 needs a newer kernel than x86-64 | Attaching to a kernel function (fentry) needs function-tracing support that arm64 kernels gained later: 6.1 lacks it, 6.8 has it. See [kernels.md](kernels.md) |

## Where to read

| To understand | Read |
|---|---|
| the kernel side | `crates/ceynox-watch-ebpf/src/main.rs` |
| loading, and decoding records | `crates/ceynox-watch/src/sensor/linux.rs` |
| the macOS sensor | `crates/ceynox-watch/src/sensor/macos.rs` |
| the start-up sequence | `crates/ceynox-watch/src/run.rs` |
| dropping root | `crates/ceynox-watch/src/sensor/privdrop.rs` |
