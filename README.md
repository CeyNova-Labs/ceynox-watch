<p align="center">
  <a href="https://ceynovahq.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/brand/mark-white.svg">
      <img width="84" alt="CeyNox" src="docs/brand/mark-black.svg">
    </picture>
  </a>
</p>

<h1 align="center">ceynox-watch</h1>

<p align="center">
  <b>See what a command really does on your machine.</b><br>
  Every program it starts, every host it talks to, every credential it touches.
</p>

<p align="center">
  <a href="https://github.com/CeyNova-Labs/ceynox-watch/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/CeyNova-Labs/ceynox-watch/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Platforms: Linux and macOS" src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-informational">
  <img alt="Written in Rust, no unsafe in user space" src="https://img.shields.io/badge/rust-no%20unsafe%20in%20user%20space-orange">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#what-is-flagged">What is flagged</a> ·
  <a href="#platforms">Platforms</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#limits">Limits</a>
</p>

Put it in front of `pip install`, `npm install`, a build script, or an AI coding agent:

<p align="center">
  <img src="docs/demo.svg" alt="ceynox-watch watching pip install. The package's setup script reads ~/.aws/credentials and an SSH private key, then connects to example.com. Each line names the process and the package it belongs to." width="900">
</p>

That is real, unedited output, from Linux. The package is [`demo/sneaky-pip`](demo/sneaky-pip), a harmless stand-in for one whose setup script goes looking for credentials. `pip` said nothing about it, even without `-q`: installing a package runs its code, and that code opened an AWS credentials file and an SSH key and made a connection. You can try it yourself; see [`demo/`](demo).

> **ceynox-watch shows you what happened. [CeyNox Security](https://ceynovahq.com) stops it.**
> ceynox-watch is the free, open-source viewer from the team that builds CeyNox Security, AI-native endpoint security for Windows, Linux and macOS. [More below.](#ceynox-security)

ceynox-watch shows; it does not block, and it does not decide what is malicious. `npm` reading `~/.npmrc` is `npm` doing its job, and it is listed all the same. What you get is the record, with the process that did each thing and how that process came to run.

**Status: early.** It runs on Linux and macOS. The two work differently and macOS sees less; [Platforms](#platforms) has the comparison.

## Usage

```sh
ceynox-watch -- <command> [args...]      # run a command and watch it
ceynox-watch --pid <pid>[,<pid>...]      # watch processes that are already running
ceynox-watch --all                       # watch the whole machine
```

Watching a command follows everything it starts, however deep, including processes that detach and keep running. Watching by pid (Linux only) does the same from the moment you attach, which is the way to watch an AI coding agent that is already running in another terminal:

```sh
ceynox-watch --pid "$(pgrep -n claude)"
```

A program that takes over the whole terminal, such as an editor or a coding agent, leaves no room for live output. Run it quietly in one terminal and follow along in another:

```sh
ceynox-watch -q --json /tmp/session.jsonl -- claude     # terminal 1
ceynox-watch --view /tmp/session.jsonl --follow         # terminal 2
```

`--view` without `--follow` shows a finished recording, with its summary.

| Option | |
|---|---|
| `-q`, `--quiet` | no live output, only the summary |
| `-v`, `--verbose` | also show every file opened |
| `--no-summary` | no summary at the end |
| `--json <file>` | also write every event as JSON, one per line (`-` for standard output with `--pid` or `--all`) |
| `--color auto\|always\|never` | `NO_COLOR` is honored |
| `--hosts` | macOS: show addresses and host names of connections (asks `sudo`; see [Platforms](#platforms)) |
| `--view <file>` | show a file written with `--json`; add `--follow` to keep up with one being written |
| `--buffer-mb <n>` | Linux: kernel event buffer size, default 16 |

Run it as yourself. On Linux, watching needs root, so it asks `sudo` for that part only; on macOS it needs no root at all. Either way your command runs as you, with your environment, and ceynox-watch exits with your command's exit status. Its own output goes to standard error, so pipes and redirections of the command keep working.

## What is flagged

Opens and connections are checked against a catalog of places that matter, in [`classify.rs`](crates/ceynox-watch/src/classify.rs):

- **Credentials**: SSH keys, cloud credentials (AWS, Google Cloud, Azure, Kubernetes, Docker and others), package registry tokens, Git and GitHub credentials, AI tool tokens, password stores, wallets, `.env` files, mounted secrets, another process's environment.
- **Browser data**: saved logins, cookies and extension storage.
- **History**: shell and REPL history.
- **Persistence**: writes to shell startup files, `authorized_keys`, Git hooks, autostart entries, systemd units, cron, launch agents.
- **Control**: the cloud metadata service, the container runtime socket, the SSH and GPG agents.

Listing one of the folders secrets live in (`~/.ssh`, `~/.aws`, `~/.gnupg` and so on) is flagged too: looking around comes before taking.

The catalog is one table of patterns. Adding a location is a one-line change, and additions are welcome.

## Platforms

| | Linux | macOS |
|---|---|---|
| Needs | root, through `sudo` | nothing: no root, nothing installed |
| Watch a command | yes | yes |
| Attach to running processes, or the whole machine | yes | no |
| Programs started | all, with arguments | all; arguments are missing for programs that exit within a few milliseconds |
| Files read | all | those in catalog locations (`-v` for all) |
| Files written | all | all |
| Network | address, port, protocol and host name | port only; with `--hosts`, address, protocol and host name (uses `sudo`) |
| Processes ending | yes | no |
| Programs that sandbox themselves | work | fail to start their sandbox |

The last row matters. macOS does not allow a sandbox inside a sandbox, so a program that sandboxes itself or its children will find that it cannot while it runs under ceynox-watch. Browsers do this, and so do AI coding agents that sandbox the commands they run. For the same reason ceynox-watch cannot be started from inside such a sandbox, and says so if you try.

## Install

Download the archive for your system from the [releases page](https://github.com/CeyNova-Labs/ceynox-watch/releases), check it against `SHA256SUMS`, and put the `ceynox-watch` binary somewhere on your `PATH`. The Linux binaries are static and run on any distribution; the macOS binary runs on both Apple silicon and Intel.

The macOS binary is not signed with an Apple developer certificate. If you download it with a browser, macOS marks it as quarantined and refuses to run it. Either download with `curl`, which sets no such mark, or clear it once:

```sh
xattr -d com.apple.quarantine ./ceynox-watch
```

You do not have to take the binary on trust either way: the checksums are published with each release, the build is done in the open by the [release workflow](.github/workflows/release.yml), and you can build it yourself from source.

To build from source instead:

**macOS**, with a [Rust toolchain](https://rustup.rs):

```sh
git clone https://github.com/CeyNova-Labs/ceynox-watch
cd ceynox-watch
cargo build --release      # the binary is target/release/ceynox-watch
```

Reading the reports needs an account that is allowed to read the system log, which administrator accounts are.

**Linux** needs Docker, or the toolchain described in [CONTRIBUTING.md](CONTRIBUTING.md):

```sh
git clone https://github.com/CeyNova-Labs/ceynox-watch
cd ceynox-watch
docker build -t ceynox-watch-dev dev/
dev/run.sh cargo build --release
```

Requirements to run: Linux 5.11 or newer on x86-64, 6.0 or newer on arm64, with BTF type information (`/sys/kernel/btf/vmlinux` exists). Every mainstream distribution of the last few years qualifies.

## How it works

### Linux

Six small eBPF programs, written in Rust, observe the kernel:

| What | Where |
|---|---|
| process start, exec, exit | `sched_process_fork`, `sched_process_exec`, `sched_process_exit` |
| file opens | `security_file_open` |
| connections and datagrams | `security_socket_connect`, `security_socket_sendmsg` |

File and network activity is hooked at the kernel's security layer, not at system-call entry. Every way of opening a file passes through it (`open`, `openat2`, `io_uring`, the kernel loading a program for `execve`), and the kernel supplies the path it resolved. A relative path, a symlink, or a path swapped after the check cannot hide the real target.

Which processes are reported is decided in the kernel. Watching a command means watching its process and everything descended from it; nothing about any other process leaves the kernel. Process ids are translated to the pid namespace ceynox-watch runs in, so it works inside containers and sees into containers from the host.

Host names come from DNS replies read off a packet socket that a seventh program narrows to UDP from port 53. An address is shown with the name it was last looked up by.

The programs only observe. They attach to tracing hooks, which cannot change what the kernel does, and they write only to their own maps.

### macOS

macOS ships a sandbox, and a sandbox profile can ask for a report of an operation without forbidding it. ceynox-watch starts your command with `sandbox-exec` under a profile that allows everything and reports program starts, forks, reads of catalog locations, writes and outgoing connections. The kernel writes the reports to the system log, and ceynox-watch reads them back with `log stream`, picking out its own by a tag unique to the run.

That is all of it: two tools that come with the system, no kernel extension, no entitlement, no root. The one optional extra is `--hosts`: the sandbox reports a connection's port but not its address, so with that flag ceynox-watch asks `sudo` to run the system's own `tcpdump`, reads the capture as you, and matches connections to the watched processes. No code of ours runs as root. Names come from DNS replies and from the server name each TLS connection states when it opens, so they survive the system's lookup cache. The price is what the reports leave out, listed under [Platforms](#platforms). They do not say which process a new process came from, so that is reconstructed from the order of reports and from the process table, which is right nearly always and can be wrong for processes that live a few milliseconds.

## The tool's own security

A tool you run as root in front of untrusted code should hold up to scrutiny.

- **Root is used for as little and as short as possible.** On macOS it is not used at all. On Linux the part that needs root is a separate helper process started through `sudo`. It loads the kernel programs and then gives up root for good: it becomes you again, keeps one capability (`CAP_BPF`), and sets `no_new_privs`. The test suite checks this on every run. Watching the whole machine (`--all`) is the exception, because describing other users' processes needs root.
- **The watched command never runs as root** and never holds a file descriptor of the helper.
- **No `unsafe` in the user-space program**: `#![forbid(unsafe_code)]`. The kernel programs need `unsafe` to read kernel memory through BPF helpers; each use carries its justification, and the kernel's verifier checks the result independently before anything runs.
- **Untrusted input is treated as such.** DNS replies and kernel type information are parsed with bounds checks everywhere and tested against truncated and corrupted input. Everything a watched process controls (file names, arguments, socket paths) is stripped of terminal control sequences before it is printed, so a file name cannot repaint your screen.
- **Nothing leaves your machine.** No telemetry, no update check, no network access of any kind.
- **Few dependencies**, all listed in `Cargo.lock`, checked in CI against known advisories and a license allowlist.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Limits

Worth knowing before you rely on it:

- **It is a record, not a sandbox.** By the time you read that a key was opened, it was opened. Run untrusted code in a disposable environment if the outcome matters.
- **It reports opens, not bytes.** A file that was opened counts as read even if nothing was read from it, and you see where a connection went, not what was sent.
- **Work done by someone else is not followed.** If a watched process asks an already-running service to act for it (the Docker daemon, `systemd-run`, an SSH agent), you see the request being made, since the socket connection is reported, but not what the service then does.
- **Names are best effort.** On Linux they come from plain DNS over UDP: a process using DNS over HTTPS, or an address hard-coded in the program, shows as an address only. On macOS with `--hosts` they also come from the TLS handshake, which covers cached lookups but not QUIC or a handshake split across packets. When two names share an address, the most recent one wins.
- **A process running as root can interfere** with any tracing tool, this one included. ceynox-watch is built to tell you what ordinary untrusted code does, not to withstand an attacker who already owns the machine.
- **Under extreme load events can be dropped.** When that happens the output says so and says how many; it never fails silently. `--buffer-mb` raises the limit.
- **Files already open are not opens.** A descriptor inherited from outside the watched tree is used without an open being seen.

## JSON

`--json` writes one object per event:

```json
{"ts":1795011840123,"pid":4211,"type":"exec","ppid":4207,"uid":1000,"exe":"/usr/bin/node","argv":["node","collect.js"],"cwd":"/home/dev/app/node_modules/sneaky-package"}
{"ts":1795011840182,"pid":4211,"type":"open","path":"/home/dev/.aws/credentials"}
{"ts":1795011840210,"pid":4211,"type":"connect","peer":{"net":"ip","ip":"172.66.147.243","port":443,"proto":"tcp"},"name":"example.com"}
{"ts":1795011840260,"pid":4211,"type":"exit","code":0}
```

Event types are `fork`, `exec`, `open` (with `"write":true` when opened for writing, `"dir":true` for directories), `connect` (peer is `ip` or `unix`), `exit` (with `code` or `signal`) and `lost`. `ts` is milliseconds since the Unix epoch. The format may still change before 1.0.

## Development

```sh
cargo test                        # unit tests, any platform
dev/run.sh dev/integration.sh     # Linux: real commands on a real kernel
dev/integration-macos.sh          # macOS: the same idea, no root needed
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the details.

## License

The user-space program is licensed under [Apache-2.0](LICENSE). The kernel programs in `crates/ceynox-watch-ebpf` are licensed under MIT or GPL-2.0, at your option, because the kernel only loads programs that use its tracing helpers under a GPL-compatible license. The record layouts in `crates/ceynox-watch-common`, which both sides compile, are MIT or Apache-2.0.

The CeyNox and CeyNova Labs names and logos (`docs/brand`) are trademarks of CeyNova Labs LLC and are not covered by these licenses.

## CeyNox Security

ceynox-watch tells you, after the fact, that an install script opened your SSH key. On one laptop, when you remember to run it, that is useful. Across a company's machines, all day, somebody has to be watching and somebody has to act.

That is what [**CeyNox Security**](https://ceynovahq.com) does. It is AI-native endpoint security for Windows, Linux and macOS, made by CeyNova Labs, the company behind this tool:

- **It watches every device, all the time.** An agent on each one sees processes, network, DNS, files and sign-ins.
- **It reviews every package.** Every Python and npm package installed is read by AI, once per release for the whole fleet.
- **It acts, not just advises.** The agents quarantine a malicious package, stop the process running it, or cut a computer off the network, on their own and in milliseconds, within the limits you set.
- **It runs where you want.** Hosted by CeyNova Labs, or self-hosted on your own infrastructure.

CeyNox Security is in closed beta. [Join the waitlist at ceynovahq.com.](https://ceynovahq.com)

ceynox-watch is and stays free and open source. It shares no code with CeyNox Security and sends nothing anywhere.
