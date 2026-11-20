# How ceynox-watch compares

None of the mechanisms in ceynox-watch are new. If one of these already answers your question, use it.

| Tool | What it is, in its own words | Reach for it instead when |
|---|---|---|
| [strace](https://strace.io) | "intercepts and records the system calls made by a process" | you want every system call and its arguments, from a tool every distribution packages. It is the more complete record. |
| [bpftrace](https://github.com/bpftrace/bpftrace) | "a general purpose tracing tool and language for Linux" | you have a question of your own to ask the kernel and are happy to write the program that asks it. |
| [Tetragon](https://tetragon.io) | "realtime, eBPF-based Security Observability and Runtime Enforcement" | you need something running all the time across hosts or a cluster, with policies, and able to act. |
| [Falco](https://falco.org) | "designed to detect and alert on abnormal behavior and potential security threats in real-time" | you want rule-based alerts from hosts, containers and Kubernetes, fed into your monitoring. |
| [Tracee](https://github.com/aquasecurity/tracee) | "a runtime security and observability tool" that uses eBPF | you want a continuous stream of detailed runtime events to investigate. |
| [Harden-Runner](https://github.com/step-security/harden-runner) | for GitHub Actions jobs: "Each outbound network connection, file operation, and process execution is mapped" | your concern is GitHub Actions. It overlaps most with our Action: it also builds a baseline of a job's outbound calls and flags what is new. It goes further than we do by blocking traffic outside an allow-list, and it shows results on StepSecurity's site, where ours writes files into the job. |
| [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) | "analyses the capabilities of packages available on open source repositories" | you want a stronger sandbox than `--inspect` gives. It runs packages in gVisor; ours shares your kernel. |
| [Socket Firewall](https://docs.socket.dev/docs/socket-firewall-free) | "blocks confirmed malware that has been verified through human review" | you want known-bad packages stopped before they install. It works from what is already known; ceynox-watch shows what happened, known or not. The two go together. |

## Against strace, measured

The closest existing tool to `ceynox-watch -- <command>` is `strace -f <command>`. These are the differences we have tested, not assumed. Everything can be repeated: the timings with [`dev/bench.sh`](../dev/bench.sh), the rest with the commands shown.

### Speed is not the difference it might seem

A warm-cache `npm ci` of a project depending on express, typescript, eslint, esbuild and webpack. Eleven runs of each, interleaved so that drift in the machine affects all alike.

| | Median | Fastest to slowest | Slower by (median) |
|---|---:|---:|---:|
| on its own | 1,251 ms | 1,183 to 1,333 ms | |
| `strace -f` | 3,647 ms | 3,489 to 3,990 ms | 191% |
| `strace -f -e trace=execve,openat,connect` | 3,463 ms | 3,351 to 3,963 ms | 177% |
| the same with `--seccomp-bpf` | 1,322 ms | 1,244 to 1,375 ms | 6% |
| ceynox-watch | 1,368 ms | 1,338 to 1,491 ms | 9% |

What the numbers support:

- By default strace stops the process at every system call, and that roughly triples the time of this install.
- Told which calls it wants and given `--seccomp-bpf`, strace costs a few percent. So does ceynox-watch. The ranges of those two rows overlap, so this run does not show one to be faster than the other; treat them as the same.
- A command that does nothing takes about 220 ms longer under ceynox-watch, so very short commands pay proportionally more.

Measured on one machine: Linux 7.0 on arm64 (Docker Desktop's kernel), strace 6.13, ceynox-watch 0.2.3. Other machines will give other numbers.

### Opens made through io_uring

A program that opens a file with an `io_uring` request makes no `open` system call. [`dev/uring_open.c`](../dev/uring_open.c) is such a program (build it with `gcc -o uring_open dev/uring_open.c -luring`).

```
$ strace -f ./uring_open ~/.aws/credentials
io_uring_enter(3, 1, 0, 0, NULL, 8) = 1          # the open is in here, unseen

$ ceynox-watch -- ./uring_open ~/.aws/credentials
   0.001s  READ   ~/.aws/credentials  AWS credentials (credentials)  uring_open
```

ceynox-watch hooks where the kernel opens files, not where programs ask, so the route taken does not matter.

### Commands that use sudo

Run as an ordinary user, strace cannot follow a command through `sudo`:

```
$ strace -f sudo id -u
sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set ...
```

The strace manual explains why: "Programs that use the setuid bit do not have effective user ID privileges while being traced." Under ceynox-watch the same command works, and what it ran as root is in the record.

### Resolved paths

strace prints the path a program passed. `strace -y` adds the file it resolved to. On Linux ceynox-watch always shows the resolved one.

### What strace has and ceynox-watch does not

Every system call, with its arguments and return value. Signals. Timing per call. Decades of use. ceynox-watch records program starts and exits, file opens, connections and transfer sizes, and nothing else. If you need the complete record, strace is the tool.
