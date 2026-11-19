# ceynox-watch and strace, measured

The closest existing tool to `ceynox-watch -- <command>` is `strace -f <command>`. This page records the differences we have tested, not assumed. Everything here can be repeated: the timings with [`dev/bench.sh`](../dev/bench.sh), the rest with the commands shown.

## Speed is not the difference it might seem

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

## Opens made through io_uring

A program that opens a file with an `io_uring` request makes no `open` system call. [`dev/uring_open.c`](../dev/uring_open.c) is such a program (build it with `gcc -o uring_open dev/uring_open.c -luring`).

```
$ strace -f ./uring_open ~/.aws/credentials
io_uring_enter(3, 1, 0, 0, NULL, 8) = 1          # the open is in here, unseen

$ ceynox-watch -- ./uring_open ~/.aws/credentials
   0.001s  READ   ~/.aws/credentials  AWS credentials (credentials)  uring_open
```

ceynox-watch hooks where the kernel opens files, not where programs ask, so the route taken does not matter.

## Commands that use sudo

Run as an ordinary user, strace cannot follow a command through `sudo`:

```
$ strace -f sudo id -u
sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set ...
```

The strace manual explains why: "Programs that use the setuid bit do not have effective user ID privileges while being traced." Under ceynox-watch the same command works, and what it ran as root is in the record.

## Resolved paths

strace prints the path a program passed. `strace -y` adds the file it resolved to. On Linux ceynox-watch always shows the resolved one.

## What strace has and ceynox-watch does not

Every system call, with its arguments and return value. Signals. Timing per call. Decades of use. ceynox-watch records program starts and exits, file opens, connections and transfer sizes, and nothing else. If you need the complete record, strace is the tool.
