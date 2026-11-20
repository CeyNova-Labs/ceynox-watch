# Contributing

Bug reports, catalog additions and patches are welcome.

## What belongs here

ceynox-watch observes one machine, when asked, and reports what it saw. Changes that make it see more, show it better, or flag more of it from a fixed list are in scope.

Out of scope, however well made: anything that blocks, stops, quarantines or otherwise acts on what it sees; anything that plants bait such as decoy files or fake credentials; anything that judges with a model instead of a list a person can read; and anything that collects results from many machines. Those are a different kind of tool. Saying so here means a "no" to such a change is about scope, not about the idea.

## Layout

| Path | What |
|---|---|
| `crates/ceynox-watch` | the program: command line, runner, report, output, and the Linux loader under `src/sensor` |
| `crates/ceynox-watch-ebpf` | the kernel programs, compiled to BPF bytecode |
| `crates/ceynox-watch-common` | record layouts shared by the two |
| `dev/` | the build and test container, and the end-to-end tests |
| `demo/` | a harmless package for demonstrations |
| `action.yml` | the GitHub Action, a thin wrapper around the program |
| `fuzz/` | fuzz targets for the parsers of untrusted input |
| `docs/gallery` | records of well-known packages being installed, made by `dev/gallery.sh` |

## Building

The kernel programs are Rust compiled for the `bpfel-unknown-none` target. That needs the nightly toolchain pinned in `crates/ceynox-watch-ebpf/rust-toolchain.toml` (with `rust-src`) and `bpf-linker` built against the same LLVM major version as that nightly. `dev/Dockerfile` sets all of it up, and works on macOS and Windows hosts through Docker:

```sh
docker build -t ceynox-watch-dev dev/
dev/run.sh cargo build
dev/run.sh                    # a shell in the container
```

`crates/ceynox-watch/build.rs` compiles the kernel programs as part of a normal `cargo build` on Linux. To build without the BPF toolchain, point `CEYNOX_WATCH_BPF_OBJECT` at an object built elsewhere.

On macOS `cargo build` is all there is to it: the macOS sensor (`src/sensor/macos.rs`) uses tools the system ships and needs no special toolchain. The unit tests of both sensors run on either system.

## Testing

```sh
cargo test                        # unit tests, any platform
dev/run.sh dev/integration.sh     # end to end, needs a privileged Linux container
dev/integration-macos.sh          # end to end on macOS, after cargo build --release
cargo clippy --all-targets
cargo fmt --all --check
```

`--inspect` and the GitHub Action need a container runtime and a runner, so they are exercised by the `build and end-to-end (Linux)` job in CI. To try `--inspect` from macOS during development, build the static Linux binary in the container and point `CEYNOX_WATCH_LINUX_BINARY` at it.

A change to one of the parsers of untrusted input (`sensor/dns.rs`, `sensor/pktap.rs`, `sensor/btf.rs`) should survive its fuzz target for a while: `cargo install cargo-fuzz`, then `cargo +nightly fuzz run dns` (or `btf`, `capture`) from the repository root. CI runs each for under a minute.

`dev/smoke.sh <binary>` is a two-minute check for a machine you have not tried before. Its results are collected in `docs/kernels.md`.

`dev/run.sh dev/bench.sh` times a real `npm ci` on its own, under strace and under ceynox-watch. The numbers in `docs/comparison.md` come from it; a change that could affect overhead should be measured with it, and that page updated if they move.

The end-to-end tests run real commands (a shell, `curl`, `npm install`) under ceynox-watch on the container's kernel and check what is reported. A change to the kernel programs or the loader should come with a case there.

## Adding to the catalog

Locations worth flagging live in one table, `RULES` in `crates/ceynox-watch/src/classify.rs`. Hosts worth flagging live in another, `HOSTS`, in the same file. Add a line, and a line to the tests below it. Keep in mind:

- The first matching rule wins, so put exceptions (`skip`) before the rule they carve out of.
- Flag where secrets are, not where they might be. A rule that fires on every run of a common tool teaches people to stop reading.
- Use `Write` for locations that only matter when changed, such as startup files.
- A host belongs in `HOSTS` only if its main use is to receive arbitrary data from anyone. A general-purpose site that can also be misused does not.

## Rules for the code

- No `unsafe` in `crates/ceynox-watch` or `crates/ceynox-watch-common`; both forbid it. In the kernel programs every `unsafe` block states why it is sound.
- Anything a watched process or the network controls is untrusted: bounds-check it, limit it, and clean it before printing (`render::clean`).
- The kernel programs observe and nothing else. No program type that can change a return value, drop a packet or modify memory.
- New dependencies need a reason. The tool is about supply-chain risk and should carry little of its own.
- Output is part of the interface: the tests compare it literally, so change them together.

## Licensing of contributions

Contributions are accepted under the license of the files they touch: Apache-2.0 for the program, MIT or GPL-2.0 for the kernel programs, MIT or Apache-2.0 for the shared layouts.
