# Linux build and test environment for ceynox-watch.
#
#   docker build -t ceynox-watch-dev dev/
#   docker run --rm -it --privileged --pid=host \
#     -v "$PWD":/src -v ceynox-watch-target:/target -w /src ceynox-watch-dev
#
# The kernel programs are Rust compiled to BPF bytecode. That needs a nightly
# toolchain with rust-src, and bpf-linker built against the LLVM major version
# that nightly uses.
# Pinned by digest, so the toolchain image cannot change underneath a
# build. Dependabot proposes the new digest when the tag moves.
FROM rust:1-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8

ARG BPF_TOOLCHAIN=nightly-2026-09-12
ARG BPF_LINKER_VERSION=0.13.0
# apt.llvm.org's signing key. The build fails if the downloaded key differs.
ARG LLVM_KEY_FPR=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget gnupg pkg-config make sudo iproute2 curl strace \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    rustup toolchain install "$BPF_TOOLCHAIN" --component rust-src --profile minimal; \
    V="$(rustc +"$BPF_TOOLCHAIN" -vV | sed -n 's/^LLVM version: \([0-9]*\).*/\1/p')"; \
    wget -qO /tmp/llvm.asc https://apt.llvm.org/llvm-snapshot.gpg.key; \
    test "$(gpg --show-keys --with-colons /tmp/llvm.asc | awk -F: '/^fpr/{print $10; exit}')" = "$LLVM_KEY_FPR"; \
    gpg --dearmor -o /usr/share/keyrings/apt-llvm.gpg /tmp/llvm.asc; \
    echo "deb [signed-by=/usr/share/keyrings/apt-llvm.gpg] https://apt.llvm.org/trixie/ llvm-toolchain-trixie-$V main" \
        > /etc/apt/sources.list.d/apt-llvm.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "llvm-$V-dev" "libpolly-$V-dev" libzstd-dev zlib1g-dev; \
    export "LLVM_SYS_${V}1_PREFIX=/usr/lib/llvm-$V" PATH="/usr/lib/llvm-$V/bin:$PATH"; \
    cargo install bpf-linker --version "$BPF_LINKER_VERSION" --locked \
        --no-default-features --features "llvm-$V"; \
    bpf-linker --version; \
    rm -rf /var/lib/apt/lists/* /usr/local/cargo/registry

ENV CARGO_TARGET_DIR=/target

# Package managers to watch in the integration tests and the demo.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# For `cargo clippy` and `cargo fmt --check`, as CI runs them.
RUN rustup component add clippy rustfmt

# Static release builds: musl, so one binary runs on any distribution.
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/* \
    && rustup target add "$(uname -m)-unknown-linux-musl"
