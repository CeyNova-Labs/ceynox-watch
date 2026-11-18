//! On Linux targets, compile the kernel programs (`../ceynox-watch-ebpf`) to
//! BPF bytecode and hand the object's path to the crate, which embeds it.
//!
//! Set `CEYNOX_WATCH_BPF_OBJECT` to an already built object to skip the
//! compile: useful where the BPF toolchain is not installed, and for
//! reproducing a release from a published object.

use std::{env, path::PathBuf, process::Command};

const EBPF_DIR: &str = "../ceynox-watch-ebpf";

fn main() {
    println!("cargo:rerun-if-env-changed=CEYNOX_WATCH_BPF_OBJECT");
    println!("cargo:rerun-if-changed={EBPF_DIR}/src");
    println!("cargo:rerun-if-changed={EBPF_DIR}/Cargo.toml");
    println!("cargo:rerun-if-changed={EBPF_DIR}/rust-toolchain.toml");
    println!("cargo:rerun-if-changed=../ceynox-watch-common/src");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    if let Some(prebuilt) = env::var_os("CEYNOX_WATCH_BPF_OBJECT") {
        println!("cargo:rustc-env=CEYNOX_WATCH_BPF_OBJECT={}", PathBuf::from(prebuilt).display());
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let target_dir = out.join("ebpf");
    let toolchain = pinned_toolchain();

    // The outer cargo exports its own toolchain and flags to build scripts.
    // Left in place they would override `+<toolchain>` and leak host flags
    // into the BPF build.
    let mut cmd = Command::new("cargo");
    for var in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_DIR",
    ] {
        cmd.env_remove(var);
    }
    let status = cmd
        .arg(format!("+{toolchain}"))
        .args(["build", "--release", "--locked", "-Z", "build-std=core"])
        .args(["--target", "bpfel-unknown-none"])
        .arg("--manifest-path")
        .arg(format!("{EBPF_DIR}/Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .unwrap_or_else(|e| panic!("could not run `cargo +{toolchain}`: {e}\n{HELP}"));
    assert!(status.success(), "building the kernel programs failed\n{HELP}");

    let object = target_dir.join("bpfel-unknown-none/release/ceynox-watch-ebpf");
    println!("cargo:rustc-env=CEYNOX_WATCH_BPF_OBJECT={}", object.display());
}

const HELP: &str = "The kernel programs need the nightly toolchain pinned in \
crates/ceynox-watch-ebpf/rust-toolchain.toml (with rust-src) and bpf-linker. \
dev/Dockerfile sets both up. See CONTRIBUTING.md.";

/// The channel named in the kernel crate's `rust-toolchain.toml`.
fn pinned_toolchain() -> String {
    let path = format!("{EBPF_DIR}/rust-toolchain.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("channel"))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_string())
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("{path} names no channel"))
}
