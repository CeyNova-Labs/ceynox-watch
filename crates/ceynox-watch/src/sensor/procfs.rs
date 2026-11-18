//! Reads of `/proc` for what the kernel programs do not carry: the resolved
//! program path and working directory of a process, and a description of
//! processes that were already running when watching began.
//!
//! Everything here is best effort. A process can exit between an event and
//! the read, so every function returns `None` rather than an error.

use std::{collections::HashMap, fs, path::Path};

use crate::event::What;

/// The program a process is running, as an absolute path.
pub fn exe(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let s = link.to_string_lossy();
    // The kernel appends this when the file was replaced or removed.
    Some(s.strip_suffix(" (deleted)").unwrap_or(&s).to_string())
}

pub fn cwd(pid: u32) -> Option<String> {
    Some(fs::read_link(format!("/proc/{pid}/cwd")).ok()?.to_string_lossy().into_owned())
}

/// Split a NUL-separated argument block, as found in `/proc/<pid>/cmdline`
/// and in the kernel's exec record.
pub fn split_args(raw: &[u8]) -> Vec<String> {
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|&b| b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
}

/// Parent pid and real uid from `/proc/<pid>/status`.
fn parent_and_uid(pid: u32) -> Option<(u32, u32)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field =
        |name: &str| status.lines().find_map(|l| l.strip_prefix(name)?.split_whitespace().next()?.parse::<u32>().ok());
    Some((field("PPid:")?, field("Uid:")?))
}

/// Describe a process that is already running, in the shape of the exec
/// event we would have seen had we been watching when it started.
pub fn describe(pid: u32) -> Option<What> {
    let (ppid, uid) = parent_and_uid(pid)?;
    let argv = split_args(&fs::read(format!("/proc/{pid}/cmdline")).ok()?);
    // Kernel threads have no cmdline and no exe; fall back to their name.
    let exe = exe(pid)
        .or_else(|| argv.first().cloned())
        .or_else(|| Some(format!("[{}]", fs::read_to_string(format!("/proc/{pid}/comm")).ok()?.trim())))?;
    Some(What::Exec { ppid, uid, exe, argv, cwd: cwd(pid), existing: true })
}

/// `roots` plus every process descended from them, parents before children.
pub fn with_descendants(roots: &[u32]) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for pid in all_pids() {
        if let Some((ppid, _)) = parent_and_uid(pid) {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut out: Vec<u32> = Vec::new();
    let mut queue: Vec<u32> = roots.to_vec();
    while let Some(pid) = queue.pop() {
        if out.contains(&pid) {
            continue;
        }
        out.push(pid);
        if let Some(kids) = children.get(&pid) {
            queue.extend(kids);
        }
    }
    out
}

pub fn all_pids() -> Vec<u32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect()
}

pub fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_argument_blocks() {
        assert_eq!(split_args(b"npm\0install\0"), ["npm", "install"]);
        assert_eq!(split_args(b"sh\0-c\0echo hi"), ["sh", "-c", "echo hi"]);
        assert_eq!(split_args(b"a\0\0b\0"), ["a", "", "b"]);
        assert!(split_args(b"").is_empty());
        assert!(split_args(b"\0").is_empty());
    }
}
