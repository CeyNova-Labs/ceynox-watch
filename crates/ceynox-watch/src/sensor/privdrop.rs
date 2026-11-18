//! Giving up root once it is no longer needed.
//!
//! Root is needed to load the kernel programs and open the packet socket.
//! After that the helper only reads from file descriptors it already holds,
//! and it parses data it does not control (kernel records, DNS replies from
//! the network). So when it was started through sudo to watch one user's
//! processes, it becomes that user again and keeps a single capability,
//! `CAP_BPF`, which reading the loss counters requires.

use rustix::{
    process::{Gid, Uid, geteuid},
    thread::{
        CapabilitySet, CapabilitySets, set_capabilities, set_keep_capabilities, set_no_new_privs, set_thread_groups,
        set_thread_res_gid, set_thread_res_uid,
    },
};

/// Become the user who ran sudo. `Ok(false)` when there is no such user to
/// become (started as root directly). Must be called while the process has
/// a single thread: the kernel changes identity per thread.
pub fn become_invoker() -> Result<bool, String> {
    let id = |var: &str| std::env::var(var).ok()?.parse::<u32>().ok().filter(|&n| n != 0);
    let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else {
        return Ok(false);
    };
    let (uid, gid) = (Uid::from_raw(uid), Gid::from_raw(gid));
    let step = |what: &str, res: rustix::io::Result<()>| res.map_err(|e| format!("could not drop root ({what}): {e}"));

    // Keep capabilities across the change of user, then cut them down.
    step("keep-caps", set_keep_capabilities(true))?;
    step("groups", set_thread_groups(&[gid]))?;
    step("gid", set_thread_res_gid(gid, gid, gid))?;
    step("uid", set_thread_res_uid(uid, uid, uid))?;
    let only_bpf = CapabilitySets {
        effective: CapabilitySet::BPF,
        permitted: CapabilitySet::BPF,
        inheritable: CapabilitySet::empty(),
    };
    step("capabilities", set_capabilities(None, only_bpf))?;
    step("keep-caps", set_keep_capabilities(false))?;
    step("no-new-privs", set_no_new_privs(true))?;

    // Trust nothing: being root again must now be impossible.
    let root = Uid::from_raw(0);
    if geteuid().is_root() || set_thread_res_uid(root, root, root).is_ok() {
        return Err("dropping root did not take effect".into());
    }
    Ok(true)
}
