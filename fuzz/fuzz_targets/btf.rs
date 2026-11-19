//! Kernel type information is read as root, before privileges are dropped.
//! It comes from the kernel, but a parser run as root gets no benefit of
//! the doubt: any bytes must be parsed or refused, never trusted.
#![no_main]

use ceynox_watch_fuzz::sensor::btf::Btf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(btf) = Btf::parse(data) {
        // The lookups the loader makes, which walk the type graph.
        for (strukt, field) in [("task_struct", "pid"), ("sock", "__sk_common"), ("file", "f_path"), ("a", "b")] {
            let _ = btf.field_offset(strukt, field);
            let _ = btf.struct_size(strukt);
        }
    }
});
