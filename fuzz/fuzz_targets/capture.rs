//! The packet capture on macOS is the output of another program, carrying
//! packets from the network. It arrives in pieces of any size; the reader
//! must cope with every way of cutting it up, and so must what consumes it.
#![no_main]

use ceynox_watch_fuzz::sensor::pktap::{Capture, Matcher};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte decides how the rest is cut into reads.
    let Some((&step, rest)) = data.split_first() else {
        return;
    };
    let step = usize::from(step) + 1;
    let mut capture = Capture::new();
    let mut matcher = Matcher::new();
    let mut now = 0u64;
    for piece in rest.chunks(step) {
        for seen in capture.push(piece) {
            matcher.seen(seen, now);
        }
        now += 100;
        let _ = matcher.ready(now, false, |pid| pid % 2 == 0);
    }
    let _ = matcher.ready(now, true, |_| true);
});
