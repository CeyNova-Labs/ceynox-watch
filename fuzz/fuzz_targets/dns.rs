//! DNS replies come from whoever answered the query. Whatever the bytes,
//! the parser must return, and never with a name that is not a host name.
#![no_main]

use ceynox_watch_fuzz::sensor::dns;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // As a raw packet, from which the DNS message is cut out...
    if let Some(payload) = dns::dns_payload(data) {
        let _ = dns::parse_reply(payload);
    }
    // ...and as the message itself.
    if let Some(reply) = dns::parse_reply(data) {
        assert!(reply.name.len() <= 253);
        assert!(reply.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')));
    }
});
