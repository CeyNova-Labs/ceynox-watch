//! Reads the packet capture that Apple's `tcpdump -i pktap,all -w -`
//! produces, to learn which process connected where and which names were
//! looked up.
//!
//! The format is pcapng with two Apple additions: a "process information"
//! block naming a process, and options on each packet block pointing at the
//! process that sent or will receive it. That is what lets a connection be
//! tied to a pid.
//!
//! The capture is network data and the output of another program. Nothing
//! in it is trusted: every length is checked against what is there, sizes
//! are capped, and anything unexpected is skipped.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::dns;
use crate::event::{Event, Peer, Proto, What};

const BLOCK_SECTION: u32 = 0x0A0D_0D0A;
const BLOCK_INTERFACE: u32 = 1;
const BLOCK_PACKET: u32 = 6;
/// Apple: a process, as `pid` followed by options (its name among them).
const BLOCK_PROCESS: u32 = 0x8000_0001;

const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

const OPT_END: u16 = 0;
/// Standard: packet flags; the low two bits are the direction.
const OPT_FLAGS: u16 = 2;
/// Apple: index of the process block of the socket's owner.
const OPT_PROCESS: u16 = 0x8001;
/// Apple: index of the process on whose behalf it acted, if different
/// (a name lookup done by the resolver daemon for a program).
const OPT_EFFECTIVE_PROCESS: u16 = 0x8003;

const DIRECTION_OUT: u32 = 2;

const LINK_NULL: u16 = 0;
const LINK_ETHERNET: u16 = 1;
const LINK_RAW: u16 = 12;
const LINK_LOOP: u16 = 108;
const LINK_RAW_ALT: u16 = 101;

/// No block we care about is larger; a bigger length means corrupt input.
const MAX_BLOCK: usize = 1 << 20;
const MAX_TABLE: usize = 65_536;

/// Something learned from one captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// A process started a TCP connection or sent a datagram.
    Sent { pid: u32, ip: IpAddr, port: u16, proto: Proto },
    /// A name lookup was answered.
    Resolved { name: String, addrs: Vec<IpAddr> },
}

/// Incremental parser: feed it bytes as they arrive from the pipe.
#[derive(Debug, Default)]
pub struct Capture {
    pending: Vec<u8>,
    /// Link type of each interface of the current section, by index.
    links: Vec<u16>,
    /// Pid of each process block of the current section, by index.
    pids: Vec<u32>,
    /// Set when the input stops making sense; everything after is ignored.
    broken: bool,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

/// Walk a block's options, calling `each` with (code, value).
fn options(mut b: &[u8], mut each: impl FnMut(u16, &[u8])) {
    while let (Some(code), Some(len)) = (u16_at(b, 0), u16_at(b, 2)) {
        let len = usize::from(len);
        let Some(value) = b.get(4..4 + len) else {
            return;
        };
        if code == OPT_END {
            return;
        }
        each(code, value);
        // Values are padded to four bytes.
        let Some(rest) = b.get(4 + len.next_multiple_of(4)..) else {
            return;
        };
        b = rest;
    }
}

impl Capture {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bytes from the capture and return what the complete blocks among
    /// them say. Incomplete data is kept for the next call.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Seen> {
        let mut out = Vec::new();
        if self.broken {
            return out;
        }
        self.pending.extend_from_slice(bytes);
        let mut at = 0;
        while let (Some(kind), Some(len)) = (u32_at(&self.pending, at), u32_at(&self.pending, at + 4)) {
            let len = len as usize;
            // Header, trailing length, and four-byte alignment are the rule.
            if !(12..=MAX_BLOCK).contains(&len) || !len.is_multiple_of(4) {
                self.broken = true;
                self.pending.clear();
                return out;
            }
            // The whole block, trailing length included, must be here.
            let Some(whole) = self.pending.get(at..at + len) else {
                break; // the rest of the block has not arrived yet
            };
            let body = whole[8..len - 4].to_vec();
            self.block(kind, &body, &mut out);
            if self.broken {
                self.pending.clear();
                return out;
            }
            at += len;
        }
        self.pending.drain(..at);
        out
    }

    fn block(&mut self, kind: u32, body: &[u8], out: &mut Vec<Seen>) {
        match kind {
            BLOCK_SECTION => {
                // Only the byte order this code reads; Macs write no other.
                if u32_at(body, 0) != Some(BYTE_ORDER_MAGIC) {
                    self.broken = true;
                    return;
                }
                self.links.clear();
                self.pids.clear();
            }
            BLOCK_INTERFACE => {
                if let Some(link) = u16_at(body, 0)
                    && self.links.len() < MAX_TABLE
                {
                    self.links.push(link);
                }
            }
            BLOCK_PROCESS => {
                if let Some(pid) = u32_at(body, 0)
                    && self.pids.len() < MAX_TABLE
                {
                    self.pids.push(pid);
                }
            }
            BLOCK_PACKET => {
                if let Some(seen) = self.packet(body) {
                    out.push(seen);
                }
            }
            _ => {}
        }
    }

    fn packet(&self, body: &[u8]) -> Option<Seen> {
        let link = *self.links.get(u32_at(body, 0)? as usize)?;
        let captured = u32_at(body, 12)? as usize;
        let frame = body.get(20..20usize.checked_add(captured)?)?;

        let (mut owner, mut effective, mut direction) = (None, None, None);
        options(body.get(20 + captured.next_multiple_of(4)..).unwrap_or(&[]), |code, value| {
            let number = u32_at(value, 0);
            match code {
                OPT_PROCESS => owner = number,
                OPT_EFFECTIVE_PROCESS => effective = number,
                OPT_FLAGS => direction = number.map(|f| f & 3),
                _ => {}
            }
        });

        let packet = match link {
            LINK_NULL | LINK_LOOP => frame.get(4..)?,
            LINK_ETHERNET => {
                // A VLAN tag pushes the payload four bytes further.
                let tagged = frame.get(12..14)? == [0x81, 0x00];
                frame.get(if tagged { 18 } else { 14 }..)?
            }
            LINK_RAW | LINK_RAW_ALT => frame,
            _ => return None,
        };

        // Answers to name lookups, whoever asked.
        if let Some(reply) = dns::dns_payload(packet).and_then(dns::parse_reply) {
            return Some(Seen::Resolved { name: reply.name, addrs: reply.addrs });
        }

        // The rest is about who sent what, so it needs a sender.
        if direction != Some(DIRECTION_OUT) {
            return None;
        }
        let pid = *self.pids.get(effective.or(owner)? as usize)?;
        if pid == 0 {
            return None;
        }
        let (protocol, ip, transport) = match packet.first()? >> 4 {
            4 => {
                let header = usize::from(packet[0] & 0x0f) * 4;
                // Only the first fragment has the transport header.
                if header < 20 || u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]) & 0x1fff != 0 {
                    return None;
                }
                let a = packet.get(16..20)?;
                (*packet.get(9)?, IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])), packet.get(header..)?)
            }
            6 => {
                let a: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
                (*packet.get(6)?, IpAddr::V6(Ipv6Addr::from(a)), packet.get(40..)?)
            }
            _ => return None,
        };
        let port = u16::from_be_bytes([*transport.get(2)?, *transport.get(3)?]);
        match protocol {
            6 => {
                // The first packet of a connection: SYN without ACK.
                let flags = *transport.get(13)?;
                if flags & 0x12 == 0x02 {
                    return Some(Seen::Sent { pid, ip, port, proto: Proto::Tcp });
                }
                // Otherwise the filter let it through as the opening of a
                // TLS session, which names the server it is meant for. That
                // works when the lookup was answered from a cache and never
                // crossed the wire.
                let header = usize::from(*transport.get(12)? >> 4) * 4;
                if header < 20 {
                    return None;
                }
                let name = server_name(transport.get(header..)?)?;
                Some(Seen::Resolved { name, addrs: vec![ip] })
            }
            17 => Some(Seen::Sent { pid, ip, port, proto: Proto::Udp }),
            _ => None,
        }
    }
}

/// The server name in a TLS ClientHello, if `data` starts with one and the
/// name extension is within it. Written for hostile input: every length is
/// checked, and the name must look like a host name.
fn server_name(data: &[u8]) -> Option<String> {
    // Record: type 22 (handshake), version, length. Handshake: type 1
    // (ClientHello), 3-byte length, version, 32 random bytes.
    if *data.first()? != 22 || *data.get(5)? != 1 {
        return None;
    }
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(*data.get(at)?); // session id
    at += 2 + usize::from(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?])); // cipher suites
    at += 1 + usize::from(*data.get(at)?); // compression methods
    let extensions_len = usize::from(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]));
    at += 2;
    // The hello may continue in the next packet; read what is here.
    let end = data.len().min(at.checked_add(extensions_len)?);
    while at + 4 <= end {
        let kind = u16::from_be_bytes([data[at], data[at + 1]]);
        let len = usize::from(u16::from_be_bytes([data[at + 2], data[at + 3]]));
        let body = data.get(at + 4..at + 4 + len)?;
        if kind == 0 {
            // server_name: list length, then entries of type (0 = host
            // name), length, name. The first host name is the one.
            if *body.get(2)? != 0 {
                return None;
            }
            let name_len = usize::from(u16::from_be_bytes([*body.get(3)?, *body.get(4)?]));
            let name = body.get(5..5 + name_len)?;
            let ok = !name.is_empty()
                && name.len() <= 253
                && name.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'));
            return ok.then(|| String::from_utf8_lossy(name).to_ascii_lowercase());
        }
        at += 4 + len;
    }
    None
}

/// Joins what the capture saw with what the sandbox reported.
///
/// The capture sees the whole machine; only connections by processes of the
/// watched command are wanted. Which pids those are is learned from the
/// sandbox reports, which can trail the packets by a moment, so a
/// connection is held until its process is known or it has waited too long.
#[derive(Debug, Default)]
pub struct Matcher {
    names: HashMap<IpAddr, String>,
    waiting: Vec<(u64, u32, IpAddr, u16, Proto)>,
    /// When a (process, peer) was last passed on, to report a stream of
    /// datagrams to one peer once per window instead of once per packet.
    recent: HashMap<(u32, IpAddr, u16), u64>,
}

const MAX_NAMES: usize = 8192;
const MAX_WAITING: usize = 4096;
/// How long a connection waits for its process to become known.
const WAIT_MS: u64 = 15_000;
/// How long a TCP connection is held back for its name to turn up: the TLS
/// opening follows the first packet by one round trip.
const NAME_MS: u64 = 400;
const REPEAT_MS: u64 = 5_000;

impl Matcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seen(&mut self, seen: Seen, now: u64) {
        match seen {
            Seen::Resolved { name, addrs } => {
                if self.names.len() + addrs.len() > MAX_NAMES {
                    self.names.clear();
                }
                for addr in addrs {
                    self.names.insert(addr, name.clone());
                }
            }
            Seen::Sent { pid, ip, port, proto } => {
                if self.waiting.len() < MAX_WAITING {
                    self.waiting.push((now, pid, ip, port, proto));
                }
            }
        }
    }

    /// The connections whose process `is_ours` now vouches for, as events.
    /// Those that have waited too long are forgotten. A connection without
    /// a name yet is held a moment for one, unless `last` says this is the
    /// final call.
    pub fn ready(&mut self, now: u64, last: bool, is_ours: impl Fn(u32) -> bool) -> Vec<Event> {
        let mut out = Vec::new();
        let waiting = std::mem::take(&mut self.waiting);
        for (at, pid, ip, port, proto) in waiting {
            if !is_ours(pid) {
                if now.saturating_sub(at) < WAIT_MS {
                    self.waiting.push((at, pid, ip, port, proto));
                }
                continue;
            }
            let name = self.names.get(&ip).cloned();
            if name.is_none() && proto == Proto::Tcp && !last && now.saturating_sub(at) < NAME_MS {
                self.waiting.push((at, pid, ip, port, proto));
                continue;
            }
            let before = self.recent.insert((pid, ip, port), at);
            if before.is_some_and(|l| at.saturating_sub(l) < REPEAT_MS) {
                continue;
            }
            out.push(Event { ts: at, pid, what: What::Connect { peer: Peer::Ip { ip, port, proto }, name } });
        }
        if self.recent.len() > MAX_WAITING {
            self.recent.clear();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut body = body.to_vec();
        body.resize(body.len().next_multiple_of(4), 0);
        let len = (body.len() + 12) as u32;
        let mut out = kind.to_le_bytes().to_vec();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&len.to_le_bytes());
        out
    }

    fn section() -> Vec<u8> {
        let mut body = BYTE_ORDER_MAGIC.to_le_bytes().to_vec();
        body.extend_from_slice(&[1, 0, 0, 0]);
        body.extend_from_slice(&[0xff; 8]);
        block(BLOCK_SECTION, &body)
    }

    fn interface(link: u16) -> Vec<u8> {
        let mut body = link.to_le_bytes().to_vec();
        body.extend_from_slice(&[0, 0, 0, 0, 8, 0]);
        block(BLOCK_INTERFACE, &body)
    }

    fn process(pid: u32, name: &str) -> Vec<u8> {
        let mut body = pid.to_le_bytes().to_vec();
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        block(BLOCK_PROCESS, &body)
    }

    fn option(code: u16, value: u32) -> Vec<u8> {
        let mut o = code.to_le_bytes().to_vec();
        o.extend_from_slice(&4u16.to_le_bytes());
        o.extend_from_slice(&value.to_le_bytes());
        o
    }

    fn packet(iface: u32, frame: &[u8], opts: &[(u16, u32)]) -> Vec<u8> {
        let mut body = iface.to_le_bytes().to_vec();
        body.extend_from_slice(&[0; 8]); // timestamp
        body.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        body.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        body.extend_from_slice(frame);
        body.resize(body.len().next_multiple_of(4), 0);
        for (code, value) in opts {
            body.extend(option(*code, *value));
        }
        body.extend_from_slice(&[0; 4]); // end of options
        block(BLOCK_PACKET, &body)
    }

    fn ipv4(proto: u8, dst: [u8; 4], transport: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0, 192, 168, 1, 44];
        p.extend_from_slice(&dst);
        p.extend_from_slice(transport);
        p
    }

    fn tcp(dport: u16, flags: u8) -> Vec<u8> {
        let mut t = vec![0xc0, 0x01];
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0; 8]);
        t.push(0x50); // header length: five 32-bit words
        t.push(flags);
        t.extend_from_slice(&[0; 6]);
        t
    }

    fn ethernet(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(payload);
        f
    }

    fn loopback(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![2, 0, 0, 0];
        f.extend_from_slice(payload);
        f
    }

    const OUT: (u16, u32) = (OPT_FLAGS, 2);
    const IN: (u16, u32) = (OPT_FLAGS, 1);
    const SYN: u8 = 0x02;

    fn sent(pid: u32, ip: &str, port: u16, proto: Proto) -> Seen {
        Seen::Sent { pid, ip: ip.parse().expect("ip"), port, proto }
    }

    #[test]
    fn ties_connections_to_processes() {
        let mut data = section();
        data.extend(interface(LINK_NULL));
        data.extend(process(4018, "agent"));
        data.extend(packet(0, &loopback(&ipv4(6, [127, 0, 0, 1], &tcp(28194, SYN))), &[(OPT_PROCESS, 0), OUT]));
        // The same packet as it arrives: no sender, not reported twice.
        data.extend(packet(0, &loopback(&ipv4(6, [127, 0, 0, 1], &tcp(28194, SYN))), &[IN]));
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(68355, "gh"));
        data.extend(packet(1, &ethernet(&ipv4(6, [20, 205, 243, 168], &tcp(443, SYN))), &[(OPT_PROCESS, 1), OUT]));
        // The reply (SYN+ACK) and later packets are not new connections.
        data.extend(packet(1, &ethernet(&ipv4(6, [192, 168, 1, 44], &tcp(49884, 0x12))), &[(OPT_PROCESS, 1), IN]));
        data.extend(packet(1, &ethernet(&ipv4(6, [20, 205, 243, 168], &tcp(443, 0x10))), &[(OPT_PROCESS, 1), OUT]));
        // A datagram.
        let mut udp = vec![0xc0, 0x02, 0x01, 0xbb, 0, 8, 0, 0];
        udp.extend_from_slice(b"quic");
        data.extend(packet(1, &ethernet(&ipv4(17, [142, 250, 1, 1], &udp)), &[(OPT_PROCESS, 1), OUT]));

        let seen = Capture::new().push(&data);
        assert_eq!(
            seen,
            [
                sent(4018, "127.0.0.1", 28194, Proto::Tcp),
                sent(68355, "20.205.243.168", 443, Proto::Tcp),
                sent(68355, "142.250.1.1", 443, Proto::Udp),
            ]
        );
    }

    #[test]
    fn the_effective_process_is_the_one_that_counts() {
        let mut data = section();
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(247, "mDNSResponder"));
        data.extend(process(68355, "gh"));
        let frame = ethernet(&ipv4(6, [1, 2, 3, 4], &tcp(853, SYN)));
        data.extend(packet(0, &frame, &[(OPT_PROCESS, 0), (OPT_EFFECTIVE_PROCESS, 1), OUT]));
        assert_eq!(Capture::new().push(&data), [sent(68355, "1.2.3.4", 853, Proto::Tcp)]);
    }

    #[test]
    fn reads_name_lookups_and_ipv6() {
        // A reply for example.com with one address, from port 53.
        let mut dns_msg = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        dns_msg.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        dns_msg.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
        let mut udp = vec![0, 53, 0xc0, 0x03];
        udp.extend_from_slice(&((8 + dns_msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&dns_msg);

        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 6, 64];
        v6.extend_from_slice(&[0; 16]);
        v6.extend_from_slice(&"2606:4700::1".parse::<Ipv6Addr>().expect("v6").octets());
        v6.extend_from_slice(&tcp(443, SYN));
        let mut v6_frame = vec![0; 12];
        v6_frame.extend_from_slice(&[0x86, 0xdd]);
        v6_frame.extend_from_slice(&v6);

        let mut data = section();
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(9, "curl"));
        data.extend(packet(0, &ethernet(&ipv4(17, [192, 168, 1, 44], &udp)), &[(OPT_PROCESS, 0), IN]));
        data.extend(packet(0, &v6_frame, &[(OPT_PROCESS, 0), OUT]));
        assert_eq!(
            Capture::new().push(&data),
            [
                Seen::Resolved { name: "example.com".into(), addrs: vec!["93.184.215.14".parse().expect("ip")] },
                sent(9, "2606:4700::1", 443, Proto::Tcp),
            ]
        );
    }

    #[test]
    fn works_whatever_way_the_bytes_are_cut_up() {
        let mut data = section();
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(7, "nc"));
        for port in [80, 443, 8080] {
            data.extend(packet(0, &ethernet(&ipv4(6, [9, 9, 9, 9], &tcp(port, SYN))), &[(OPT_PROCESS, 0), OUT]));
        }
        let whole = Capture::new().push(&data);
        assert_eq!(whole.len(), 3);
        for chunk in [1, 3, 7, 64] {
            let mut c = Capture::new();
            let pieces: Vec<Seen> = data.chunks(chunk).flat_map(|piece| c.push(piece)).collect();
            assert_eq!(pieces, whole, "in pieces of {chunk}");
        }
    }

    #[test]
    fn packets_without_a_known_sender_are_ignored() {
        let frame = ethernet(&ipv4(6, [9, 9, 9, 9], &tcp(443, SYN)));
        let mut data = section();
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(0, "kernel_task"));
        data.extend(packet(0, &frame, &[OUT])); // no process at all
        data.extend(packet(0, &frame, &[(OPT_PROCESS, 0), OUT])); // the kernel
        data.extend(packet(0, &frame, &[(OPT_PROCESS, 5), OUT])); // no such process block
        data.extend(packet(3, &frame, &[(OPT_PROCESS, 0), OUT])); // no such interface
        data.extend(packet(0, &frame, &[(OPT_PROCESS, 0)])); // direction unknown
        assert!(Capture::new().push(&data).is_empty());
    }

    #[test]
    fn damaged_input_never_panics() {
        let mut data = section();
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(7, "nc"));
        data.extend(packet(0, &ethernet(&ipv4(6, [9, 9, 9, 9], &tcp(443, SYN))), &[(OPT_PROCESS, 0), OUT]));
        for len in 0..data.len() {
            let _ = Capture::new().push(&data[..len]);
        }
        for i in 0..data.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut bad = data.clone();
                bad[i] ^= flip;
                let mut c = Capture::new();
                let _ = c.push(&bad);
                let _ = c.push(&data);
            }
        }
        // A nonsense length stops the parser for good instead of misreading.
        let mut c = Capture::new();
        assert!(c.push(&[6, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]).is_empty());
        assert!(c.push(&data).is_empty());
    }

    #[test]
    fn matcher_passes_on_only_our_processes_with_names() {
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        let mut m = Matcher::new();
        m.seen(Seen::Resolved { name: "example.com".into(), addrs: vec![ip("93.184.215.14")] }, 0);
        m.seen(sent(50, "93.184.215.14", 443, Proto::Tcp), 10);
        m.seen(sent(99, "8.8.8.8", 443, Proto::Tcp), 11); // someone else's
        // Nothing is ours yet: the sandbox reports have not caught up.
        assert!(m.ready(20, false, |_| false).is_empty());
        let events = m.ready(30, false, |pid| pid == 50);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 50);
        assert_eq!(events[0].ts, 10);
        assert_eq!(
            events[0].what,
            What::Connect {
                peer: Peer::Ip { ip: ip("93.184.215.14"), port: 443, proto: Proto::Tcp },
                name: Some("example.com".into())
            }
        );
        // The other one is dropped once it has waited long enough.
        assert!(m.ready(11 + WAIT_MS, false, |pid| pid == 50).is_empty());
        assert!(m.waiting.is_empty());
    }

    /// A ClientHello carrying `name`, with `filler` bytes of other
    /// extensions before the name.
    fn client_hello(name: &str, filler: usize) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x2b]); // some other extension first
        ext.extend_from_slice(&(filler as u16).to_be_bytes());
        ext.extend(std::iter::repeat_n(0u8, filler));
        let n = name.len() as u16;
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(n + 5).to_be_bytes());
        ext.extend_from_slice(&(n + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&n.to_be_bytes());
        ext.extend_from_slice(name.as_bytes());

        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[7; 32]);
        hello.push(0); // no session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[1, 0]); // one compression method
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend(ext);

        let mut out = vec![22, 3, 1];
        out.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
        out.push(1);
        out.extend_from_slice(&[0, (hello.len() >> 8) as u8, hello.len() as u8]);
        out.extend(hello);
        out
    }

    #[test]
    fn reads_the_server_name_of_a_tls_session() {
        assert_eq!(server_name(&client_hello("Example.COM", 0)).as_deref(), Some("example.com"));
        assert_eq!(server_name(&client_hello("api.github.com", 300)).as_deref(), Some("api.github.com"));
        // Not a host name.
        assert_eq!(server_name(&client_hello("bad\x1bname", 0)), None);
        // Not a ClientHello.
        assert_eq!(server_name(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(server_name(&[]), None);
        // Cut anywhere, or damaged anywhere, it answers without panicking.
        let hello = client_hello("example.com", 40);
        for len in 0..hello.len() {
            let _ = server_name(&hello[..len]);
        }
        for i in 0..hello.len() {
            let mut bad = hello.clone();
            bad[i] ^= 0xff;
            let _ = server_name(&bad);
        }
    }

    #[test]
    fn a_tls_opening_names_the_address_it_goes_to() {
        let mut segment = tcp(443, 0x18); // PSH+ACK, not a new connection
        segment.extend(client_hello("example.com", 0));
        let mut data = section();
        data.extend(interface(LINK_ETHERNET));
        data.extend(process(9, "curl"));
        data.extend(packet(0, &ethernet(&ipv4(6, [172, 66, 147, 243], &tcp(443, SYN))), &[(OPT_PROCESS, 0), OUT]));
        data.extend(packet(0, &ethernet(&ipv4(6, [172, 66, 147, 243], &segment)), &[(OPT_PROCESS, 0), OUT]));
        let seen = Capture::new().push(&data);
        assert_eq!(
            seen,
            [
                sent(9, "172.66.147.243", 443, Proto::Tcp),
                Seen::Resolved { name: "example.com".into(), addrs: vec!["172.66.147.243".parse().expect("ip")] },
            ]
        );

        // The connection waits a moment for that name, but not forever.
        let mut m = Matcher::new();
        let mut seen = seen.into_iter();
        m.seen(seen.next().expect("syn"), 1000);
        assert!(m.ready(1010, false, |_| true).is_empty(), "held for its name");
        m.seen(seen.next().expect("hello"), 1030);
        let events = m.ready(1040, false, |_| true);
        assert!(matches!(&events[0].what, What::Connect { name: Some(n), .. } if n == "example.com"));

        let mut m = Matcher::new();
        m.seen(sent(9, "10.0.0.1", 22, Proto::Tcp), 1000);
        assert!(m.ready(1100, false, |_| true).is_empty());
        assert_eq!(m.ready(1000 + NAME_MS, false, |_| true).len(), 1, "given up waiting for a name");
        m.seen(sent(9, "10.0.0.2", 22, Proto::Tcp), 5000);
        assert_eq!(m.ready(5001, true, |_| true).len(), 1, "the final call holds nothing back");
    }

    #[test]
    fn matcher_reports_a_stream_of_datagrams_once_per_window() {
        let mut m = Matcher::new();
        for t in [0, 100, 200, REPEAT_MS + 300] {
            m.seen(sent(7, "142.250.1.1", 443, Proto::Udp), t);
        }
        let times: Vec<u64> = m.ready(REPEAT_MS + 400, false, |_| true).iter().map(|e| e.ts).collect();
        assert_eq!(times, [0, REPEAT_MS + 300]);
    }

    /// Run against a real capture when one is at hand:
    /// `CEYNOX_WATCH_PCAPNG=/tmp/cw.pcapng cargo test real_capture -- --nocapture`
    #[test]
    fn real_capture() {
        let Some(path) = std::env::var_os("CEYNOX_WATCH_PCAPNG") else {
            return;
        };
        let data = std::fs::read(path).expect("readable capture");
        let seen = Capture::new().push(&data);
        for s in &seen {
            println!("{s:?}");
        }
        assert!(!seen.is_empty());
    }
}
