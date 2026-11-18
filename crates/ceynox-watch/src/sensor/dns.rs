//! Reads DNS replies off the wire so that connections can be shown by name
//! ("registry.npmjs.org") and not only by address.
//!
//! The input is network data, written by whoever answered the query. The
//! parser therefore assumes nothing: every offset is bounds-checked, name
//! compression is followed a limited number of times, and names are only
//! accepted if they are made of ordinary host-name characters.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const MAX_ANSWERS: usize = 64;
const MAX_JUMPS: usize = 16;
const MAX_NAME: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The name that was asked for, lower-cased, without a trailing dot.
    pub name: String,
    /// The addresses it resolved to (through any CNAME chain).
    pub addrs: Vec<IpAddr>,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

/// The UDP payload of an IP packet, if it is UDP sent from port 53.
pub fn dns_payload(packet: &[u8]) -> Option<&[u8]> {
    let udp = match packet.first()? >> 4 {
        4 => {
            if *packet.get(9)? != 17 {
                return None;
            }
            // A fragment other than the first has no UDP header.
            if u16_at(packet, 6)? & 0x1fff != 0 {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 {
                return None;
            }
            packet.get(header..)?
        }
        6 => {
            // Next header directly UDP; packets with extension headers are skipped.
            if *packet.get(6)? != 17 {
                return None;
            }
            packet.get(40..)?
        }
        _ => return None,
    };
    if u16_at(udp, 0)? != 53 {
        return None;
    }
    udp.get(8..)
}

/// Read the domain name at `pos`. Returns the name and the offset just past
/// it in the original sequence (not past any compression target).
fn name_at(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut after = None;
    let mut jumps = 0;
    loop {
        let len = usize::from(*msg.get(pos)?);
        match len {
            0 => {
                pos += 1;
                break;
            }
            // A pointer to an earlier occurrence of the rest of the name.
            l if l & 0xc0 == 0xc0 => {
                let target = usize::from(u16_at(msg, pos)? & 0x3fff);
                after.get_or_insert(pos + 2);
                jumps += 1;
                // Pointers must go backwards, which also rules out loops.
                if jumps > MAX_JUMPS || target >= pos {
                    return None;
                }
                pos = target;
            }
            l if l & 0xc0 != 0 => return None,
            l => {
                let label = msg.get(pos + 1..pos + 1 + l)?;
                if !label.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_') {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|c| char::from(c.to_ascii_lowercase())));
                if name.len() > MAX_NAME {
                    return None;
                }
                pos += 1 + l;
            }
        }
    }
    Some((name, after.unwrap_or(pos)))
}

/// Parse a DNS message. `Some` only for a successful reply to a single
/// question that carries at least one address.
pub fn parse_reply(msg: &[u8]) -> Option<Reply> {
    let flags = u16_at(msg, 2)?;
    let is_reply = flags & 0x8000 != 0;
    let failed = flags & 0x000f != 0;
    if !is_reply || failed || u16_at(msg, 4)? != 1 {
        return None;
    }
    let answers = usize::from(u16_at(msg, 6)?).min(MAX_ANSWERS);
    let (name, mut pos) = name_at(msg, 12)?;
    if name.is_empty() {
        return None;
    }
    pos = pos.checked_add(4)?; // question type and class

    let mut addrs = Vec::new();
    for _ in 0..answers {
        let (_, next) = name_at(msg, pos)?;
        let kind = u16_at(msg, next)?;
        let len = usize::from(u16_at(msg, next + 8)?);
        let data = msg.get(next + 10..next + 10 + len)?;
        match (kind, data.len()) {
            (TYPE_A, 4) => addrs.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (TYPE_AAAA, 16) => {
                let bytes: [u8; 16] = data.try_into().ok()?;
                addrs.push(IpAddr::V6(Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
        pos = next + 10 + len;
    }
    (!addrs.is_empty()).then_some(Reply { name, addrs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in name.split('.') {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    /// A reply to `question` with the given (type, rdata) answers, each
    /// answer's name being a pointer to the question.
    fn reply(question: &str, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend(labels(question));
        m.extend_from_slice(&[0, 1, 0, 1]);
        for (kind, data) in answers {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&kind.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            m.extend_from_slice(&(data.len() as u16).to_be_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    #[test]
    fn reads_addresses_through_a_cname() {
        let cname = labels("cdn.example.net");
        let v6 = "2606:4700::6810:1".parse::<Ipv6Addr>().expect("v6").octets();
        let msg = reply("Registry.NPMjs.org", &[(5, &cname), (TYPE_A, &[104, 16, 2, 35]), (TYPE_AAAA, &v6)]);
        assert_eq!(
            parse_reply(&msg),
            Some(Reply {
                name: "registry.npmjs.org".into(),
                addrs: vec!["104.16.2.35".parse().expect("ip"), "2606:4700::6810:1".parse().expect("ip")],
            })
        );
    }

    #[test]
    fn ignores_what_is_not_a_useful_reply() {
        let ok = reply("example.com", &[(TYPE_A, &[1, 2, 3, 4])]);
        assert!(parse_reply(&ok).is_some());

        let mut query = ok.clone();
        query[2] &= 0x7f; // not a reply
        assert_eq!(parse_reply(&query), None);

        let mut nxdomain = ok.clone();
        nxdomain[3] |= 3;
        assert_eq!(parse_reply(&nxdomain), None);

        assert_eq!(parse_reply(&reply("example.com", &[])), None);
        assert_eq!(parse_reply(&reply("example.com", &[(16, b"\x03txt")])), None);
        // A name with characters no host name has.
        assert_eq!(parse_reply(&reply("exa\x1bmple.com", &[(TYPE_A, &[1, 2, 3, 4])])), None);
    }

    #[test]
    fn rejects_pointer_loops_and_forward_pointers() {
        let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 12]); // question name points at itself
        m.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_reply(&m), None);

        let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 40]); // points forward
        m.extend_from_slice(&[0; 40]);
        assert_eq!(parse_reply(&m), None);
    }

    #[test]
    fn never_panics_on_damaged_input() {
        let v4: &[u8] = &[9, 9, 9, 9];
        let msg = reply("a.very.long.example.org", &[(5, &labels("x.example.org")), (TYPE_A, v4)]);
        for len in 0..msg.len() {
            let _ = parse_reply(&msg[..len]);
        }
        for i in 0..msg.len() {
            for flip in [0x01, 0x40, 0x80, 0xff] {
                let mut bad = msg.clone();
                bad[i] ^= flip;
                let _ = parse_reply(&bad);
            }
        }
    }

    #[test]
    fn finds_the_dns_payload_in_ip_packets() {
        let dns = reply("example.com", &[(TYPE_A, &[1, 2, 3, 4])]);
        let udp = |sport: u16| {
            let mut u = sport.to_be_bytes().to_vec();
            u.extend_from_slice(&[0x30, 0x39]);
            u.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
            u.extend_from_slice(&[0, 0]);
            u.extend_from_slice(&dns);
            u
        };
        let mut v4 = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        v4.extend(udp(53));
        assert_eq!(dns_payload(&v4), Some(&dns[..]));

        let mut options = vec![0x46, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 1, 1, 1];
        options.extend(udp(53));
        assert_eq!(dns_payload(&options), Some(&dns[..]));

        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        v6.extend_from_slice(&[0; 32]);
        v6.extend(udp(53));
        assert_eq!(dns_payload(&v6), Some(&dns[..]));

        let mut other_port = v4[..20].to_vec();
        other_port.extend(udp(5353));
        assert_eq!(dns_payload(&other_port), None);

        let mut tcp = v4.clone();
        tcp[9] = 6;
        assert_eq!(dns_payload(&tcp), None);

        let mut fragment = v4.clone();
        fragment[7] = 8;
        assert_eq!(dns_payload(&fragment), None);

        assert_eq!(dns_payload(&[]), None);
        assert_eq!(dns_payload(&v4[..22]), None);
    }
}
