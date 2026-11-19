//! Text output: the live lines and the closing summary.
//!
//! Everything a watched process controls (paths, arguments, socket names) is
//! passed through [`clean`] before it reaches the terminal, so a file name
//! containing escape sequences cannot move the cursor, recolor text or
//! otherwise forge what this tool prints.

use std::{collections::HashMap, fmt::Write as _, net::IpAddr};

use crate::{
    baseline::Diff,
    classify::Finding,
    event::{Peer, Proto},
    report::{Exit, Line, LineKind, NOTABLE_SENT, PeerRec, Report, Subject},
};

#[derive(Debug, Clone)]
pub struct Style {
    pub color: bool,
    /// Terminal width in columns.
    pub width: usize,
    /// Directory shown as `.`: where the watched command was started.
    pub base: Option<String>,
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[1;31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";

impl Style {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.color { format!("{code}{text}{RESET}") } else { text.to_string() }
    }
}

/// Replace characters that a terminal would act on rather than display.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            // C0 and C1 control codes, DEL, and the bidi/format characters
            // that can reorder or hide what follows.
            c if c.is_control() => '\u{fffd}',
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}' => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// Cut to `max` characters, marking the cut.
fn fit(text: &str, max: usize) -> String {
    if max == 0 || text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

pub fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, d) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(d);
    }
    out
}

/// `1 thing`, `2 things`.
pub fn count(n: usize, one: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{} {one}s", thousands(n)) }
}

/// A byte count for people: `812 B`, `4.2 kB`, `1.3 GB`.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 999.95 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

pub fn duration(ms: u64) -> String {
    match ms {
        0..1000 => format!("{ms}ms"),
        1000..60_000 => format!("{:.1}s", ms as f64 / 1000.0),
        _ => format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1000),
    }
}

/// A path as shown: relative to the starting directory or to home when it
/// is inside one of them.
pub fn show_path(report: &Report, style: &Style, path: &str) -> String {
    if let Some(base) = &style.base
        && let Some(rest) = path.strip_prefix(base.as_str())
    {
        if rest.is_empty() {
            return ".".into();
        }
        if let Some(rest) = rest.strip_prefix('/') {
            return clean(&format!("./{rest}"));
        }
    }
    match report.classifier.home_relative(path) {
        Some(rest) => clean(&format!("~/{rest}")),
        None => clean(path),
    }
}

fn service(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "ssh",
        53 => "dns",
        80 => "http",
        123 => "ntp",
        443 => "https",
        853 => "dns-over-tls",
        3306 => "mysql",
        5353 => "mdns",
        5432 => "postgres",
        6379 => "redis",
        9418 => "git",
        27017 => "mongodb",
        _ => return None,
    })
}

fn locality(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(a) if a.is_loopback() => Some("this machine"),
        IpAddr::V4(a) if a.is_private() || a.is_link_local() => Some("local network"),
        IpAddr::V6(a) if a.is_loopback() => Some("this machine"),
        IpAddr::V6(a) if a.is_unique_local() || a.is_unicast_link_local() => Some("local network"),
        _ => None,
    }
}

pub fn show_peer(peer: &Peer, name: Option<&str>) -> String {
    match peer {
        Peer::Ip { ip, port, proto } => {
            let addr = match (name, ip) {
                (Some(name), _) => format!("{}:{port} ({ip})", clean(name)),
                (None, IpAddr::V4(a)) => format!("{a}:{port}"),
                (None, IpAddr::V6(a)) => format!("[{a}]:{port}"),
            };
            let proto = match proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
                Proto::Other => "raw",
            };
            let mut notes = vec![proto];
            notes.extend(service(*port));
            notes.extend(locality(ip));
            format!("{addr}  {}", notes.join(", "))
        }
        Peer::Unix { path } => format!("unix:{}", clean(path)),
        Peer::Port { port } => match service(*port) {
            Some(name) => format!("port {port}  {name}, address not visible"),
            None => format!("port {port}  address not visible"),
        },
    }
}

pub fn who(report: &Report, proc: usize) -> String {
    let name = clean(report.procs[proc].name());
    match report.package(proc) {
        Some(pkg) => format!("{name} [{}]", clean(&pkg)),
        None => name,
    }
}

fn flag(style: &Style, finding: &Finding) -> String {
    style.paint(YELLOW, &format!("{} ({})", finding.what, finding.category.as_str()))
}

/// One line of live output, or `None` when this line is not shown at the
/// current verbosity.
pub fn live(report: &Report, line: &Line, start: u64, style: &Style, verbose: bool) -> Option<String> {
    let t = line.ts.saturating_sub(start);
    let time = style.paint(DIM, &format!("{:>4}.{:03}s", t / 1000, t % 1000));
    // Columns after the time and tag.
    let room = style.width.saturating_sub(22).max(30);
    let body = match &line.kind {
        LineKind::Exec { depth } => {
            let i = line.proc?;
            let indent = "  ".repeat((*depth).min(8));
            let pkg = report.package(i).map(|p| format!("  [{}]", clean(&p))).unwrap_or_default();
            let cmd = fit(&clean(&report.procs[i].command()), room.saturating_sub(indent.len() + pkg.chars().count()));
            format!("{}  {indent}{cmd}{}", style.paint(CYAN, "exec "), style.paint(DIM, &pkg))
        }
        LineKind::Net { peer, name, finding, background } => {
            if *background && !verbose {
                return None;
            }
            let by = style.paint(DIM, &format!("  {}", who(report, line.proc?)));
            let peer = show_peer(peer, name.as_deref());
            match finding {
                Some(f) => format!("{}  {peer}  {}{by}", style.paint(RED, "NET  "), flag(style, f)),
                None => format!("{}  {peer}{by}", style.paint(GREEN, "net  ")),
            }
        }
        LineKind::Sent { peer, name, bytes } => {
            let by = style.paint(DIM, &format!("  {}", who(report, line.proc?)));
            let to = show_peer(peer, name.as_deref());
            format!("{}  {} to {to}{by}", style.paint(YELLOW, "sent "), style.paint(BOLD, &size(*bytes)))
        }
        LineKind::File { path, write, finding } => {
            let by = style.paint(DIM, &format!("  {}", who(report, line.proc?)));
            let path = show_path(report, style, path);
            match (finding, write) {
                (Some(f), false) => format!("{}  {path}  {}{by}", style.paint(RED, "READ "), flag(style, f)),
                (Some(f), true) => format!("{}  {path}  {}{by}", style.paint(RED, "WRITE"), flag(style, f)),
                (None, _) if !verbose => return None,
                (None, false) => format!("{}  {path}{by}", style.paint(DIM, "read "), by = by),
                (None, true) => format!("write  {path}{by}"),
            }
        }
        LineKind::Lost { count } => style.paint(
            YELLOW,
            &format!(
                "lost   {} events were dropped: the machine produced them faster than they could be read",
                thousands(*count as usize)
            ),
        ),
    };
    Some(format!("{time}  {body}"))
}

/// What was watched, for the summary's first line.
#[derive(Debug, Clone)]
pub struct Header {
    pub title: String,
    pub elapsed_ms: u64,
    pub exit: Option<Exit>,
}

/// Group files by the directory area they are in, largest first.
pub fn areas(report: &Report, style: &Style, paths: &std::collections::HashSet<String>) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for path in paths {
        let shown = show_path(report, style, path);
        // `./a/b/c` and `~/a/b/c` group by one component, `/a/b/c` by two,
        // and the kernel's own trees (`/proc/1234/...`) as a whole.
        let kernel = ["/proc/", "/sys/", "/dev/"].iter().any(|p| shown.starts_with(p));
        let keep = if !shown.starts_with('/') || kernel { 2 } else { 3 };
        let parts: Vec<&str> = shown.split('/').collect();
        let area = if parts.len() > keep { parts[..keep].join("/") } else { shown.clone() };
        *counts.entry(area).or_default() += 1;
    }
    let mut out: Vec<(String, usize)> = counts.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

fn list(items: &[(String, usize)], max: usize) -> String {
    let mut out: Vec<String> = items.iter().take(max).map(|(name, n)| format!("{name} ({})", thousands(*n))).collect();
    if items.len() > max {
        out.push(format!("+{} more", items.len() - max));
    }
    out.join("  ")
}

fn peer_line(report: &Report, style: &Style, rec: &PeerRec) -> String {
    let times = if rec.count > 1 { format!("  ×{}", thousands(rec.count as usize)) } else { String::new() };
    let by: Vec<String> = rec.by.iter().map(|n| clean(n)).collect();
    let pkg = report.package(rec.first_by).map(|p| format!(" [{}]", clean(&p))).unwrap_or_default();
    let mut line = format!("   {}{}", show_peer(&rec.peer, rec.name.as_deref()), style.paint(DIM, &times));
    if rec.closed > 0 {
        // A large upload is worth the eye; the rest is context.
        let up = format!("↑{}", size(rec.sent));
        let up = if rec.sent >= NOTABLE_SENT { style.paint(YELLOW, &up) } else { up };
        let _ = write!(line, "  {up} ↓{}", size(rec.received));
    }
    if let Some(f) = &rec.finding {
        let _ = write!(line, "  {}", flag(style, f));
    }
    let _ = write!(line, "{}", style.paint(DIM, &format!("  {}{pkg}", by.join(", "))));
    line
}

/// One entry under "worth a look": a flagged thing, and who did it.
#[derive(Debug, Clone)]
pub struct Group {
    /// `read `, `wrote` or `net  `, padded to one width.
    pub verb: &'static str,
    pub subject: String,
    pub finding: Finding,
    /// The process and how it came to run, with its package if it has one.
    pub by: String,
    pub times: usize,
}

/// The findings, grouped. The same thing done by the same kind of process
/// (a loop, a parallel build) is one entry with a count. Within one
/// package, the same thing done by any of its processes is one entry too:
/// which of a build's steps did it matters less than whose build.
pub fn finding_groups(report: &Report, style: &Style) -> Vec<Group> {
    let mut groups: Vec<(String, Group)> = Vec::new();
    for f in &report.findings {
        let (verb, subject) = match &f.subject {
            Subject::File { path, write: false } => ("read ", show_path(report, style, path)),
            Subject::File { path, write: true } => ("wrote", show_path(report, style, path)),
            Subject::Peer(peer) => ("net  ", show_peer(peer, report.peer_name(peer))),
        };
        let chain: Vec<String> = report.ancestry(f.proc).take(5).map(|p| fit(&clean(&p.command()), 48)).collect();
        let pkg = report.package(f.proc).map(|p| format!("  [{}]", clean(&p))).unwrap_or_default();
        let by = format!("{}{pkg}", chain.join(" ← "));
        let key = if pkg.is_empty() { by.clone() } else { pkg };
        let same = |(k, g): &&mut (String, Group)| {
            *k == key && g.verb == verb && g.subject == subject && g.finding == f.finding
        };
        match groups.iter_mut().find(same) {
            Some((_, group)) => group.times += 1,
            None => groups.push((key, Group { verb, subject, finding: f.finding, by, times: 1 })),
        }
    }
    groups.into_iter().map(|(_, g)| g).collect()
}

/// What this run did that the one it is compared with did not.
pub fn changes(diff: &Diff, against: &str, style: &Style) -> String {
    let mut out = String::new();
    let against = fit(&clean(against), 48);
    if diff.new.is_empty() {
        let _ = writeln!(out, "\n {}", style.paint(GREEN, &format!("Nothing new since {against}.")));
    } else {
        let _ = writeln!(out, "\n {}  {}", style.paint(RED, &format!("NEW SINCE {against}")), diff.new.len());
        for (kind, what) in diff.new.iter().take(60) {
            let _ = writeln!(out, "   {}  {}", style.paint(YELLOW, &format!("{:<11}", kind.label())), clean(what));
        }
        if diff.new.len() > 60 {
            let _ = writeln!(out, "   +{} more", diff.new.len() - 60);
        }
    }
    if diff.gone > 0 {
        let _ =
            writeln!(out, "   {}", style.paint(DIM, &format!("{} seen then, not seen now", count(diff.gone, "thing"))));
    }
    out
}

pub fn summary(report: &Report, header: &Header, style: &Style) -> String {
    let mut out = String::new();
    let rule = "─".repeat(style.width.clamp(40, 78).saturating_sub(16));
    let _ = writeln!(out, "\n{}", style.paint(DIM, &format!("── ceynox-watch {rule}")));

    let mut top = format!(" {}  {}", style.paint(BOLD, &fit(&clean(&header.title), 60)), duration(header.elapsed_ms));
    match header.exit {
        Some(Exit::Code(0)) => top.push_str("  exit 0"),
        Some(Exit::Code(c)) => top.push_str(&style.paint(YELLOW, &format!("  exit {c}"))),
        Some(Exit::Signal(s)) => top.push_str(&style.paint(YELLOW, &format!("  killed by signal {s}"))),
        None => {}
    }
    let _ = writeln!(out, "{top}\n");

    // Processes.
    let started = report.started().count();
    let _ = writeln!(
        out,
        " {}  {} started, {} programs run",
        style.paint(BOLD, "PROCESSES"),
        thousands(started),
        thousands(report.execs as usize)
    );
    let programs: Vec<(String, usize)> = report.programs().into_iter().map(|(n, c)| (clean(&n), c)).collect();
    if !programs.is_empty() {
        let names: Vec<String> =
            programs.iter().take(10).map(|(n, c)| if *c > 1 { format!("{n} ×{c}") } else { n.clone() }).collect();
        let more = if programs.len() > 10 { format!("  +{} more", programs.len() - 10) } else { String::new() };
        let _ = writeln!(out, "   {}{more}", names.join("  "));
    }
    // Only meaningful where the sensor sees processes end.
    let running = if report.exits_seen { report.still_running() } else { Vec::new() };
    if !running.is_empty() && header.exit.is_some() {
        let who: Vec<String> = running.iter().take(5).map(|p| format!("{} (pid {})", clean(p.name()), p.pid)).collect();
        let more = if running.len() > 5 { format!(" and {} more", running.len() - 5) } else { String::new() };
        let _ = writeln!(
            out,
            "   {}",
            style.paint(YELLOW, &format!("still running after the command exited: {}{more}", who.join(", ")))
        );
    }

    // Network.
    let mut peers: Vec<&PeerRec> = report.peers.iter().filter(|p| !p.background).collect();
    let _ = writeln!(out, "\n {}  {} destinations", style.paint(BOLD, "NETWORK"), peers.len());
    peers.sort_by_key(|p| p.finding.is_none());
    for rec in peers.iter().take(25) {
        let _ = writeln!(out, "{}", peer_line(report, style, rec));
    }
    if peers.len() > 25 {
        let _ = writeln!(out, "   +{} more", peers.len() - 25);
    }

    // Files.
    let _ = writeln!(
        out,
        "\n {}  {} read, {} written",
        style.paint(BOLD, "FILES"),
        thousands(report.read.len()),
        thousands(report.written.len())
    );
    if !report.written.is_empty() {
        let _ = writeln!(out, "   written  {}", list(&areas(report, style, &report.written), 6));
    }
    if !report.read.is_empty() {
        let _ = writeln!(out, "   read     {}", list(&areas(report, style, &report.read), 6));
    }

    // Findings.
    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "\n {}",
            style.paint(GREEN, "Nothing touched the credential, browser, history or startup locations in the catalog.")
        );
    } else {
        let groups = finding_groups(report, style);
        let _ = writeln!(out, "\n {}  {}", style.paint(RED, "WORTH A LOOK"), groups.len());
        for g in groups.iter().take(40) {
            let times = if g.times > 1 { style.paint(DIM, &format!("  ×{}", g.times)) } else { String::new() };
            let head = format!("   {}  {}  {}", style.paint(RED, g.verb), g.subject, flag(style, &g.finding));
            let _ = writeln!(out, "{head}{times}");
            let _ = writeln!(out, "          {}", style.paint(DIM, &g.by));
        }
        if groups.len() > 40 {
            let _ = writeln!(out, "   +{} more", groups.len() - 40);
        }
    }

    if report.lost > 0 {
        let _ = writeln!(
            out,
            "\n {}",
            style.paint(
                YELLOW,
                &format!(
                    "{} events were dropped, so this record is incomplete. Try --buffer-mb with a larger value.",
                    thousands(report.lost as usize)
                )
            )
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        classify::Classifier,
        event::{Event, What},
    };

    fn plain() -> Style {
        Style { color: false, width: 100, base: Some("/home/sam/app".into()) }
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(clean("a\x1b[2Jb"), "a\u{fffd}[2Jb");
        assert_eq!(clean("line1\nline2\tx"), "line1 line2 x");
        assert_eq!(clean("\u{9b}31m"), "\u{fffd}31m");
        assert_eq!(clean("abc\u{202e}cba"), "abc\u{fffd}cba");
        assert_eq!(clean("naïve/日本語"), "naïve/日本語");
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(duration(950), "950ms");
        assert_eq!(duration(14_230), "14.2s");
        assert_eq!(duration(125_000), "2m05s");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(size(0), "0 B");
        assert_eq!(size(812), "812 B");
        assert_eq!(size(999), "999 B");
        assert_eq!(size(1000), "1.0 kB");
        assert_eq!(size(4_200), "4.2 kB");
        assert_eq!(size(999_949), "999.9 kB");
        assert_eq!(size(999_950), "1.0 MB");
        assert_eq!(size(4_200_000), "4.2 MB");
        assert_eq!(size(1_300_000_000), "1.3 GB");
        assert_eq!(fit("abc", 4), "abc");
    }

    #[test]
    fn paths_are_shown_relative_to_base_and_home() {
        let r = Report::new(Classifier::new(None));
        let s = plain();
        assert_eq!(show_path(&r, &s, "/home/sam/app/node_modules/x/a.js"), "./node_modules/x/a.js");
        assert_eq!(show_path(&r, &s, "/home/sam/app"), ".");
        assert_eq!(show_path(&r, &s, "/home/sam/application/x"), "~/application/x");
        assert_eq!(show_path(&r, &s, "/home/sam/.aws/credentials"), "~/.aws/credentials");
        assert_eq!(show_path(&r, &s, "/etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn peers_are_described() {
        let ip = |s: &str, port, proto| Peer::Ip { ip: s.parse().expect("ip"), port, proto };
        assert_eq!(show_peer(&ip("104.16.2.35", 443, Proto::Tcp), None), "104.16.2.35:443  tcp, https");
        assert_eq!(
            show_peer(&ip("104.16.2.35", 443, Proto::Tcp), Some("registry.npmjs.org")),
            "registry.npmjs.org:443 (104.16.2.35)  tcp, https"
        );
        assert_eq!(show_peer(&ip("127.0.0.53", 53, Proto::Udp), None), "127.0.0.53:53  udp, dns, this machine");
        assert_eq!(show_peer(&ip("2606:4700::1", 8443, Proto::Tcp), None), "[2606:4700::1]:8443  tcp");
        assert_eq!(show_peer(&Peer::Port { port: 443 }, None), "port 443  https, address not visible");
        assert_eq!(show_peer(&Peer::Port { port: 8443 }, None), "port 8443  address not visible");
        assert_eq!(show_peer(&Peer::Unix { path: "/run/x\x1b[0m".into() }, None), "unix:/run/x\u{fffd}[0m");
    }

    #[test]
    fn summary_of_a_small_run() {
        let mut r = Report::new(Classifier::new(None));
        let exec = |pid, ppid, argv: &[&str], cwd: &str| Event {
            ts: 0,
            pid,
            what: What::Exec {
                ppid,
                uid: 1000,
                exe: format!("/usr/bin/{}", argv[0]),
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: Some(cwd.into()),
                existing: false,
            },
        };
        let open =
            |pid, path: &str, write| Event { ts: 5, pid, what: What::Open { path: path.into(), write, dir: false } };
        let mut lines = Vec::new();
        for ev in [
            exec(10, 1, &["npm", "install"], "/home/sam/app"),
            Event { ts: 1, pid: 11, what: What::Fork { ppid: 10 } },
            exec(11, 10, &["node", "post.js"], "/home/sam/app/node_modules/evil"),
            open(11, "/home/sam/.aws/credentials", false),
            open(11, "/home/sam/app/node_modules/evil/post.js", false),
            open(11, "/home/sam/app/node_modules/evil/out.bin", true),
            Event {
                ts: 9,
                pid: 11,
                what: What::Connect {
                    peer: Peer::Ip { ip: "203.0.113.9".parse().expect("ip"), port: 443, proto: Proto::Tcp },
                    name: Some("updates.example.net".into()),
                },
            },
        ] {
            lines.extend(r.ingest(&ev));
        }
        let s = plain();
        let live: Vec<String> = lines.iter().filter_map(|l| live(&r, l, 0, &s, false)).collect();
        assert_eq!(
            live,
            [
                "   0.000s  exec   npm install",
                "   0.000s  exec     node post.js  [npm:evil]",
                "   0.005s  READ   ~/.aws/credentials  AWS credentials (credentials)  node [npm:evil]",
                "   0.009s  net    updates.example.net:443 (203.0.113.9)  tcp, https  node [npm:evil]",
            ]
        );

        let text =
            summary(&r, &Header { title: "npm install".into(), elapsed_ms: 1500, exit: Some(Exit::Code(0)) }, &s);
        for expected in [
            " npm install  1.5s  exit 0",
            " PROCESSES  2 started, 2 programs run",
            "   node  npm",
            " NETWORK  1 destinations",
            "   updates.example.net:443 (203.0.113.9)  tcp, https  node [npm:evil]",
            " FILES  2 read, 1 written",
            "   written  ./node_modules (1)",
            "   read     ./node_modules (1)  ~/.aws (1)",
            " WORTH A LOOK  1",
            "   read   ~/.aws/credentials  AWS credentials (credentials)",
            "          node post.js ← npm install  [npm:evil]",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }
}
