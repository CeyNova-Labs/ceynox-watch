//! Comparing one run with another.
//!
//! A [`Baseline`] is what a run did, reduced to the parts that should be the
//! same next time: which programs ran, which hosts were contacted, what in
//! the catalog was touched and where files were written. Process ids,
//! timestamps, temporary names and counts are left out, so two runs of the
//! same install compare equal and a baseline can live in a repository.
//!
//! The comparison is one-sided on purpose. What matters is what a run did
//! that the earlier one did not; things that stopped happening are counted
//! and nothing more.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    classify::Classifier,
    event::{Event, Peer, Proto, What},
    render::{self, Style},
    report::{Report, Subject},
};

/// The only format there is so far.
const FORMAT: u32 = 1;

/// No baseline file is anywhere near this size; more is not read.
const MAX_BASELINE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// Marks the file as a baseline and says which format it is in.
    #[serde(rename = "ceynox-watch-baseline")]
    pub format: u32,
    /// What was watched. For people; not compared.
    pub command: String,
    /// Programs run, with the package they ran for: `node [npm:esbuild]`.
    pub programs: BTreeSet<String>,
    /// Hosts contacted, by name where one was seen: `registry.npmjs.org:443`.
    pub destinations: BTreeSet<String>,
    /// Catalog findings: `read ~/.npmrc (npm token) by npm`.
    pub flagged: BTreeSet<String>,
    /// Areas files were written in: `./node_modules`, `~/.npm`.
    pub writes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Program,
    Destination,
    Flagged,
    Writes,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Destination => "destination",
            Self::Flagged => "flagged",
            Self::Writes => "writes to",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// What this run did that the baseline did not.
    pub new: Vec<(Kind, String)>,
    /// How many things in the baseline this run did not do.
    pub gone: usize,
}

/// A peer in the form two runs can agree on: by name when there is one,
/// since the addresses behind a name change from day to day.
fn destination(peer: &Peer, name: Option<&str>) -> String {
    match peer {
        Peer::Ip { ip, port, proto } => {
            let host = match (name, ip) {
                (Some(name), _) => name.trim_end_matches('.').to_ascii_lowercase(),
                (None, std::net::IpAddr::V4(a)) => a.to_string(),
                (None, std::net::IpAddr::V6(a)) => format!("[{a}]"),
            };
            match proto {
                Proto::Tcp => format!("{host}:{port}"),
                Proto::Udp => format!("{host}:{port}/udp"),
                Proto::Other => format!("{host}:{port}/raw"),
            }
        }
        Peer::Unix { path } => format!("unix:{path}"),
        Peer::Port { port } => format!("port {port}"),
    }
}

/// Temporary directories get a new name every run; only that something was
/// written there is comparable.
fn stable_area(area: &str) -> String {
    for temp in
        ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm", "/var/folders", "/private/var/folders"]
    {
        if area.strip_prefix(temp).is_some_and(|rest| rest.starts_with('/')) {
            return temp.trim_start_matches("/private").to_string();
        }
    }
    area.to_string()
}

impl Baseline {
    /// Reduce a finished run. `style.base` decides which paths are shown
    /// as `./...`, so it should be the directory the command started in.
    pub fn of(report: &Report, command: &str, style: &Style) -> Self {
        let mut b = Self { format: FORMAT, command: render::clean(command), ..Self::default() };
        for (i, p) in report.procs.iter().enumerate() {
            if p.execed {
                b.programs.insert(render::who(report, i));
            }
        }
        for rec in report.peers.iter().filter(|r| !r.background || r.finding.is_some()) {
            b.destinations.insert(render::clean(&destination(&rec.peer, rec.name.as_deref())));
        }
        for f in &report.findings {
            let (verb, subject) = match &f.subject {
                Subject::File { path, write: false } => ("read", render::show_path(report, style, path)),
                Subject::File { path, write: true } => ("wrote", render::show_path(report, style, path)),
                Subject::Peer(peer) => ("contacted", render::clean(&destination(peer, report.peer_name(peer)))),
            };
            b.flagged.insert(format!("{verb} {subject} ({}) by {}", f.finding.what, render::who(report, f.proc)));
        }
        for (area, _) in render::areas(report, style, &report.written) {
            b.writes.insert(stable_area(&area));
        }
        b
    }

    /// What `self` has that `earlier` does not.
    pub fn since(&self, earlier: &Self) -> Diff {
        let mut diff = Diff::default();
        let sets = [
            (Kind::Flagged, &self.flagged, &earlier.flagged),
            (Kind::Destination, &self.destinations, &earlier.destinations),
            (Kind::Program, &self.programs, &earlier.programs),
            (Kind::Writes, &self.writes, &earlier.writes),
        ];
        for (kind, now, then) in sets {
            diff.new.extend(now.difference(then).map(|s| (kind, s.clone())));
            diff.gone += then.difference(now).count();
        }
        diff
    }

    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Read a baseline: either a file written with `--write-baseline`, or a
    /// recording written with `--json`, which is reduced the same way a
    /// live run is.
    ///
    /// `home` is the home directory the recorded command ran with.
    pub fn load(path: &Path, home: Option<String>) -> Result<Self, String> {
        let name = path.to_string_lossy();
        let file = File::open(path).map_err(|e| format!("cannot read {name}: {e}"))?;
        let mut reader = BufReader::new(file);
        let mut first = String::new();
        reader.read_line(&mut first).map_err(|e| format!("cannot read {name}: {e}"))?;

        if serde_json::from_str::<Event>(first.trim_end()).is_ok() {
            let (report, base) = replay(std::iter::once(Ok(first)).chain(reader.lines()), home);
            let style = Style { color: false, width: 100, base };
            return Ok(Self::of(&report, &name, &style));
        }
        let mut rest = String::new();
        reader.take(MAX_BASELINE_BYTES).read_to_string(&mut rest).map_err(|e| format!("cannot read {name}: {e}"))?;
        first.push_str(&rest);
        let baseline: Self = serde_json::from_str(&first)
            .map_err(|_| format!("{name} is neither a baseline (--write-baseline) nor a recording (--json)"))?;
        if baseline.format != FORMAT {
            return Err(format!(
                "{name} is a baseline in format {}, which this version does not read",
                baseline.format
            ));
        }
        Ok(baseline)
    }
}

/// Run a recording through a fresh report. Returns it with the directory
/// the recorded command started in, when the recording says. Lines that
/// are not events are skipped.
pub fn replay(lines: impl Iterator<Item = std::io::Result<String>>, home: Option<String>) -> (Report, Option<String>) {
    let mut report = Report::new(Classifier::new(home));
    let mut base = None;
    for line in lines.map_while(Result::ok) {
        let Ok(event) = serde_json::from_str::<Event>(line.trim_end()) else {
            continue;
        };
        if base.is_none()
            && let What::Exec { cwd: Some(cwd), .. } = &event.what
        {
            base = Some(cwd.clone());
        }
        report.ingest(&event);
    }
    (report, base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(pid: u32, ppid: u32, argv: &[&str], cwd: &str) -> Event {
        Event {
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
        }
    }
    fn open(pid: u32, path: &str, write: bool) -> Event {
        Event { ts: 1, pid, what: What::Open { path: path.into(), write, dir: false } }
    }
    fn tcp(pid: u32, ip: &str, name: Option<&str>) -> Event {
        let peer = Peer::Ip { ip: ip.parse().expect("ip"), port: 443, proto: Proto::Tcp };
        Event { ts: 2, pid, what: What::Connect { peer, name: name.map(str::to_string) } }
    }

    fn style() -> Style {
        Style { color: false, width: 100, base: Some("/home/sam/app".into()) }
    }

    /// An install. `pid` and `address` differ from run to run; `evil` adds
    /// a dependency whose install script misbehaves.
    fn run(pid: u32, address: &str, tmp: &str, evil: bool) -> Baseline {
        let mut r = Report::new(Classifier::new(None));
        let mut events = vec![
            exec(pid, 1, &["npm", "ci"], "/home/sam/app"),
            open(pid, "/home/sam/.npmrc", false),
            tcp(pid, address, Some("registry.npmjs.org")),
            open(pid, "/home/sam/app/node_modules/a/index.js", true),
            open(pid, &format!("/tmp/{tmp}/x"), true),
        ];
        if evil {
            events.extend([
                Event { ts: 3, pid: pid + 1, what: What::Fork { ppid: pid } },
                exec(pid + 1, pid, &["node", "post.js"], "/home/sam/app/node_modules/evil"),
                open(pid + 1, "/home/sam/.aws/credentials", false),
                tcp(pid + 1, "203.0.113.9", None),
                open(pid + 1, "/home/sam/.config/autostart/x.desktop", true),
            ]);
        }
        for e in &events {
            r.ingest(e);
        }
        Baseline::of(&r, "npm ci", &style())
    }

    #[test]
    fn two_runs_of_the_same_thing_compare_equal() {
        let a = run(100, "104.16.2.35", "npm-abc", false);
        let b = run(7311, "104.16.9.99", "npm-xyz", false);
        assert_eq!(a, b);
        assert_eq!(b.since(&a), Diff::default());
        assert_eq!(a.programs, BTreeSet::from(["npm".to_string()]));
        assert_eq!(a.destinations, BTreeSet::from(["registry.npmjs.org:443".to_string()]));
        assert_eq!(a.flagged, BTreeSet::from(["read ~/.npmrc (npm token) by npm".to_string()]));
        assert_eq!(a.writes, BTreeSet::from(["./node_modules".to_string(), "/tmp".to_string()]));
    }

    #[test]
    fn what_is_new_is_listed_and_what_is_gone_is_counted() {
        let before = run(100, "104.16.2.35", "a", false);
        let after = run(200, "104.16.2.35", "b", true);
        let diff = after.since(&before);
        let new: Vec<(Kind, &str)> = diff.new.iter().map(|(k, s)| (*k, s.as_str())).collect();
        assert_eq!(
            new,
            [
                (Kind::Flagged, "read ~/.aws/credentials (AWS credentials) by node [npm:evil]"),
                (Kind::Flagged, "wrote ~/.config/autostart/x.desktop (desktop autostart entry) by node [npm:evil]"),
                (Kind::Destination, "203.0.113.9:443"),
                (Kind::Program, "node [npm:evil]"),
                (Kind::Writes, "~/.config"),
            ]
        );
        assert_eq!(diff.gone, 0);
        // The other way round nothing is new, and five things are gone.
        let back = before.since(&after);
        assert!(back.new.is_empty());
        assert_eq!(back.gone, 5);
    }

    #[test]
    fn a_baseline_survives_being_written_and_read() {
        let b = run(1, "104.16.2.35", "t", true);
        let text = b.to_json();
        assert!(text.starts_with("{\n  \"ceynox-watch-baseline\": 1,"));
        assert_eq!(serde_json::from_str::<Baseline>(&text).expect("parses"), b);
        assert!(serde_json::from_str::<Baseline>("{\"ceynox-watch-baseline\":1,\"surprise\":true}").is_err());
    }

    #[test]
    fn destinations_and_areas_are_made_comparable() {
        let ip = |s: &str, port, proto| Peer::Ip { ip: s.parse().expect("ip"), port, proto };
        assert_eq!(destination(&ip("1.2.3.4", 443, Proto::Tcp), Some("Example.COM.")), "example.com:443");
        assert_eq!(destination(&ip("1.2.3.4", 53, Proto::Udp), None), "1.2.3.4:53/udp");
        assert_eq!(destination(&ip("2606:4700::1", 443, Proto::Tcp), None), "[2606:4700::1]:443");
        assert_eq!(destination(&Peer::Unix { path: "/run/docker.sock".into() }, None), "unix:/run/docker.sock");
        assert_eq!(destination(&Peer::Port { port: 443 }, None), "port 443");
        assert_eq!(stable_area("/tmp/pip-install-x7"), "/tmp");
        assert_eq!(stable_area("/private/var/folders/zz"), "/var/folders");
        assert_eq!(stable_area("/tmpfiles/x"), "/tmpfiles/x");
        assert_eq!(stable_area("~/.npm"), "~/.npm");
    }
}
