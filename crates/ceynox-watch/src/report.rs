//! Turns the event stream into what gets shown: a process table, the set of
//! network peers and files touched, and the findings worth a second look.
//!
//! [`Report::ingest`] takes one event and returns the lines it adds to the
//! live view. At the end, the same `Report` is the summary.

use std::collections::{HashMap, HashSet};

use crate::{
    classify::{Classifier, Finding, is_background},
    event::{Event, Peer, What},
};

/// Distinct paths remembered per kind. Past this, opens are still counted
/// and still checked against the catalog, but no longer de-duplicated.
const MAX_PATHS: usize = 400_000;

#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: u32,
    /// Index of the parent in [`Report::procs`], when it is known.
    pub parent: Option<usize>,
    pub exe: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// Was running before watching began.
    pub existing: bool,
    /// Has run a program of its own (as opposed to a fork still running its
    /// parent's).
    pub execed: bool,
    pub exit: Option<Exit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl Proc {
    /// Short name: the program as it was called (`sh`, not the `dash` it
    /// may resolve to), without its directory.
    pub fn name(&self) -> &str {
        let called = match self.argv.first() {
            Some(first) if !first.is_empty() => first,
            _ if !self.exe.is_empty() => &self.exe,
            _ => "?",
        };
        called.rsplit('/').next().unwrap_or(called)
    }

    /// The command line as typed, more or less.
    pub fn command(&self) -> String {
        if self.argv.is_empty() {
            // A process that was only ever seen acting, never starting.
            return if self.exe.is_empty() { "(unidentified process)".into() } else { self.exe.clone() };
        }
        let mut out = String::new();
        for (i, arg) in self.argv.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            // The program is shown by name; a full path adds only noise.
            // So does the long path of a script deep in some package
            // directory: its last two components say what it is.
            let shortened;
            let arg = if i == 0 {
                arg.rsplit('/').next().unwrap_or(arg)
            } else if arg.starts_with('/') && arg.len() > 48 && !arg.contains(' ') {
                let mut tail = arg.rsplitn(3, '/');
                let (file, dir) = (tail.next().unwrap_or(""), tail.next().unwrap_or(""));
                shortened = format!("…/{dir}/{file}");
                &shortened
            } else {
                arg
            };
            if arg.is_empty() || arg.contains([' ', '\t', '\n', '"', '\'']) {
                out.push('\'');
                out.push_str(&arg.replace('\n', "\\n"));
                out.push('\'');
            } else {
                out.push_str(arg);
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct PeerRec {
    pub peer: Peer,
    /// Host name the address was looked up by, if that was seen.
    pub name: Option<String>,
    /// Local plumbing, shown only in verbose output.
    pub background: bool,
    pub count: u64,
    /// Index of the first process seen talking to it.
    pub first_by: usize,
    /// Names of every program that talked to it.
    pub by: Vec<String>,
    pub finding: Option<Finding>,
    /// Connections seen to close, and the data that went each way over
    /// them. Stays zero where the sensor cannot measure it.
    pub closed: u64,
    pub sent: u64,
    pub received: u64,
}

#[derive(Debug, Clone)]
pub struct FindingRec {
    pub proc: usize,
    pub finding: Finding,
    pub subject: Subject,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Subject {
    File { path: String, write: bool },
    Peer(Peer),
}

/// One line of the live view.
#[derive(Debug, Clone)]
pub struct Line {
    pub ts: u64,
    pub proc: Option<usize>,
    pub kind: LineKind,
}

#[derive(Debug, Clone)]
pub enum LineKind {
    /// A program was started. `depth` is its distance from the root.
    Exec {
        depth: usize,
    },
    /// First contact with a peer.
    Net {
        peer: Peer,
        name: Option<String>,
        finding: Option<Finding>,
        background: bool,
    },
    /// A file was opened. Lines without a finding are for verbose output.
    File {
        path: String,
        write: bool,
        finding: Option<Finding>,
    },
    /// A connection closed after carrying a noteworthy amount out.
    Sent {
        peer: Peer,
        name: Option<String>,
        bytes: u64,
    },
    Lost {
        count: u64,
    },
}

/// A closed connection gets a line of its own from this much data sent.
/// Below it, the amounts only appear in the summary.
pub const NOTABLE_SENT: u64 = 100_000;

#[derive(Debug)]
pub struct Report {
    pub classifier: Classifier,
    /// Every process seen, in order of appearance. Never shrinks, so
    /// indexes stay valid when a pid is reused.
    pub procs: Vec<Proc>,
    current: HashMap<u32, usize>,
    pub peers: Vec<PeerRec>,
    peer_index: HashMap<Peer, usize>,
    pub read: HashSet<String>,
    pub written: HashSet<String>,
    /// Opens beyond [`MAX_PATHS`] distinct paths.
    pub uncounted_opens: u64,
    pub findings: Vec<FindingRec>,
    finding_seen: HashSet<(usize, Subject)>,
    pub lost: u64,
    /// Whether any process was seen to exit. Some sensors cannot see that.
    pub exits_seen: bool,
    pub first_ts: Option<u64>,
    pub last_ts: u64,
    pub execs: u64,
}

impl Report {
    pub fn new(classifier: Classifier) -> Self {
        Self {
            classifier,
            procs: Vec::new(),
            current: HashMap::new(),
            peers: Vec::new(),
            peer_index: HashMap::new(),
            read: HashSet::new(),
            written: HashSet::new(),
            uncounted_opens: 0,
            findings: Vec::new(),
            finding_seen: HashSet::new(),
            lost: 0,
            exits_seen: false,
            first_ts: None,
            last_ts: 0,
            execs: 0,
        }
    }

    /// Index of the process currently holding `pid`, creating a placeholder
    /// for one we never saw start.
    fn proc_index(&mut self, pid: u32) -> usize {
        if let Some(&i) = self.current.get(&pid) {
            return i;
        }
        self.procs.push(Proc {
            pid,
            parent: None,
            exe: String::new(),
            argv: Vec::new(),
            cwd: None,
            existing: true,
            execed: false,
            exit: None,
        });
        let i = self.procs.len() - 1;
        self.current.insert(pid, i);
        i
    }

    /// Distance from `proc` to the top of its known ancestry.
    pub fn depth(&self, proc: usize) -> usize {
        self.ancestry(proc).count() - 1
    }

    /// `proc`, its parent, its grandparent...
    pub fn ancestry(&self, proc: usize) -> impl Iterator<Item = &Proc> {
        let mut next = Some(proc);
        let mut hops = 0;
        std::iter::from_fn(move || {
            let p = self.procs.get(next?)?;
            hops += 1;
            // A cycle cannot happen (parents are always older), but a bound
            // costs nothing.
            next = if hops < 64 { p.parent } else { None };
            Some(p)
        })
    }

    /// The package whose install script or build this process belongs to,
    /// judged from where it runs. Children inherit their parent's.
    pub fn package(&self, proc: usize) -> Option<String> {
        self.ancestry(proc).find_map(package_of)
    }

    pub fn ingest(&mut self, ev: &Event) -> Vec<Line> {
        self.first_ts.get_or_insert(ev.ts);
        self.last_ts = self.last_ts.max(ev.ts);
        let mut lines = Vec::new();
        match &ev.what {
            What::Fork { ppid } => {
                let parent = self.current.get(ppid).copied();
                let inherited = parent.map(|i| self.procs[i].clone());
                self.procs.push(Proc {
                    pid: ev.pid,
                    parent,
                    exe: inherited.as_ref().map(|p| p.exe.clone()).unwrap_or_default(),
                    argv: inherited.as_ref().map(|p| p.argv.clone()).unwrap_or_default(),
                    cwd: inherited.and_then(|p| p.cwd),
                    existing: false,
                    execed: false,
                    exit: None,
                });
                self.current.insert(ev.pid, self.procs.len() - 1);
            }
            What::Exec { ppid, exe, argv, cwd, existing, .. } => {
                let i = self.proc_index(ev.pid);
                if self.procs[i].parent.is_none() {
                    self.procs[i].parent = self.current.get(ppid).copied().filter(|&p| p != i);
                }
                let p = &mut self.procs[i];
                p.exe.clone_from(exe);
                p.argv.clone_from(argv);
                if cwd.is_some() {
                    p.cwd.clone_from(cwd);
                }
                p.existing = *existing;
                if !existing {
                    p.execed = true;
                    self.execs += 1;
                    lines.push(Line { ts: ev.ts, proc: Some(i), kind: LineKind::Exec { depth: self.depth(i) } });
                }
            }
            What::Exit { code, signal } => {
                self.exits_seen = true;
                if let Some(i) = self.current.remove(&ev.pid) {
                    self.procs[i].exit = match (code, signal) {
                        (_, Some(s)) => Some(Exit::Signal(*s)),
                        (Some(c), None) => Some(Exit::Code(*c)),
                        (None, None) => None,
                    };
                }
            }
            What::Open { path, write, dir } => {
                let i = self.proc_index(ev.pid);
                let finding = self.classifier.open(path, *write);
                if !dir {
                    let set = if *write { &mut self.written } else { &mut self.read };
                    if set.len() < MAX_PATHS {
                        set.insert(path.clone());
                    } else if !set.contains(path) {
                        self.uncounted_opens += 1;
                    }
                }
                let subject = Subject::File { path: path.clone(), write: *write };
                let fresh = finding.is_none() || self.note_finding(i, finding, &subject);
                // A finding is shown once per process; other opens every time
                // (only verbose output shows them at all).
                if fresh && !(*dir && finding.is_none()) {
                    lines.push(Line {
                        ts: ev.ts,
                        proc: Some(i),
                        kind: LineKind::File { path: path.clone(), write: *write, finding },
                    });
                }
            }
            What::Connect { peer, name: host } => {
                let i = self.proc_index(ev.pid);
                let name = self.procs[i].name().to_string();
                let mut finding = self.classifier.peer(peer, host.as_deref());
                let background = finding.is_none() && is_background(peer);
                let first = match self.peer_index.get(peer) {
                    Some(&p) => {
                        let rec = &mut self.peers[p];
                        rec.count += 1;
                        if rec.name.is_none() {
                            rec.name.clone_from(host);
                        }
                        // A name learned late can turn an ordinary peer
                        // into a flagged one; an earlier finding stands.
                        match rec.finding {
                            Some(earlier) => finding = Some(earlier),
                            None => rec.finding = finding,
                        }
                        if !rec.by.contains(&name) {
                            rec.by.push(name);
                        }
                        false
                    }
                    None => {
                        self.peer_index.insert(peer.clone(), self.peers.len());
                        self.peers.push(PeerRec {
                            peer: peer.clone(),
                            name: host.clone(),
                            background,
                            count: 1,
                            first_by: i,
                            by: vec![name],
                            finding,
                            closed: 0,
                            sent: 0,
                            received: 0,
                        });
                        true
                    }
                };
                let fresh = self.note_finding(i, finding, &Subject::Peer(peer.clone()));
                if first || fresh {
                    lines.push(Line {
                        ts: ev.ts,
                        proc: Some(i),
                        kind: LineKind::Net { peer: peer.clone(), name: host.clone(), finding, background },
                    });
                }
            }
            What::Close { peer, sent, received } => {
                // Only connections whose start was seen are counted.
                if let Some(&p) = self.peer_index.get(peer) {
                    let i = self.proc_index(ev.pid);
                    let rec = &mut self.peers[p];
                    rec.closed += 1;
                    rec.sent += sent;
                    rec.received += received;
                    if *sent >= NOTABLE_SENT {
                        let kind = LineKind::Sent { peer: peer.clone(), name: rec.name.clone(), bytes: *sent };
                        lines.push(Line { ts: ev.ts, proc: Some(i), kind });
                    }
                }
            }
            What::Lost { count } => {
                self.lost += count;
                lines.push(Line { ts: ev.ts, proc: None, kind: LineKind::Lost { count: *count } });
            }
        }
        lines
    }

    /// Record a finding. `true` when this process had not triggered it yet.
    fn note_finding(&mut self, proc: usize, finding: Option<Finding>, subject: &Subject) -> bool {
        let Some(finding) = finding else {
            return false;
        };
        if !self.finding_seen.insert((proc, subject.clone())) {
            return false;
        }
        self.findings.push(FindingRec { proc, finding, subject: subject.clone() });
        true
    }

    /// The host name a peer was looked up by, if it was seen.
    pub fn peer_name(&self, peer: &Peer) -> Option<&str> {
        self.peers.get(*self.peer_index.get(peer)?)?.name.as_deref()
    }

    /// Processes that started while watching.
    pub fn started(&self) -> impl Iterator<Item = &Proc> {
        self.procs.iter().filter(|p| !p.existing)
    }

    /// How many times each program was run, most frequent first.
    pub fn programs(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for p in self.procs.iter().filter(|p| p.execed) {
            *counts.entry(p.name()).or_default() += 1;
        }
        let mut out: Vec<(String, usize)> = counts.into_iter().map(|(n, c)| (n.to_string(), c)).collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    /// Processes known and not seen to exit.
    pub fn alive(&self) -> usize {
        self.current.len()
    }

    /// Started while watching and not seen to exit, oldest first.
    pub fn still_running(&self) -> Vec<&Proc> {
        let mut left: Vec<usize> = self.current.values().copied().filter(|&i| !self.procs[i].existing).collect();
        left.sort_unstable();
        left.into_iter().map(|i| &self.procs[i]).collect()
    }
}

/// The package a process's working directory or program path points at.
fn package_of(p: &Proc) -> Option<String> {
    if let Some(cwd) = &p.cwd {
        // npm, pnpm, yarn: install scripts run in the package's directory.
        if let Some((_, rest)) = cwd.rsplit_once("/node_modules/") {
            let mut parts = rest.split('/');
            let first = parts.next().filter(|s| !s.is_empty() && !s.starts_with('.'))?;
            let name = match (first.starts_with('@'), parts.next()) {
                (true, Some(second)) => format!("{first}/{second}"),
                (true, None) => return None,
                (false, _) => first.to_string(),
            };
            return Some(format!("npm:{name}"));
        }
        // pip building a source distribution: /tmp/pip-install-x/<name>_<hash>
        if let Some(at) = cwd.find("/pip-install-") {
            let name = cwd[at + 1..].split('/').nth(1)?;
            let name = name.rsplit_once('_').map_or(name, |(n, _)| n);
            if !name.is_empty() {
                return Some(format!("pypi:{name}"));
            }
        }
        // pip running a package's build (its setup.py, or another build
        // backend) through its hook runner, in the package's directory.
        if p.argv.iter().any(|a| a.contains("/pyproject_hooks/")) {
            let dir = cwd.rsplit('/').next().unwrap_or(cwd);
            // An unpacked archive gets a throwaway directory name.
            let name = if dir.starts_with("pip-req-build-") || dir.is_empty() { "a package being built" } else { dir };
            return Some(format!("pypi:{name}"));
        }
    }
    // cargo build scripts: target/<profile>/build/<crate>-<hash>/build-script-build
    if let Some(dir) = p.exe.strip_suffix("/build-script-build")
        && let Some((before, krate)) = dir.rsplit_once('/')
        && before.ends_with("/build")
    {
        let name = krate.rsplit_once('-').map_or(krate, |(n, _)| n);
        return Some(format!("crate:{name}"));
    }
    run_from_registry(&p.argv)
}

/// A package fetched and run in one go: `npx <package>`, `uvx <package>`
/// and their relatives. This is how AI agents start most MCP servers, and
/// what was asked for is on the command line. The label is the runner and
/// the name as given, which is not always the name of the package that
/// provides it (`npx tsc` runs the `typescript` package).
fn run_from_registry(argv: &[String]) -> Option<String> {
    // The runner is the program, or a script handed to an interpreter
    // (`node /usr/bin/npx`, `env node /usr/bin/npx`).
    let first = argv.first()?.rsplit('/').next()?;
    let behind = match first {
        "env" => 2,
        "node" | "bun" | "sh" | "bash" | "python" | "python3" => 1,
        _ => 0,
    };
    runner_at(argv, 0).or_else(|| if behind > 0 { runner_at(argv, behind) } else { None })
}

/// [`run_from_registry`] with the runner expected at `argv[skip]`.
fn runner_at(argv: &[String], skip: usize) -> Option<String> {
    let runner = argv.get(skip)?.rsplit('/').next()?.to_string();
    let mut rest = argv[skip + 1..].iter().map(String::as_str).peekable();
    // Runners that are a subcommand of something else.
    let (label, python) = match runner.as_str() {
        "npx" => ("npx", false),
        "bunx" => ("bunx", false),
        "uvx" => ("uvx", true),
        "npm" if matches!(rest.peek(), Some(&"exec" | &"x")) => ("npx", false),
        "bun" if rest.peek() == Some(&"x") => ("bunx", false),
        "pnpm" if rest.peek() == Some(&"dlx") => ("pnpm", false),
        "yarn" if rest.peek() == Some(&"dlx") => ("yarn", false),
        "pipx" if rest.peek() == Some(&"run") => ("pipx", true),
        "uv" if rest.peek() == Some(&"tool") => {
            rest.next();
            if rest.peek() != Some(&"run") {
                return None;
            }
            ("uvx", true)
        }
        _ => return None,
    };
    if !matches!(runner.as_str(), "npx" | "bunx" | "uvx") {
        rest.next();
    }
    let mut named = None;
    let mut found = None;
    while let Some(arg) = rest.next() {
        match arg {
            "--" => {
                found = rest.next();
                break;
            }
            // Options that name the package outright.
            "-p" | "--package" | "--from" | "--spec" if !(python && arg == "-p") => named = named.or(rest.next()),
            // A command line to run, not a package.
            "-c" | "--call" => return named.and_then(|n| registry_name(label, n, python)),
            // Options that take a value.
            "--with" | "--python" | "-p" | "--index" | "--index-url" | "--registry" | "--prefix" | "--cache" => {
                rest.next();
            }
            _ if arg.starts_with("--package=") || arg.starts_with("--from=") => {
                named = named.or(arg.split_once('=').map(|(_, v)| v));
            }
            _ if arg.starts_with('-') => {}
            _ => {
                found = Some(arg);
                break;
            }
        }
    }
    registry_name(label, named.or(found)?, python)
}

/// `runner:name`, with the version and extras cut off. `None` for what is
/// not a registry name: a path, a URL.
fn registry_name(label: &str, spec: &str, python: bool) -> Option<String> {
    if spec.starts_with(['.', '/', '~']) || spec.contains("://") || spec.contains(':') {
        return None;
    }
    let name = if python {
        spec.split(['=', '<', '>', '!', '~', '[', '@']).next()?
    } else {
        match spec.char_indices().skip(1).find(|(_, c)| *c == '@') {
            Some((at, _)) => &spec[..at],
            None => spec,
        }
    };
    let ok = !name.is_empty()
        && name.len() <= 214
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/' | '~'));
    ok.then(|| format!("{label}:{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Proto;

    fn exec(ts: u64, pid: u32, ppid: u32, argv: &[&str], cwd: &str) -> Event {
        Event {
            ts,
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
    fn fork(ts: u64, pid: u32, ppid: u32) -> Event {
        Event { ts, pid, what: What::Fork { ppid } }
    }
    fn open(ts: u64, pid: u32, path: &str, write: bool) -> Event {
        Event { ts, pid, what: What::Open { path: path.into(), write, dir: false } }
    }
    fn tcp(ts: u64, pid: u32, ip: &str) -> Event {
        let peer = Peer::Ip { ip: ip.parse().expect("ip"), port: 443, proto: Proto::Tcp };
        Event { ts, pid, what: What::Connect { peer, name: None } }
    }

    fn report() -> Report {
        Report::new(Classifier::new(None))
    }

    /// npm install whose dependency's postinstall reads a credential.
    fn scenario(r: &mut Report) -> Vec<Line> {
        let events = [
            exec(0, 10, 1, &["npm", "install"], "/home/sam/app"),
            tcp(5, 10, "104.16.2.35"),
            tcp(6, 10, "104.16.2.35"),
            fork(10, 11, 10),
            exec(11, 11, 10, &["sh", "-c", "node postinstall.js"], "/home/sam/app/node_modules/@evil/pkg"),
            fork(12, 12, 11),
            exec(13, 12, 11, &["node", "postinstall.js"], "/home/sam/app/node_modules/@evil/pkg"),
            open(14, 12, "/home/sam/app/node_modules/@evil/pkg/postinstall.js", false),
            open(15, 12, "/home/sam/.aws/credentials", false),
            open(16, 12, "/home/sam/.aws/credentials", false),
            tcp(17, 12, "203.0.113.9"),
            open(18, 12, "/home/sam/.bashrc", true),
            Event { ts: 19, pid: 12, what: What::Exit { code: Some(0), signal: None } },
            Event { ts: 20, pid: 11, what: What::Exit { code: Some(0), signal: None } },
            Event { ts: 30, pid: 10, what: What::Exit { code: Some(0), signal: None } },
        ];
        events.iter().flat_map(|e| r.ingest(e)).collect()
    }

    #[test]
    fn builds_the_process_tree() {
        let mut r = report();
        scenario(&mut r);
        assert_eq!(r.procs.len(), 3);
        assert_eq!(r.depth(0), 0);
        assert_eq!(r.depth(2), 2);
        let chain: Vec<String> = r.ancestry(2).map(Proc::command).collect();
        assert_eq!(chain, ["node postinstall.js", "sh -c 'node postinstall.js'", "npm install"]);
        assert!(r.still_running().is_empty());
        assert_eq!(r.procs[0].exit, Some(Exit::Code(0)));
        assert_eq!(r.programs(), [("node".to_string(), 1), ("npm".to_string(), 1), ("sh".to_string(), 1)]);
        let dash = Proc {
            exe: "/usr/bin/dash".into(),
            argv: vec!["sh".into(), "-c".into(), "x".into()],
            ..r.procs[0].clone()
        };
        assert_eq!(dash.name(), "sh");
    }

    #[test]
    fn attributes_install_scripts_to_their_package() {
        let mut r = report();
        scenario(&mut r);
        assert_eq!(r.package(0), None);
        assert_eq!(r.package(1).as_deref(), Some("npm:@evil/pkg"));
        assert_eq!(r.package(2).as_deref(), Some("npm:@evil/pkg"));
    }

    #[test]
    fn package_detection() {
        let p = |exe: &str, cwd: &str| Proc {
            pid: 1,
            parent: None,
            exe: exe.into(),
            argv: vec![],
            cwd: Some(cwd.into()),
            existing: false,
            execed: true,
            exit: None,
        };
        assert_eq!(package_of(&p("/usr/bin/node", "/a/node_modules/left-pad")).as_deref(), Some("npm:left-pad"));
        assert_eq!(
            package_of(&p("/usr/bin/node", "/a/node_modules/x/node_modules/esbuild/lib")).as_deref(),
            Some("npm:esbuild")
        );
        assert_eq!(package_of(&p("/usr/bin/node", "/a/node_modules/.bin")), None);
        assert_eq!(package_of(&p("/usr/bin/node", "/a/src")), None);
        assert_eq!(
            package_of(&p("/usr/bin/python3", "/tmp/pip-install-ab12/evil_pkg_0f3a9c")).as_deref(),
            Some("pypi:evil_pkg")
        );
        assert_eq!(
            package_of(&p("/w/target/debug/build/openssl-sys-1a2b3c/build-script-build", "/w")).as_deref(),
            Some("crate:openssl-sys")
        );
        let hook = |cwd: &str| Proc {
            argv: vec![
                "python3".into(),
                "/v/lib/python3.13/site-packages/pip/_vendor/pyproject_hooks/_in_process/_in_process.py".into(),
            ],
            ..p("/usr/bin/python3.13", cwd)
        };
        assert_eq!(package_of(&hook("/home/sam/sneaky-pip")).as_deref(), Some("pypi:sneaky-pip"));
        assert_eq!(package_of(&hook("/tmp/pip-req-build-x7k2")).as_deref(), Some("pypi:a package being built"));
        assert_eq!(package_of(&hook("/tmp/pip-install-ab12/evil_pkg_0f3a9c")).as_deref(), Some("pypi:evil_pkg"));
        assert_eq!(
            hook("/x").command(),
            "python3 …/_in_process/_in_process.py",
            "a long script path is shown by its last two components"
        );
    }

    #[test]
    fn packages_run_straight_from_a_registry() {
        let run = |argv: &[&str]| run_from_registry(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            run(&["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]).as_deref(),
            Some("npx:@modelcontextprotocol/server-filesystem")
        );
        assert_eq!(run(&["node", "/usr/local/bin/npx", "--yes", "cowsay@1.6.0", "hi"]).as_deref(), Some("npx:cowsay"));
        assert_eq!(run(&["/usr/bin/env", "node", "/usr/bin/npx", "cowsay"]).as_deref(), Some("npx:cowsay"));
        assert_eq!(run(&["npx", "-p", "typescript@5", "tsc", "--version"]).as_deref(), Some("npx:typescript"));
        assert_eq!(run(&["npx", "--package=typescript", "-c", "tsc -v"]).as_deref(), Some("npx:typescript"));
        assert_eq!(run(&["npx", "-c", "echo hi"]), None);
        assert_eq!(run(&["npm", "exec", "--", "cowsay", "hi"]).as_deref(), Some("npx:cowsay"));
        assert_eq!(run(&["npm", "install", "cowsay"]), None);
        assert_eq!(run(&["bunx", "cowsay"]).as_deref(), Some("bunx:cowsay"));
        assert_eq!(run(&["bun", "x", "cowsay"]).as_deref(), Some("bunx:cowsay"));
        assert_eq!(run(&["pnpm", "dlx", "create-vite@latest", "app"]).as_deref(), Some("pnpm:create-vite"));
        assert_eq!(run(&["yarn", "dlx", "cowsay"]).as_deref(), Some("yarn:cowsay"));
        assert_eq!(run(&["uvx", "mcp-server-git", "--repository", "."]).as_deref(), Some("uvx:mcp-server-git"));
        assert_eq!(run(&["uvx", "--from", "ruff==0.6.0", "ruff", "check"]).as_deref(), Some("uvx:ruff"));
        assert_eq!(run(&["uvx", "--python", "3.12", "ruff"]).as_deref(), Some("uvx:ruff"));
        assert_eq!(run(&["uv", "tool", "run", "ruff[fast]>=0.6"]).as_deref(), Some("uvx:ruff"));
        assert_eq!(run(&["uv", "tool", "install", "ruff"]), None);
        assert_eq!(run(&["pipx", "run", "--spec", "black==24.1", "black"]).as_deref(), Some("pipx:black"));
        // Not registry names: a local path, a URL, a host.
        assert_eq!(run(&["npx", "./local-tool"]), None);
        assert_eq!(run(&["npx", "https://example.com/x.tgz"]), None);
        assert_eq!(run(&["npx", "github:user/repo"]), None);
        // The word alone, somewhere in a command line, means nothing.
        assert_eq!(run(&["echo", "npx", "cowsay"]), None);
        assert_eq!(run(&["npx"]), None);
        assert_eq!(run(&[]), None);
    }

    #[test]
    fn a_package_installed_under_a_runner_keeps_its_own_name() {
        let mut r = report();
        r.ingest(&exec(0, 10, 1, &["npx", "-y", "some-server"], "/home/sam"));
        r.ingest(&fork(1, 11, 10));
        r.ingest(&exec(2, 11, 10, &["node", "install.js"], "/home/sam/.npm/_npx/ab12/node_modules/esbuild"));
        r.ingest(&fork(3, 12, 10));
        r.ingest(&exec(4, 12, 10, &["sh", "-c", "some-server"], "/home/sam"));
        assert_eq!(r.package(0).as_deref(), Some("npx:some-server"));
        assert_eq!(r.package(1).as_deref(), Some("npm:esbuild"));
        assert_eq!(r.package(2).as_deref(), Some("npx:some-server"));
    }

    #[test]
    fn findings_are_recorded_once_per_process() {
        let mut r = report();
        let lines = scenario(&mut r);
        let what: Vec<&str> = r.findings.iter().map(|f| f.finding.what).collect();
        assert_eq!(what, ["AWS credentials", "shell startup file"]);
        assert!(r.findings.iter().all(|f| f.proc == 2));
        let flagged = lines.iter().filter(|l| matches!(l.kind, LineKind::File { finding: Some(_), .. })).count();
        assert_eq!(flagged, 2);
    }

    #[test]
    fn peers_are_counted_and_announced_once() {
        let mut r = report();
        let lines = scenario(&mut r);
        assert_eq!(r.peers.len(), 2);
        assert_eq!(r.peers[0].count, 2);
        assert_eq!(r.peers[0].by, ["npm"]);
        assert_eq!(r.peers[1].by, ["node"]);
        assert_eq!(lines.iter().filter(|l| matches!(l.kind, LineKind::Net { .. })).count(), 2);
    }

    #[test]
    fn transfers_are_added_up_per_peer() {
        let mut r = report();
        let peer = Peer::Ip { ip: "203.0.113.9".parse().expect("ip"), port: 443, proto: Proto::Tcp };
        let close =
            |ts, sent, received| Event { ts, pid: 10, what: What::Close { peer: peer.clone(), sent, received } };
        r.ingest(&exec(0, 10, 1, &["curl"], "/"));
        // A close for a connection whose start was not seen is ignored.
        assert!(r.ingest(&close(1, 5_000_000, 0)).is_empty());
        r.ingest(&tcp(2, 10, "203.0.113.9"));
        assert!(r.ingest(&close(3, 900, 40_000)).is_empty(), "small uploads only show in the summary");
        let lines = r.ingest(&close(4, 4_200_000, 300));
        assert!(matches!(lines[0].kind, LineKind::Sent { bytes: 4_200_000, .. }));
        let rec = &r.peers[0];
        assert_eq!((rec.closed, rec.sent, rec.received), (2, 4_200_900, 40_300));
    }

    #[test]
    fn a_name_learned_later_can_flag_a_peer() {
        let mut r = report();
        let peer = Peer::Ip { ip: "203.0.113.9".parse().expect("ip"), port: 443, proto: Proto::Tcp };
        let connect = |ts, name: Option<&str>| Event {
            ts,
            pid: 10,
            what: What::Connect { peer: peer.clone(), name: name.map(str::to_string) },
        };
        r.ingest(&exec(0, 10, 1, &["node"], "/"));
        r.ingest(&connect(1, None));
        assert!(r.findings.is_empty());
        let lines = r.ingest(&connect(2, Some("abc.ngrok-free.app")));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].finding.what, "tunnelling service");
        assert_eq!(r.peer_name(&peer), Some("abc.ngrok-free.app"));
        assert!(matches!(&lines[0].kind, LineKind::Net { finding: Some(_), .. }));
        // Seen again without a name: still one finding, still flagged.
        r.ingest(&connect(3, None));
        assert_eq!(r.findings.len(), 1);
        assert!(r.peers[0].finding.is_some());
    }

    #[test]
    fn files_are_split_into_read_and_written() {
        let mut r = report();
        scenario(&mut r);
        assert_eq!(r.read.len(), 2);
        assert_eq!(r.written.len(), 1);
        assert!(r.written.contains("/home/sam/.bashrc"));
    }

    #[test]
    fn a_reused_pid_is_a_new_process() {
        let mut r = report();
        r.ingest(&exec(0, 5, 1, &["a"], "/"));
        r.ingest(&Event { ts: 1, pid: 5, what: What::Exit { code: None, signal: Some(9) } });
        r.ingest(&fork(2, 5, 1));
        r.ingest(&exec(3, 5, 1, &["b"], "/"));
        assert_eq!(r.procs.len(), 2);
        assert_eq!(r.procs[0].exit, Some(Exit::Signal(9)));
        assert_eq!(r.procs[1].name(), "b");
        assert_eq!(r.still_running().iter().map(|p| p.pid).collect::<Vec<_>>(), [5]);
    }

    #[test]
    fn activity_from_an_unseen_process_is_kept() {
        let mut r = report();
        let lines = r.ingest(&open(0, 77, "/home/sam/.ssh/id_ed25519", false));
        assert_eq!(lines.len(), 1);
        assert_eq!(r.procs[0].pid, 77);
        assert!(r.procs[0].existing);
        assert_eq!(r.findings.len(), 1);
    }
}
