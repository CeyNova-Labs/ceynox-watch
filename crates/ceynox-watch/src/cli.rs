//! Command-line parsing.

use std::ffi::OsString;

use lexopt::prelude::*;

use crate::sensor::Scope;

pub const USAGE: &str = "\
See what a command really does on your machine: every program it starts,
every host it talks to, and every credential it touches.

Usage:
  ceynox-watch [options] -- <command> [args...]   watch one command
  ceynox-watch [options] --pid <pid>[,<pid>...]   watch running processes
  ceynox-watch [options] --all                    watch the whole machine
  ceynox-watch [options] --view <file> [--follow] show a --json file, formatted
  ceynox-watch [options] --inspect <package>      install a package in a throwaway
                                                  container and watch that

Examples:
  ceynox-watch -- npm install
  ceynox-watch -- pip install -r requirements.txt
  ceynox-watch --pid $(pgrep -n claude)
  ceynox-watch --inspect npm:left-pad@1.3.0
  ceynox-watch --baseline install.json --fail-on new -- npm ci

Options:
  -q, --quiet          no live output, only the summary
  -v, --verbose        also show every file opened
      --no-summary     no summary at the end
      --json <file>    also write every event as JSON, one per line
                       (\"-\" for standard output, with --pid or --all)
      --report <file>  also write the run as a page to share: .html or .md
      --baseline <file>
                       say what this run did that an earlier one did not.
                       The file is a baseline, or a --json recording
      --write-baseline <file>
                       save what this run did, to compare later runs with
      --fail-on <what> exit with status 3 when the command itself succeeded
                       but something in the catalog was touched (flagged)
                       or something was not in the baseline (new)
      --against <package>
                       with --inspect: install this one too, and say what the
                       inspected one does that it does not
      --image <image>  with --inspect: the container image to install in
      --color <when>   auto, always or never [default: auto]
      --hosts          macOS: show addresses and host names of connections.
                       Asks sudo to run the system's tcpdump. (Linux always
                       shows them.)
      --buffer-mb <n>  Linux: kernel event buffer size [default: 16]
  -h, --help           show this help
  -V, --version        show the version

Run it as yourself. On Linux it asks sudo for the part that needs root; on
macOS it needs none. Your command always runs as you.

ceynox-watch shows what happened. CeyNox Security stops it:
https://ceynovahq.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub quiet: bool,
    pub verbose: bool,
    pub summary: bool,
    pub json: Option<OsString>,
    pub color: Color,
    pub buffer_mb: u32,
    pub hosts: bool,
    pub report: Option<OsString>,
    pub baseline: Option<OsString>,
    pub write_baseline: Option<OsString>,
    pub fail_on_flagged: bool,
    pub fail_on_new: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            quiet: false,
            verbose: false,
            summary: true,
            json: None,
            color: Color::Auto,
            buffer_mb: 16,
            hosts: false,
            report: None,
            baseline: None,
            write_baseline: None,
            fail_on_flagged: false,
            fail_on_new: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    Help,
    Version,
    /// Run and watch a command.
    Run {
        command: Vec<OsString>,
        opts: Options,
    },
    /// Watch processes that are already running.
    Attach {
        scope: Scope,
        opts: Options,
    },
    /// Show a file written with `--json`, formatted like live output.
    View {
        file: OsString,
        follow: bool,
        opts: Options,
    },
    /// Install a package in a throwaway container, watched.
    Inspect {
        package: String,
        /// Another package to install first and compare with.
        against: Option<String>,
        image: Option<String>,
        /// A command to run in the container after the install.
        then: Vec<OsString>,
        opts: Options,
    },
    /// Internal: the privileged half, started through sudo. Writes events to
    /// standard output until standard input closes.
    Sensor {
        scope: Scope,
        buffer_mb: u32,
    },
    /// Internal: wait for the go-ahead, then become the command.
    Exec {
        command: Vec<OsString>,
    },
}

fn pids(value: &str) -> Result<Vec<u32>, String> {
    let list: Result<Vec<u32>, _> = value.split(',').map(|p| p.trim().parse::<u32>()).collect();
    match list {
        Ok(l) if !l.is_empty() && !l.contains(&0) => Ok(l),
        _ => Err(format!("--pid takes process ids separated by commas, not '{value}'")),
    }
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut raw: Vec<OsString> = args.into_iter().collect();

    // The two internal modes are positional and never mix with options.
    if raw.first().is_some_and(|a| a == "__exec") {
        raw.remove(0);
        if raw.is_empty() {
            return Err("__exec needs a command".into());
        }
        return Ok(Invocation::Exec { command: raw });
    }
    let internal_sensor = raw.first().is_some_and(|a| a == "__sensor");
    if internal_sensor {
        raw.remove(0);
    }

    let mut opts = Options::default();
    let mut scope: Option<Scope> = None;
    let mut view: Option<OsString> = None;
    let mut follow = false;
    let mut inspect: Option<String> = None;
    let mut image: Option<String> = None;
    let mut against: Option<String> = None;
    let mut command: Vec<OsString> = Vec::new();
    let mut parser = lexopt::Parser::from_args(raw);
    let text = |e: lexopt::Error| e.to_string();

    while let Some(arg) = parser.next().map_err(text)? {
        match arg {
            Short('h') | Long("help") => return Ok(Invocation::Help),
            Short('V') | Long("version") => return Ok(Invocation::Version),
            Short('q') | Long("quiet") => opts.quiet = true,
            Short('v') | Long("verbose") => opts.verbose = true,
            Long("no-summary") => opts.summary = false,
            Long("hosts") => opts.hosts = true,
            Long("json") => opts.json = Some(parser.value().map_err(text)?),
            Long("color") => {
                let v: String = parser.value().map_err(text)?.parse().map_err(text)?;
                opts.color = match v.as_str() {
                    "auto" => Color::Auto,
                    "always" => Color::Always,
                    "never" => Color::Never,
                    _ => return Err(format!("--color takes auto, always or never, not '{v}'")),
                };
            }
            Long("buffer-mb") => {
                opts.buffer_mb = parser.value().map_err(text)?.parse().map_err(text)?;
                if !(1..=1024).contains(&opts.buffer_mb) {
                    return Err("--buffer-mb takes a size from 1 to 1024".into());
                }
            }
            Long("report") => {
                let file = parser.value().map_err(text)?;
                if crate::export::Format::of(&file).is_none() {
                    return Err(format!("--report writes .html or .md; '{}' is neither", file.to_string_lossy()));
                }
                opts.report = Some(file);
            }
            Long("baseline") => opts.baseline = Some(parser.value().map_err(text)?),
            Long("write-baseline") => opts.write_baseline = Some(parser.value().map_err(text)?),
            Long("fail-on") => {
                let v: String = parser.value().map_err(text)?.parse().map_err(text)?;
                for what in v.split(',') {
                    match what {
                        "flagged" => opts.fail_on_flagged = true,
                        "new" => opts.fail_on_new = true,
                        _ => return Err(format!("--fail-on takes flagged or new, not '{what}'")),
                    }
                }
            }
            Long("inspect") => inspect = Some(parser.value().map_err(text)?.parse().map_err(text)?),
            Long("against") => against = Some(parser.value().map_err(text)?.parse().map_err(text)?),
            Long("image") => image = Some(parser.value().map_err(text)?.parse().map_err(text)?),
            Long("all") => scope = Some(Scope::All),
            Long("view") => view = Some(parser.value().map_err(text)?),
            Short('f') | Long("follow") => follow = true,
            Long("pid") => {
                let v: String = parser.value().map_err(text)?.parse().map_err(text)?;
                let mut list = pids(&v)?;
                if let Some(Scope::Pids(prev)) = &scope {
                    list.splice(0..0, prev.iter().copied());
                }
                scope = Some(Scope::Pids(list));
            }
            // `--` ends our options; lexopt hands over what follows as values.
            Value(first) => {
                command.push(first);
                command.extend(parser.raw_args().map_err(text)?);
            }
            other => return Err(text(other.unexpected())),
        }
    }

    if internal_sensor {
        let scope = scope.ok_or("__sensor needs --pid or --all")?;
        return Ok(Invocation::Sensor { scope, buffer_mb: opts.buffer_mb });
    }
    if opts.quiet && opts.verbose {
        return Err("--quiet and --verbose contradict each other".into());
    }
    let other_output = opts.json.is_some()
        || opts.report.is_some()
        || opts.write_baseline.is_some()
        || opts.fail_on_flagged
        || opts.fail_on_new;
    if opts.quiet && !opts.summary && !other_output {
        return Err("--quiet with --no-summary would show nothing; add --json, --report or --fail-on".into());
    }
    if image.is_some() && inspect.is_none() {
        return Err("--image goes with --inspect".into());
    }
    if against.is_some() && inspect.is_none() {
        return Err("--against goes with --inspect".into());
    }
    if against.is_some() && opts.baseline.is_some() {
        return Err("--against and --baseline both name what to compare with; give one".into());
    }
    if opts.fail_on_new && opts.baseline.is_none() && against.is_none() {
        return Err("--fail-on new needs something to compare with: add --baseline <file>".into());
    }
    if let Some(package) = inspect {
        if scope.is_some() || view.is_some() || follow {
            return Err("--inspect installs a package; it cannot be combined with --pid, --all or --view".into());
        }
        if opts.json.as_ref().is_some_and(|j| j == "-") {
            return Err("--json - would mix with the install's own output; give a file name".into());
        }
        return Ok(Invocation::Inspect { package, against, image, then: command, opts });
    }
    if let Some(file) = view {
        if scope.is_some() || !command.is_empty() {
            return Err("--view shows a file; it cannot be combined with watching something".into());
        }
        if opts.json.is_some() {
            return Err("--view reads JSON; it does not write it".into());
        }
        return Ok(Invocation::View { file, follow, opts });
    }
    if follow {
        return Err("--follow goes with --view".into());
    }
    match (scope, command.is_empty()) {
        (Some(_), false) => Err("give either a command to run or --pid / --all, not both".into()),
        (Some(scope), true) => Ok(Invocation::Attach { scope, opts }),
        (None, false) => {
            if opts.json.as_ref().is_some_and(|j| j == "-") {
                return Err("--json - would mix with the command's own output; give a file name".into());
            }
            Ok(Invocation::Run { command, opts })
        }
        (None, true) => Err("nothing to watch: give a command after --, or --pid, or --all".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Invocation, String> {
        parse(args.iter().map(OsString::from))
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_command_keeps_its_own_flags() {
        assert_eq!(
            p(&["-v", "--", "npm", "install", "--quiet", "-h"]),
            Ok(Invocation::Run {
                command: os(&["npm", "install", "--quiet", "-h"]),
                opts: Options { verbose: true, ..Options::default() }
            })
        );
        // Without `--`, the first non-option starts the command too.
        assert_eq!(
            p(&["npm", "install", "--json", "x"]),
            Ok(Invocation::Run { command: os(&["npm", "install", "--json", "x"]), opts: Options::default() })
        );
    }

    #[test]
    fn attach_modes() {
        assert_eq!(p(&["--all"]), Ok(Invocation::Attach { scope: Scope::All, opts: Options::default() }));
        assert_eq!(
            p(&["--pid", "12,34", "--pid=56", "-q"]),
            Ok(Invocation::Attach {
                scope: Scope::Pids(vec![12, 34, 56]),
                opts: Options { quiet: true, ..Options::default() }
            })
        );
        assert!(p(&["--pid", "abc"]).is_err());
        assert!(p(&["--pid", "0"]).is_err());
        assert!(p(&["--all", "--", "ls"]).is_err());
    }

    #[test]
    fn options() {
        let Ok(Invocation::Attach { opts, .. }) =
            p(&["--all", "--json", "-", "--color=never", "--buffer-mb", "64", "--no-summary"])
        else {
            panic!("expected attach");
        };
        assert_eq!(opts.json, Some(OsString::from("-")));
        assert_eq!(opts.color, Color::Never);
        assert_eq!(opts.buffer_mb, 64);
        assert!(!opts.summary);
        assert!(p(&["--color", "blue", "--all"]).is_err());
        assert!(p(&["--buffer-mb", "0", "--all"]).is_err());
        assert!(p(&["--frobnicate", "--all"]).is_err());
        assert!(p(&["-q", "-v", "--all"]).is_err());
        assert!(p(&["--json", "-", "--", "ls"]).is_err());
        assert!(p(&[]).is_err());
    }

    #[test]
    fn view_mode() {
        assert_eq!(
            p(&["--view", "run.jsonl", "-f", "-v"]),
            Ok(Invocation::View {
                file: OsString::from("run.jsonl"),
                follow: true,
                opts: Options { verbose: true, ..Options::default() }
            })
        );
        assert!(p(&["--view", "x", "--all"]).is_err());
        assert!(p(&["--view", "x", "--", "ls"]).is_err());
        assert!(p(&["--view", "x", "--json", "y"]).is_err());
        assert!(p(&["--follow", "--all"]).is_err());
    }

    #[test]
    fn reports_and_baselines() {
        let Ok(Invocation::Run { opts, .. }) = p(&[
            "--report",
            "run.html",
            "--baseline",
            "b.json",
            "--write-baseline",
            "b.json",
            "--fail-on",
            "flagged,new",
            "--",
            "npm",
            "ci",
        ]) else {
            panic!("expected run");
        };
        assert_eq!(opts.report, Some(OsString::from("run.html")));
        assert_eq!(opts.baseline, Some(OsString::from("b.json")));
        assert_eq!(opts.write_baseline, Some(OsString::from("b.json")));
        assert!(opts.fail_on_flagged && opts.fail_on_new);
        assert!(p(&["--report", "run.txt", "--", "ls"]).is_err());
        assert!(p(&["--fail-on", "everything", "--", "ls"]).is_err());
        assert!(p(&["--fail-on", "new", "--", "ls"]).is_err(), "nothing to compare with");
        assert!(p(&["--fail-on", "flagged", "--", "ls"]).is_ok());
        // Silent on the terminal is fine when the result goes elsewhere.
        assert!(p(&["-q", "--no-summary", "--", "ls"]).is_err());
        assert!(p(&["-q", "--no-summary", "--fail-on", "flagged", "--", "ls"]).is_ok());
        assert!(p(&["-q", "--no-summary", "--write-baseline", "b.json", "--", "ls"]).is_ok());
        // A recording can be turned into a report, and compared, afterwards.
        assert!(p(&["--view", "a.jsonl", "--report", "a.md", "--baseline", "b.jsonl", "--fail-on", "new"]).is_ok());
    }

    #[test]
    fn inspect_mode() {
        assert_eq!(
            p(&["--inspect", "npm:left-pad@1.3.0", "-q"]),
            Ok(Invocation::Inspect {
                package: "npm:left-pad@1.3.0".into(),
                against: None,
                image: None,
                then: vec![],
                opts: Options { quiet: true, ..Options::default() }
            })
        );
        let Ok(Invocation::Inspect { image, then, .. }) =
            p(&["--inspect", "pypi:requests", "--image", "python:3.12-slim", "--", "python", "-c", "import requests"])
        else {
            panic!("expected inspect");
        };
        assert_eq!(image.as_deref(), Some("python:3.12-slim"));
        assert_eq!(then, os(&["python", "-c", "import requests"]));
        assert!(p(&["--inspect", "npm:x", "--all"]).is_err());
        assert!(p(&["--inspect", "npm:x", "--view", "f"]).is_err());
        assert!(p(&["--inspect", "npm:x", "--json", "-"]).is_err());
        assert!(p(&["--image", "x", "--", "ls"]).is_err());
        let Ok(Invocation::Inspect { against, opts, .. }) =
            p(&["--inspect", "npm:x@2.0.0", "--against", "npm:x@1.0.0", "--fail-on", "new"])
        else {
            panic!("expected inspect");
        };
        assert_eq!(against.as_deref(), Some("npm:x@1.0.0"));
        assert!(opts.fail_on_new, "the other package is what new is measured against");
        assert!(p(&["--against", "npm:x", "--", "ls"]).is_err());
        assert!(p(&["--inspect", "npm:x", "--against", "npm:y", "--baseline", "b.json"]).is_err());
    }

    #[test]
    fn help_and_version() {
        assert_eq!(p(&["--help"]), Ok(Invocation::Help));
        assert_eq!(p(&["-V"]), Ok(Invocation::Version));
    }

    #[test]
    fn internal_modes() {
        assert_eq!(
            p(&["__sensor", "--pid", "7", "--buffer-mb", "32"]),
            Ok(Invocation::Sensor { scope: Scope::Pids(vec![7]), buffer_mb: 32 })
        );
        assert!(p(&["__sensor"]).is_err());
        assert_eq!(p(&["__exec", "ls", "--all"]), Ok(Invocation::Exec { command: os(&["ls", "--all"]) }));
        assert!(p(&["__exec"]).is_err());
    }
}
