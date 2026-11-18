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

Examples:
  ceynox-watch -- npm install
  ceynox-watch -- pip install -r requirements.txt
  ceynox-watch --pid $(pgrep -n claude)

Options:
  -q, --quiet          no live output, only the summary
  -v, --verbose        also show every file opened
      --no-summary     no summary at the end
      --json <file>    also write every event as JSON, one per line
                       (\"-\" for standard output, with --pid or --all)
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
    if opts.quiet && !opts.summary && opts.json.is_none() {
        return Err("--quiet with --no-summary and no --json would show nothing".into());
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
