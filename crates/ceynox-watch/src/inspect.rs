//! `ceynox-watch --inspect <package>`: install a package somewhere that is
//! not your machine, and watch that.
//!
//! The install runs in a container that is made for it and removed after.
//! The Linux build of this program is copied in and does the watching from
//! inside, so the record has full Linux detail whatever the host is. It
//! starts as the container's root, which loading the sensor needs, and the
//! install itself runs as an ordinary user with no capabilities.
//!
//! The container starts empty. There is no `~/.aws/credentials` in it for a
//! package to take, and none is planted: this tool observes, it does not
//! bait. So a package that only acts when it finds something to steal will
//! show less here than on a developer's machine. What it starts, where it
//! connects and which secret folders it goes looking in still show.
//!
//! A container is a weaker wall than a virtual machine. This keeps a
//! package out of your home directory; it is not a place to detonate
//! something built to break out of containers.

use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};

use crate::{
    cli::{Color, Options},
    run::{self, FAILURE, say},
};

/// Home directory of the user the install runs as.
const HOME: &str = "/home/inspect";
/// That user. 1000 is the unprivileged user in the common images.
const USER: &str = "1000:1000";
/// Where the watcher is put, and where it writes the recording. Both in
/// the container's root directory, which the install cannot write to.
const WATCHER: &str = "/ceynox-watch";
const RECORDING: &str = "/ceynox-watch.jsonl";

/// What the sensor needs and nothing else: loading and attaching the
/// kernel programs, the packet socket for DNS replies, reading `/proc`
/// entries of the install's processes, and changing user for the install.
const CAPABILITIES: &[&str] =
    &["BPF", "PERFMON", "NET_RAW", "SYS_PTRACE", "DAC_READ_SEARCH", "SETUID", "SETGID", "SYS_RESOURCE"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ecosystem {
    Npm,
    Pypi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Spec {
    ecosystem: Ecosystem,
    name: String,
    version: Option<String>,
}

fn plain(text: &str, extra: &[char]) -> bool {
    text.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

impl Spec {
    /// `npm:name`, `npm:@scope/name@1.2.3`, `pypi:name`, `pypi:name==1.2.3`.
    ///
    /// Names and versions are held to the characters registries allow, so
    /// that what is handed to the package manager can only ever be read as
    /// a package to install.
    fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "'{text}' is not a package I can inspect. Give npm:<name>[@<version>] or pypi:<name>[==<version>], \
                 for example npm:left-pad@1.3.0"
            )
        };
        let (ecosystem, rest) = text.split_once(':').ok_or_else(bad)?;
        match ecosystem {
            "npm" => {
                let (name, version) = match rest.char_indices().skip(1).find(|(_, c)| *c == '@') {
                    Some((at, _)) => (&rest[..at], Some(&rest[at + 1..])),
                    None => (rest, None),
                };
                let ok = match name.strip_prefix('@').map(|n| n.split_once('/')) {
                    Some(Some((scope, pkg))) => {
                        plain(scope, &['-', '.', '_', '~']) && plain(pkg, &['-', '.', '_', '~'])
                    }
                    Some(None) => false,
                    None => plain(name, &['-', '.', '_', '~']),
                };
                if !ok || name.len() > 214 || version.is_some_and(|v| !plain(v, &['-', '.', '_', '+']) || v.len() > 64)
                {
                    return Err(bad());
                }
                Ok(Self { ecosystem: Ecosystem::Npm, name: name.into(), version: version.map(Into::into) })
            }
            "pypi" | "pip" => {
                let (name, version) = match rest.split_once("==").or_else(|| rest.split_once('@')) {
                    Some((n, v)) => (n, Some(v)),
                    None => (rest, None),
                };
                if !plain(name, &['-', '.', '_'])
                    || name.len() > 128
                    || version.is_some_and(|v| !plain(v, &['-', '.', '_', '+', '!']) || v.len() > 64)
                {
                    return Err(bad());
                }
                Ok(Self { ecosystem: Ecosystem::Pypi, name: name.into(), version: version.map(Into::into) })
            }
            _ => Err(bad()),
        }
    }

    fn image(&self) -> &'static str {
        match self.ecosystem {
            Ecosystem::Npm => "node:lts-slim",
            Ecosystem::Pypi => "python:3-slim",
        }
    }

    /// The install, as the package manager's own command line.
    fn install(&self) -> Vec<String> {
        let strs = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match self.ecosystem {
            Ecosystem::Npm => {
                let mut cmd =
                    strs(&["npm", "install", "--no-audit", "--no-fund", "--no-update-notifier", "--loglevel=error"]);
                cmd.push(match &self.version {
                    Some(v) => format!("{}@{v}", self.name),
                    None => self.name.clone(),
                });
                cmd
            }
            Ecosystem::Pypi => {
                let mut cmd = strs(&[
                    "python",
                    "-m",
                    "pip",
                    "install",
                    "--user",
                    "--quiet",
                    "--no-input",
                    "--no-cache-dir",
                    "--disable-pip-version-check",
                    "--no-warn-script-location",
                ]);
                cmd.push(match &self.version {
                    Some(v) => format!("{}=={v}", self.name),
                    None => self.name.clone(),
                });
                cmd
            }
        }
    }
}

/// `docker` or `podman`, whichever is there.
fn runtime() -> Result<(String, String), String> {
    let mut last = String::new();
    for name in ["docker", "podman"] {
        let format = if name == "docker" { "{{.Architecture}}" } else { "{{.Host.Arch}}" };
        match Command::new(name).args(["info", "--format", format]).stdin(Stdio::null()).output() {
            Ok(out) if out.status.success() => {
                let arch = match String::from_utf8_lossy(&out.stdout).trim() {
                    "aarch64" | "arm64" => "aarch64",
                    "x86_64" | "amd64" => "x86_64",
                    other => {
                        return Err(format!("{name} runs containers for {other}, which ceynox-watch is not built for"));
                    }
                };
                return Ok((name.to_string(), arch.to_string()));
            }
            Ok(out) => {
                let why = String::from_utf8_lossy(&out.stderr);
                last = format!("{name} is installed but not usable: {}", why.lines().last().unwrap_or("").trim());
            }
            Err(_) => {}
        }
    }
    if last.is_empty() {
        last =
            "inspecting a package needs Docker or Podman to make the throwaway container, and neither was found".into();
    }
    Err(last)
}

/// The Linux build of this program for the container's architecture.
fn watcher(arch: &str) -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("CEYNOX_WATCH_LINUX_BINARY") {
        let path = PathBuf::from(path);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(format!("CEYNOX_WATCH_LINUX_BINARY points at {}, which is not a file", path.display()))
        };
    }
    let me = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("cannot find my own executable: {e}"))?;
    if cfg!(target_os = "linux") {
        return if std::env::consts::ARCH == arch {
            Ok(me)
        } else {
            Err(format!(
                "the container runs {arch} and this is the {} build; point CEYNOX_WATCH_LINUX_BINARY at a {arch} one",
                std::env::consts::ARCH
            ))
        };
    }
    // Elsewhere the Linux builds ship beside this one, in libexec.
    let name = format!("ceynox-watch-linux-{arch}");
    let dir = me.parent().unwrap_or(Path::new("."));
    [dir.join("../libexec").join(&name), dir.join("libexec").join(&name)].into_iter().find(|p| p.is_file()).ok_or_else(
        || {
            format!(
                "the watching inside the container is done by the Linux build of ceynox-watch, and {name} is not \
                 installed beside this one. The Homebrew package and the release archive include it; otherwise \
                 point CEYNOX_WATCH_LINUX_BINARY at one"
            )
        },
    )
}

/// A private directory for the recording, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Self> {
        let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("ceynox-watch-inspect-{}-{nanos}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Removes the container however we leave.
struct Container<'a> {
    runtime: &'a str,
    name: String,
}

impl Drop for Container<'_> {
    fn drop(&mut self) {
        let _ = Command::new(self.runtime)
            .args(["rm", "--force", "--volumes", &self.name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Run a quick container command, returning its error output if it fails.
fn quiet(runtime: &str, args: &[&OsStr]) -> Result<(), String> {
    let out = Command::new(runtime)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {runtime}: {e}"))?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
}

/// What to install in the container: one package from a registry, or
/// everything a project's lockfile names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Package(Spec),
    /// `package-lock.json` (with the `package.json` beside it) or a
    /// `requirements.txt`. The files are copied in; nothing else of the
    /// project is.
    Project {
        ecosystem: Ecosystem,
        files: Vec<PathBuf>,
    },
}

/// Where a project's files are put in the container.
const PROJECT: &str = "/ceynox-watch-project";

impl Target {
    fn parse(text: &str) -> Result<Self, String> {
        let path = Path::new(text);
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name == "package-lock.json" {
            let manifest = path.with_file_name("package.json");
            for file in [path, manifest.as_path()] {
                if !file.is_file() {
                    return Err(format!(
                        "{} is not there; a lockfile is installed with the package.json beside it",
                        file.display()
                    ));
                }
            }
            return Ok(Self::Project { ecosystem: Ecosystem::Npm, files: vec![manifest, path.to_path_buf()] });
        }
        if name.starts_with("requirements") && name.ends_with(".txt") {
            if !path.is_file() {
                return Err(format!("{} is not there", path.display()));
            }
            return Ok(Self::Project { ecosystem: Ecosystem::Pypi, files: vec![path.to_path_buf()] });
        }
        Spec::parse(text)
            .map(Self::Package)
            .map_err(|e| format!("{e}. Or give the path of a package-lock.json or a requirements.txt"))
    }

    fn image(&self) -> &'static str {
        match self {
            Self::Package(spec) => spec.image(),
            Self::Project { ecosystem: Ecosystem::Npm, .. } => "node:lts-slim",
            Self::Project { ecosystem: Ecosystem::Pypi, .. } => "python:3-slim",
        }
    }

    /// The install as a command line. For a project it is a shell script,
    /// because the files have to be brought to the working directory
    /// first; every word of it is ours.
    fn install(&self) -> Vec<String> {
        let strs = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match self {
            Self::Package(spec) => spec.install(),
            Self::Project { ecosystem: Ecosystem::Npm, .. } => strs(&[
                "sh",
                "-c",
                &format!(
                    "cp {PROJECT}/package.json {PROJECT}/package-lock.json . && exec npm ci --no-audit --no-fund --no-update-notifier --loglevel=error"
                ),
            ]),
            Self::Project { ecosystem: Ecosystem::Pypi, files } => {
                let file = files[0].file_name().and_then(OsStr::to_str).unwrap_or("requirements.txt");
                let mut cmd = strs(&[
                    "python",
                    "-m",
                    "pip",
                    "install",
                    "--user",
                    "--quiet",
                    "--no-input",
                    "--no-cache-dir",
                    "--disable-pip-version-check",
                    "--no-warn-script-location",
                    "-r",
                ]);
                cmd.push(format!("{PROJECT}/{file}"));
                cmd
            }
        }
    }
}

/// One install in one container, start to finish.
struct Outcome {
    code: i32,
    /// The recording, when it was asked for. Lives in `_scratch`.
    recording: Option<PathBuf>,
    _scratch: Scratch,
}

struct Job<'a> {
    target: &'a Target,
    /// What the user called it: `npm:left-pad@1.3.0`, or a file name.
    label: &'a str,
    image: &'a str,
    runtime: &'a str,
    binary: &'a Path,
    then: &'a [OsString],
    opts: &'a Options,
    /// Show nothing: this run is only wanted for its recording.
    silent: bool,
    record: bool,
}

fn once(job: &Job<'_>) -> Result<Outcome, String> {
    let Job { target, label, image, runtime, binary, then, opts, silent, record } = *job;
    let scratch = Scratch::new().map_err(|e| format!("could not make a temporary directory: {e}"))?;

    // What the watcher inside is told: the same display options, a
    // recording, and the install as its command.
    let color = match opts.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => {
            rustix::termios::isatty(std::io::stderr())
                && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
        }
    };
    let mut inner: Vec<OsString> = vec!["--color".into(), if color { "always" } else { "never" }.into()];
    inner.extend((opts.quiet || silent).then(|| "--quiet".into()));
    inner.extend((opts.verbose && !silent).then(|| "--verbose".into()));
    inner.extend((!opts.summary || silent).then(|| "--no-summary".into()));
    inner.extend([
        "--buffer-mb".into(),
        opts.buffer_mb.to_string().into(),
        "--json".into(),
        RECORDING.into(),
        "--".into(),
    ]);
    let install = target.install();
    if then.is_empty() {
        inner.extend(install.iter().map(OsString::from));
    } else {
        // The install, and if it worked, the command that was asked for.
        // The install is written into the script as it is: every word of
        // it is one of our own flags or a checked package name, none of
        // which holds a character the shell would act on.
        let script = match target {
            Target::Package(_) => install.join(" "),
            // Already a script: take its body.
            Target::Project { .. } if install.len() == 3 => install[2].replacen("exec ", "", 1),
            Target::Project { .. } => install.join(" "),
        };
        inner.extend(["sh".into(), "-c".into(), format!("{script} && exec \"$@\"").into(), "sh".into()]);
        inner.extend(then.iter().cloned());
    }

    // Two containers of ours may exist at once only by name clash, so the
    // name carries the time as well as our pid.
    let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let container = Container { runtime, name: format!("ceynox-watch-inspect-{}-{nanos}", std::process::id()) };
    let width = rustix::termios::tcgetwinsize(std::io::stderr()).map_or(100, |w| w.ws_col);
    let tmpfs = |dir: &str| format!("{dir}:rw,exec,nosuid,uid=1000,gid=1000,mode=0755");
    let mut create: Vec<OsString> =
        ["create", "--name", &container.name, "--user", "0:0", "--cap-drop", "ALL"].map(Into::into).to_vec();
    for cap in CAPABILITIES {
        create.extend(["--cap-add".into(), OsString::from(cap)]);
    }
    create.extend(
        [
            "--pids-limit",
            "4096",
            "--tmpfs",
            &tmpfs(HOME),
            "--tmpfs",
            &tmpfs("/work"),
            "--workdir",
            "/work",
            "--env",
            &format!("HOME={HOME}"),
            "--env",
            &format!("{}={USER}", run::AS_ENV),
            "--env",
            &format!("COLUMNS={width}"),
            "--env",
            &format!("{}={label} in {image}", run::TITLE_ENV),
            "--env",
            "npm_config_update_notifier=false",
            "--entrypoint",
            WATCHER,
            image,
        ]
        .map(OsString::from),
    );
    create.extend(inner);

    if !opts.quiet && !silent {
        say(format!("installing {label} in a throwaway {image} container ({runtime})"));
    }
    // Fetch the image first when it is not here yet, without the layer by
    // layer progress that would otherwise open the output.
    if quiet(runtime, &["image", "inspect", image].map(OsStr::new)).is_err() {
        if !opts.quiet {
            say(format!("fetching {image}, which is only needed the first time"));
        }
        quiet(runtime, &["pull", "--quiet", image].map(OsStr::new))
            .map_err(|e| format!("could not fetch {image}: {}", e.lines().last().unwrap_or("").trim()))?;
    }
    match Command::new(runtime).args(&create).stdin(Stdio::null()).stdout(Stdio::null()).status() {
        Ok(s) if s.success() => {}
        Ok(_) => return Err(format!("{runtime} could not create the container")),
        Err(e) => return Err(format!("could not run {runtime}: {e}")),
    }
    let into = format!("{}:{WATCHER}", container.name);
    quiet(runtime, &["cp".as_ref(), binary.as_os_str(), into.as_ref()])
        .map_err(|e| format!("could not put the watcher in the container: {e}"))?;
    if let Target::Project { files, .. } = target {
        // A copy of just the named files, readable by the install's user.
        let dir = scratch.0.join("project");
        let prepare = || -> std::io::Result<()> {
            fs::DirBuilder::new().mode(0o755).create(&dir)?;
            for file in files {
                let to = dir.join(file.file_name().unwrap_or(OsStr::new("file")));
                fs::copy(file, &to)?;
                fs::set_permissions(&to, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
            }
            Ok(())
        };
        prepare().map_err(|e| format!("could not read the project's files: {e}"))?;
        let into = format!("{}:{PROJECT}", container.name);
        quiet(runtime, &["cp".as_ref(), dir.as_os_str(), into.as_ref()])
            .map_err(|e| format!("could not put the project's files in the container: {e}"))?;
    }

    // Our output is the container's. A Ctrl-C reaches the container
    // runtime as well as us, and it passes it on; we stay to clean up.
    let signals = run::Signals::install();
    let mut start = Command::new(runtime);
    start.args(["start", "--attach", &container.name]).stdin(Stdio::null());
    if silent {
        start.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let mut child = start.spawn().map_err(|e| format!("could not run {runtime}: {e}"))?;
    let mut asked = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => return Err(format!("lost track of the container: {e}")),
        }
        if signals.terminate.load(Ordering::Relaxed) && !asked {
            asked = true;
            let _ = quiet(runtime, &["kill", "--signal", "TERM", &container.name].map(OsStr::new));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let code = status.code().unwrap_or(FAILURE);
    if code == FAILURE {
        // The watcher inside could not start, and has said why (unless it
        // was silenced). The usual reasons are worth a hint.
        return Err(format!(
            "the watcher could not start in the container. If the sensor could not load: the container needs \
             a kernel with BTF and a {runtime} that may grant CAP_BPF, which a rootless one cannot"
        ));
    }
    let mut recording = None;
    if record {
        let to = scratch.0.join("run.jsonl");
        let from = format!("{}:{RECORDING}", container.name);
        quiet(runtime, &["cp".as_ref(), from.as_ref(), to.as_os_str()])
            .map_err(|e| format!("could not fetch the recording from the container: {e}"))?;
        recording = Some(to);
    }
    Ok(Outcome { code, recording, _scratch: scratch })
}

/// `--inspect <package> [--against <package>]`
pub fn run(package: &str, against: Option<&str>, image: Option<&str>, then: &[OsString], opts: Options) -> i32 {
    let fail = |why: String| {
        say(why);
        FAILURE
    };
    let target = match Target::parse(package) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let earlier = match against.map(Target::parse) {
        None => None,
        Some(Ok(t)) => Some(t),
        Some(Err(e)) => return fail(e),
    };
    if image.is_some_and(|i| i.starts_with('-') || i.is_empty()) {
        return fail("--image takes the name of a container image".into());
    }
    let (runtime, arch) = match runtime() {
        Ok(found) => found,
        Err(e) => return fail(e),
    };
    let binary = match watcher(&arch) {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let short = |text: &str| Path::new(text).file_name().and_then(OsStr::to_str).unwrap_or(text).to_string();
    let label = if matches!(target, Target::Package(_)) { package.to_string() } else { short(package) };

    // The earlier one first, unseen: only what it did is wanted.
    let mut compared = None;
    if let (Some(earlier), Some(text)) = (&earlier, against) {
        let name = if matches!(earlier, Target::Package(_)) { text.to_string() } else { short(text) };
        if !opts.quiet {
            say(format!("installing {name} first, to compare with"));
        }
        let job = Job {
            target: earlier,
            label: &name,
            image: image.unwrap_or(earlier.image()),
            runtime: &runtime,
            binary: &binary,
            then,
            opts: &opts,
            silent: true,
            record: true,
        };
        let outcome = match once(&job) {
            Ok(o) => o,
            Err(e) => return fail(e),
        };
        if outcome.code != 0 {
            return fail(format!(
                "installing {name} failed with status {}, so there is nothing to compare with",
                outcome.code
            ));
        }
        let baseline = outcome.recording.as_deref().map(|r| crate::baseline::Baseline::load(r, Some(HOME.to_string())));
        match baseline {
            Some(Ok(b)) => compared = Some((b, name)),
            Some(Err(e)) => return fail(e),
            None => return fail("the earlier install left no recording".into()),
        }
    }

    let wants_more = compared.is_some()
        || opts.report.is_some()
        || opts.baseline.is_some()
        || opts.write_baseline.is_some()
        || opts.json.is_some()
        || opts.fail_on_flagged
        || opts.fail_on_new;
    let image = image.unwrap_or(target.image());
    let job = Job {
        target: &target,
        label: &label,
        image,
        runtime: &runtime,
        binary: &binary,
        then,
        opts: &opts,
        silent: false,
        record: wants_more,
    };
    let outcome = match once(&job) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let Some(recording) = &outcome.recording else {
        return outcome.code;
    };
    if let Some(file) = &opts.json
        && let Err(e) = fs::copy(recording, file)
    {
        return fail(format!("cannot write {}: {e}", file.to_string_lossy()));
    }
    let title = format!("{label} in {image}");
    run::conclude_recording(recording, HOME, title, outcome.code, opts, compared)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(text: &str) -> Option<(Ecosystem, String, Option<String>)> {
        Spec::parse(text).ok().map(|s| (s.ecosystem, s.name, s.version))
    }

    #[test]
    fn package_names_are_parsed() {
        assert_eq!(spec("npm:left-pad"), Some((Ecosystem::Npm, "left-pad".into(), None)));
        assert_eq!(spec("npm:left-pad@1.3.0"), Some((Ecosystem::Npm, "left-pad".into(), Some("1.3.0".into()))));
        assert_eq!(spec("npm:@types/node@22.1.0"), Some((Ecosystem::Npm, "@types/node".into(), Some("22.1.0".into()))));
        assert_eq!(spec("npm:@scope/pkg"), Some((Ecosystem::Npm, "@scope/pkg".into(), None)));
        assert_eq!(spec("pypi:requests"), Some((Ecosystem::Pypi, "requests".into(), None)));
        assert_eq!(spec("pypi:requests==2.32.3"), Some((Ecosystem::Pypi, "requests".into(), Some("2.32.3".into()))));
        assert_eq!(
            spec("pip:zope.interface@7.0"),
            Some((Ecosystem::Pypi, "zope.interface".into(), Some("7.0".into())))
        );
    }

    #[test]
    fn only_package_names_get_through() {
        for bad in [
            "left-pad",
            "gem:rails",
            "npm:",
            "npm:--global",
            "npm:-x",
            "npm:a b",
            "npm:a;id",
            "npm:$(id)",
            "npm:../../etc",
            "npm:@scope",
            "npm:@/x",
            "npm:x@",
            "npm:x@1 2",
            "npm:x@--tag",
            "npm:https://evil.example/x.tgz",
            "npm:git+ssh://x",
            "pypi:",
            "pypi:-r",
            "pypi:--index-url=http://x",
            "pypi:x==",
            "pypi:x==1;y",
            "pypi:x[extra]",
            "pypi:./local",
        ] {
            assert!(Spec::parse(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn the_install_is_one_package_and_nothing_else() {
        let npm = Spec::parse("npm:@scope/pkg@1.0.0").expect("spec").install();
        assert_eq!(npm.last().map(String::as_str), Some("@scope/pkg@1.0.0"));
        assert_eq!(&npm[..2], ["npm", "install"]);
        let pip = Spec::parse("pypi:requests==2.32.3").expect("spec").install();
        assert_eq!(pip.last().map(String::as_str), Some("requests==2.32.3"));
        assert!(pip.contains(&"--user".to_string()));
        assert_eq!(Spec::parse("pypi:requests").expect("spec").image(), "python:3-slim");
        assert_eq!(Spec::parse("npm:x").expect("spec").image(), "node:lts-slim");
        // A lockfile that is not there is refused before anything is started.
        assert!(Target::parse("/nowhere/package-lock.json").is_err());
        assert!(Target::parse("/nowhere/requirements.txt").is_err());
        assert!(matches!(Target::parse("npm:left-pad"), Ok(Target::Package(_))));
        assert!(Target::parse("Cargo.lock").is_err());
        // The install is spliced into a shell script when a command
        // follows it, so no word of it may mean anything to a shell.
        for text in ["npm:@a.b/c_d~e@1.0.0-rc.1+build", "pypi:a.b_c-d==1!2.0+local", "pip:x@1.0"] {
            for word in Spec::parse(text).expect("spec").install() {
                assert!(
                    word.chars().all(|c| c.is_ascii_alphanumeric() || "-._~@/=+!".contains(c))
                        && !word.starts_with('~'),
                    "{word}"
                );
            }
        }
    }
}
