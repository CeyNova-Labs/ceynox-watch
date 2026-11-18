//! The four things the binary can do: run and watch a command, attach to
//! running processes, and the two internal helper modes.
//!
//! # Privilege
//!
//! Loading the sensor needs root; nothing else does. When started without
//! root, the program keeps running as the user and starts a second copy of
//! itself through `sudo` in the internal "sensor" mode. That copy loads the
//! sensor and writes events to its standard output, which the unprivileged
//! side reads. The watched command is started by the unprivileged side, so
//! it runs as the user with the user's environment, never as root.
//!
//! # Not missing the start
//!
//! The command must not run before the sensor watches it. So the command is
//! started as a third copy of this program (the "exec" mode) that first
//! waits on a lock the parent holds, and only then replaces itself with the
//! real command. The parent releases the lock once the sensor reports ready.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        io::AsFd,
        process::{CommandExt, ExitStatusExt},
    },
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use rustix::{
    event::{PollFd, PollFlags, poll},
    fs::{FlockOperation, flock},
    process::{Pid, Signal, kill_process},
    termios::{isatty, tcgetwinsize},
};

use crate::{
    classify::Classifier,
    cli::{Color, Options},
    event::{Event, What},
    render::{self, Header, Style},
    report::{Exit, Report},
    sensor::{self, Scope, Sensor},
};

/// Exit status when ceynox-watch itself fails, as opposed to the command.
pub const FAILURE: i32 = 125;

const GATE_ENV: &str = "CEYNOX_WATCH_GATE";
const GO: &[u8] = b"go";
/// Last line of the helper's output.
const END: &str = "end";

/// A directory of ours (home, the starting directory) in the form the
/// sensor reports paths in, so that the two can be compared.
fn as_reported(dir: &str) -> String {
    #[cfg(target_os = "macos")]
    if let Some(short) = crate::sensor::macos::normalize(dir) {
        return short;
    }
    dir.to_string()
}

fn say(msg: impl std::fmt::Display) {
    eprintln!("ceynox-watch: {msg}");
}

// ---- the start gate -----------------------------------------------------------

/// A lock file in a private directory. The command's stand-in blocks on the
/// lock; [`Gate::open`] lets it through. Dropping the gate without opening
/// it (for example because the sensor failed to start) tells the stand-in
/// to give up instead.
#[cfg_attr(target_os = "macos", allow(dead_code))]
struct Gate {
    dir: PathBuf,
    file: Option<File>,
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
impl Gate {
    fn new() -> io::Result<Self> {
        let parent = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = parent.join(format!("ceynox-watch-{}-{nanos}", std::process::id()));
        // Fails if the name exists, so nobody else can have prepared it, and
        // the mode keeps other users out.
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let made = || -> io::Result<File> {
            let file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join("gate"))?;
            flock(&file, FlockOperation::LockExclusive)?;
            Ok(file)
        };
        match made() {
            Ok(file) => Ok(Self { dir, file: Some(file) }),
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join("gate")
    }

    fn open(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.write_all(GO)?;
            // Dropping the file releases the lock.
        }
        Ok(())
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(self.path());
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Internal "exec" mode: wait at the gate, then become the command.
pub fn exec_main(command: Vec<OsString>) -> i32 {
    let Some(path) = std::env::var_os(GATE_ENV) else {
        say("__exec is internal; use `ceynox-watch -- <command>`");
        return FAILURE;
    };
    let go = || -> io::Result<bool> {
        let mut file = File::open(&path)?;
        // Blocks until the parent releases its exclusive lock, by opening
        // the gate or by exiting.
        flock(&file, FlockOperation::LockShared)?;
        let mut word = Vec::new();
        file.read_to_end(&mut word)?;
        Ok(word == GO)
    };
    match go() {
        Ok(true) => {}
        // The parent gave up; it has already said why.
        Ok(false) => return FAILURE,
        Err(e) => {
            say(format!("could not wait for the sensor: {e}"));
            return FAILURE;
        }
    }
    let err = Command::new(&command[0]).args(&command[1..]).env_remove(GATE_ENV).exec();
    say(format!("cannot run {}: {err}", command[0].to_string_lossy()));
    if err.kind() == io::ErrorKind::NotFound { 127 } else { 126 }
}

// ---- event sources ------------------------------------------------------------

/// A running sensor: a second copy of this program in "sensor" mode,
/// started through sudo unless we are root already.
///
/// The sensor always lives in its own process, even when no change of user
/// is involved. That keeps one code path, lets the sensor drop privileges
/// independently, and means nobody waits for the kernel to detach the
/// programs at the end, which takes a few hundred milliseconds.
struct Source {
    events: Receiver<Event>,
    /// Closing the helper's standard input tells it to finish.
    stdin: Option<ChildStdin>,
    /// On macOS the events come from the system log instead of a helper.
    #[cfg(target_os = "macos")]
    stream: Option<crate::sensor::macos::Stream>,
}

impl Source {
    fn start(scope: &Scope, buffer_mb: u32, quiet: bool) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| format!("cannot find my own executable: {e}"))?;
        let mut cmd = if rustix::process::geteuid().is_root() {
            Command::new(exe)
        } else {
            if !quiet {
                say("watching needs root; asking sudo (your command still runs as you)");
            }
            let mut sudo = Command::new("sudo");
            sudo.arg("--").arg(exe);
            sudo
        };
        cmd.arg("__sensor").arg("--buffer-mb").arg(buffer_mb.to_string());
        match scope {
            Scope::All => cmd.arg("--all"),
            Scope::Pids(pids) => cmd.arg("--pid").arg(pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")),
        };
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                "watching needs root and there is no sudo here; run ceynox-watch as root".to_string()
            } else {
                format!("could not start the sensor: {e}")
            }
        })?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or("the sensor gave no output pipe")?;

        let (tx, events) = mpsc::channel::<Event>();
        let (ready_tx, ready) = mpsc::channel::<bool>();
        thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let ok = matches!(lines.next(), Some(Ok(line)) if line == "ready");
            let _ = ready_tx.send(ok);
            if !ok {
                return;
            }
            for line in lines.map_while(Result::ok) {
                // The helper says when it has sent everything. Its pipe
                // stays open a while longer, until the kernel has detached
                // the programs; there is nothing more to read from it.
                if line == END {
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<Event>(&line) {
                    let _ = tx.send(ev);
                }
            }
        });

        let mut source = Self {
            events,
            stdin,
            #[cfg(target_os = "macos")]
            stream: None,
        };
        if ready.recv() == Ok(true) {
            return Ok(source);
        }
        // The helper has said why on standard error.
        source.finish();
        let _ = child.wait();
        Err(String::new())
    }

    /// Ask the sensor to stop. Events already produced keep arriving on
    /// `events` until the channel closes.
    fn finish(&mut self) {
        drop(self.stdin.take());
        #[cfg(target_os = "macos")]
        if let Some(stream) = &mut self.stream {
            stream.finish();
        }
    }
}

/// Internal "sensor" mode: the privileged half. Standard output carries a
/// first line saying `ready`, then events as JSON lines, then a last line
/// saying `end`. Ends when standard input closes.
pub fn sensor_main(scope: Scope, buffer_mb: u32) -> i32 {
    // A Ctrl-C at the terminal reaches this process too. It must outlive
    // the command to report its last events, so signals only set a flag.
    let _signals = Signals::install();
    let opts = sensor::Options { scope, buffer_bytes: buffer_mb.saturating_mul(1024 * 1024) };
    let mut sensor = match Sensor::start(&opts) {
        Ok(s) => s,
        Err(e) => {
            say(e);
            return 1;
        }
    };
    // From here on only already-open descriptors are used. When watching one
    // user's processes for them, stop being root. Watching the whole
    // machine keeps root: describing other users' processes needs it.
    #[cfg(target_os = "linux")]
    if opts.scope != Scope::All
        && let Err(e) = sensor::privdrop::become_invoker()
    {
        say(e);
        return 1;
    }
    let mut out = BufWriter::with_capacity(64 * 1024, io::stdout().lock());
    if writeln!(out, "ready").and_then(|()| out.flush()).is_err() {
        return 1;
    }
    let stdin = io::stdin();
    let mut broken = false;
    loop {
        let mut write = |ev: Event| {
            if serde_json::to_writer(&mut out, &ev).is_err() || out.write_all(b"\n").is_err() {
                broken = true;
            }
        };
        // Standard input is in the wait set so that its closing ends the
        // wait at once.
        let polled = sensor.poll(200, Some(stdin.as_fd()), &mut write);
        let mut fds = [PollFd::new(&stdin, PollFlags::empty())];
        let closed = matches!(poll(&mut fds, Some(&rustix::time::Timespec { tv_sec: 0, tv_nsec: 0 })), Ok(n) if n > 0)
            && fds[0].revents().intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL);
        if closed || polled.is_err() {
            sensor.drain(&mut write);
        }
        if closed {
            let _ = writeln!(out, "{END}");
        }
        if out.flush().is_err() || broken || closed {
            // Exit without detaching program by program, which is slow; the
            // kernel releases everything when the process is gone.
            #[cfg(target_os = "linux")]
            std::mem::forget(sensor);
            return 0;
        }
        if let Err(e) = polled {
            say(e);
            return 1;
        }
    }
}

// ---- signals ------------------------------------------------------------------

/// Flags set by the signals that would otherwise kill us mid-report.
struct Signals {
    interrupt: Arc<AtomicBool>,
    terminate: Arc<AtomicBool>,
}

impl Signals {
    fn install() -> Self {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        let interrupt = Arc::new(AtomicBool::new(false));
        let terminate = Arc::new(AtomicBool::new(false));
        for sig in [SIGINT, SIGQUIT] {
            let _ = signal_hook::flag::register(sig, Arc::clone(&interrupt));
        }
        for sig in [SIGTERM, SIGHUP] {
            let _ = signal_hook::flag::register(sig, Arc::clone(&terminate));
        }
        Self { interrupt, terminate }
    }

    fn any(&self) -> bool {
        self.interrupt.load(Ordering::Relaxed) || self.terminate.load(Ordering::Relaxed)
    }
}

// ---- the watching session -----------------------------------------------------

/// Where live lines and the summary go, plus everything derived from it.
struct Screen {
    /// Standard error when a command is being run (its output owns standard
    /// output), standard output otherwise.
    to_stderr: bool,
    style: Style,
    opts: Options,
    json: Option<Box<dyn Write>>,
    /// Set when the output went away (`| head`); stops further writing.
    gone: bool,
}

impl Screen {
    fn new(opts: Options, to_stderr: bool) -> Result<Self, String> {
        let json: Option<Box<dyn Write>> = match &opts.json {
            None => None,
            Some(name) if name == "-" => Some(Box::new(BufWriter::new(io::stdout()))),
            Some(name) => {
                let file = File::create(name).map_err(|e| format!("cannot write {}: {e}", name.to_string_lossy()))?;
                Some(Box::new(BufWriter::new(file)))
            }
        };
        let tty = if to_stderr { isatty(io::stderr()) } else { isatty(io::stdout()) };
        let color = match opts.color {
            Color::Always => true,
            Color::Never => false,
            Color::Auto => {
                tty && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                    && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
            }
        };
        let size = if to_stderr { tcgetwinsize(io::stderr()) } else { tcgetwinsize(io::stdout()) };
        let width = size.ok().map(|w| usize::from(w.ws_col)).filter(|&w| w >= 40).unwrap_or(100);
        let base = std::env::current_dir().ok().map(|d| as_reported(&d.to_string_lossy()));
        Ok(Self { to_stderr, style: Style { color, width, base }, opts, json, gone: false })
    }

    /// Live text is off when quiet, and when JSON has taken standard output.
    fn live(&self) -> bool {
        !self.opts.quiet && !(self.opts.json.as_ref().is_some_and(|j| j == "-") && !self.to_stderr)
    }

    fn print(&mut self, text: &str) {
        if self.gone {
            return;
        }
        let res = if self.to_stderr { writeln!(io::stderr(), "{text}") } else { writeln!(io::stdout(), "{text}") };
        self.gone = res.is_err();
    }

    fn record(&mut self, ev: &Event) {
        if let Some(json) = &mut self.json
            // Flushed per event, so the file never ends in half a line and
            // someone following it sees each event as it happens.
            && (serde_json::to_writer(&mut *json, ev).is_err() || json.write_all(b"\n").is_err() || json.flush().is_err())
        {
            self.gone = true;
        }
    }

    fn finish(&mut self) {
        if let Some(json) = &mut self.json {
            let _ = json.flush();
        }
    }
}

struct Session {
    report: Report,
    screen: Screen,
    /// Time of the first event shown; live lines count from here.
    start: Option<u64>,
    me: u32,
    /// When each program-start line was last shown, to leave out repeats.
    shown: std::collections::HashMap<String, u64>,
    /// The command being run, when there is one.
    command: Option<Watched>,
}

/// Where the watched command is in its life, as told by the sensor.
#[derive(Debug, Clone, Copy)]
struct Watched {
    pid: u32,
    /// Its first program has started. Until then, events under its pid are
    /// our own preparations (the stand-in waiting at the gate) and are
    /// dropped. Decided here, in the one place every event passes through,
    /// because events can arrive after the command has already exited.
    started: bool,
    exited: bool,
}

/// A program started again within this long of the same line being shown
/// is not shown again. Shell start-up scripts and build loops run the same
/// few tools hundreds of times; the summary still counts every one.
const REPEAT_MS: u64 = 5_000;

impl Session {
    fn new(screen: Screen) -> Self {
        let home = std::env::var("HOME").ok().map(|h| as_reported(&h));
        Self {
            report: Report::new(Classifier::new(home)),
            screen,
            start: None,
            me: std::process::id(),
            shown: std::collections::HashMap::new(),
            command: None,
        }
    }

    fn take(&mut self, ev: &Event) {
        // Our own activity is not what anyone asked about.
        if ev.pid == self.me {
            return;
        }
        if let Some(cmd) = &mut self.command {
            let own = ev.pid == cmd.pid;
            cmd.started |= own && matches!(ev.what, What::Exec { existing: false, .. });
            if !cmd.started {
                return;
            }
            cmd.exited |= own && matches!(ev.what, What::Exit { .. });
        }
        self.screen.record(ev);
        let start = *self.start.get_or_insert(ev.ts);
        let lines = self.report.ingest(ev);
        if !self.screen.live() {
            return;
        }
        let verbose = self.screen.opts.verbose;
        for line in &lines {
            if !verbose && let (crate::report::LineKind::Exec { depth }, Some(proc)) = (&line.kind, line.proc) {
                let key = format!("{depth} {}", self.report.procs[proc].command());
                let last = self.shown.insert(key, line.ts);
                if last.is_some_and(|at| line.ts.saturating_sub(at) < REPEAT_MS) {
                    continue;
                }
                if self.shown.len() > 4096 {
                    self.shown.clear();
                }
            }
            if let Some(text) = render::live(&self.report, line, start, &self.screen.style, verbose) {
                self.screen.print(&text);
            }
        }
    }

    fn summarize(&mut self, header: &Header) {
        self.screen.finish();
        // With JSON on standard output, the summary would corrupt it.
        let json_owns_stdout = self.screen.opts.json.as_ref().is_some_and(|j| j == "-") && !self.screen.to_stderr;
        if self.screen.opts.summary && !json_owns_stdout {
            let text = render::summary(&self.report, header, &self.screen.style);
            self.screen.print(text.trim_end_matches('\n'));
        }
    }
}

/// Keep taking events until the source is finished and drained, or `limit`
/// passes.
fn drain(source: &mut Source, session: &mut Session, limit: Duration) {
    let until = Instant::now() + limit;
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        match source.events.recv_timeout(left) {
            Ok(ev) => session.take(&ev),
            Err(_) => break,
        }
    }
}

/// Start the command so that it is watched from its first instruction.
///
/// Linux: the command starts as a stand-in that waits at the gate while the
/// sensor helper attaches to it, and is then let through.
#[cfg(not(target_os = "macos"))]
fn launch(command: &[OsString], opts: &Options) -> Result<(Child, Source), String> {
    let mut gate = match Gate::new() {
        Ok(g) => g,
        Err(e) => return Err(format!("could not prepare to start the command: {e}")),
    };
    let me = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return Err(format!("cannot find my own executable: {e}")),
    };
    if rustix::process::geteuid().is_root() && std::env::var_os("SUDO_USER").is_some() && !opts.quiet {
        say("started with sudo, so the command runs as root. Run ceynox-watch as yourself to avoid that");
    }

    // The stand-in: waits at the gate, then becomes the command.
    let mut child = match Command::new(me).arg("__exec").args(command).env(GATE_ENV, gate.path()).spawn() {
        Ok(c) => c,
        Err(e) => return Err(format!("could not start: {e}")),
    };
    // `--hosts` is for macOS; here addresses and names are always shown.
    let _ = opts.hosts;
    let source = match Source::start(&Scope::Pids(vec![child.id()]), opts.buffer_mb, opts.quiet) {
        Ok(s) => s,
        Err(why) => {
            drop(gate); // the stand-in sees no go-ahead and exits
            let _ = child.wait();
            return Err(why);
        }
    };
    if let Err(e) = gate.open() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("could not release the command: {e}"));
    }
    Ok((child, source))
}

/// Start the command so that it is watched from its first instruction.
///
/// macOS: the command runs under the system sandbox with a profile that
/// allows everything and reports what matters; see `sensor/macos.rs`.
#[cfg(target_os = "macos")]
fn launch(command: &[OsString], opts: &Options) -> Result<(Child, Source), String> {
    use crate::sensor::macos;

    let tag = macos::tag();
    // The profile matches paths as the kernel sees them, symlinks resolved
    // (/tmp is /private/tmp), so the home directory must be in that form.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/var/empty".into());
    let home = std::fs::canonicalize(&home).map_or(home, |p| p.to_string_lossy().into_owned());
    // sandbox-exec reports a missing program and a refused sandbox with the
    // same exit status. Settle the first here so the second is unambiguous.
    if !can_be_run(&command[0]) {
        say(format!("cannot run {}: no such program", command[0].to_string_lossy()));
        std::process::exit(127);
    }
    let shown = command.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    if opts.hosts && !opts.quiet {
        say("showing addresses and host names needs a packet capture; asking sudo to run Apple's tcpdump");
    }
    let (events, stream) =
        macos::Stream::start(&tag, rustix::process::getuid().as_raw(), shown, opts.hosts, |why| say(why))?;
    let child = Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(macos::profile(&tag, &home, opts.verbose))
        .args(command)
        .spawn()
        .map_err(|e| format!("could not start the sandbox: {e}"))?;
    Ok((child, Source { events, stdin: None, stream: Some(stream) }))
}

/// Is `program` a file, looked up the way the shell would?
#[cfg(target_os = "macos")]
fn can_be_run(program: &std::ffi::OsStr) -> bool {
    let path = std::path::Path::new(program);
    if path.components().count() > 1 {
        return path.is_file();
    }
    std::env::var_os("PATH").is_some_and(|dirs| std::env::split_paths(&dirs).any(|dir| dir.join(path).is_file()))
}

/// `ceynox-watch -- <command>`
pub fn run_command(command: Vec<OsString>, opts: Options) -> i32 {
    let screen = match Screen::new(opts, true) {
        Ok(s) => s,
        Err(e) => {
            say(e);
            return FAILURE;
        }
    };
    let (mut child, mut source) = match launch(&command, &screen.opts) {
        Ok(started) => started,
        Err(why) => {
            if !why.is_empty() {
                say(why);
            }
            return FAILURE;
        }
    };
    let root = child.id();
    let signals = Signals::install();

    let mut session = Session::new(screen);
    session.command = Some(Watched { pid: root, started: false, exited: false });
    let began = Instant::now();
    let mut forwarded = false;
    let status = loop {
        match source.events.recv_timeout(Duration::from_millis(10)) {
            Ok(ev) => {
                session.take(&ev);
                continue; // keep reading while there is a backlog
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                say("the sensor stopped; the rest of the run is not recorded");
                break child.wait();
            }
        }
        // A request to terminate us is a request to end the command.
        if signals.terminate.load(Ordering::Relaxed) && !forwarded {
            forwarded = true;
            if let Some(pid) = i32::try_from(root).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::TERM);
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => break Err(e),
        }
    };
    let elapsed_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);

    // The command has exited, but its last events may still be on their way
    // through the sensor. Its own exit is the last of them.
    // (macOS does not report exits; there the end mark does this job.)
    let until = Instant::now() + Duration::from_millis(500);
    while cfg!(not(target_os = "macos")) && !session.command.is_some_and(|c| c.exited) {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            break;
        };
        match source.events.recv_timeout(left) {
            Ok(ev) => session.take(&ev),
            Err(_) => break,
        }
    }
    source.finish();
    // On macOS each program start is looked up in the process table as it
    // is read, so a long run can still have reports queued.
    let patience = if cfg!(target_os = "macos") { 20 } else { 3 };
    drain(&mut source, &mut session, Duration::from_secs(patience));

    let (exit, code) = match status {
        Ok(s) => match (s.code(), s.signal()) {
            (Some(c), _) => (Some(Exit::Code(c)), c),
            (None, Some(sig)) => (Some(Exit::Signal(sig)), 128 + sig),
            (None, None) => (None, FAILURE),
        },
        Err(e) => {
            say(format!("lost track of the command: {e}"));
            (None, FAILURE)
        }
    };
    // 71 is how sandbox-exec says the sandbox could not be applied, which
    // happens when we are ourselves running inside one.
    let armed = session.command.is_some_and(|c| c.started);
    #[cfg(target_os = "macos")]
    if !armed && code == 71 {
        say(crate::sensor::macos::NESTED);
    }
    if armed {
        let title = command.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
        session.summarize(&Header { title, elapsed_ms, exit });
    } else {
        session.screen.finish();
    }
    code
}

/// `ceynox-watch --pid ...` and `ceynox-watch --all`
pub fn attach(scope: Scope, opts: Options) -> i32 {
    if cfg!(target_os = "macos") {
        say("watching processes that are already running (--pid, --all) works on Linux only. \
             On macOS, start the command under ceynox-watch: ceynox-watch -- <command>");
        return FAILURE;
    }
    let quiet = opts.quiet;
    let screen = match Screen::new(opts.clone(), false) {
        Ok(s) => s,
        Err(e) => {
            say(e);
            return FAILURE;
        }
    };
    let signals = Signals::install();
    let mut source = match Source::start(&scope, opts.buffer_mb, quiet) {
        Ok(s) => s,
        Err(why) => {
            if !why.is_empty() {
                say(why);
            }
            return FAILURE;
        }
    };
    let title = match &scope {
        Scope::All => "the whole machine".to_string(),
        Scope::Pids(pids) => format!("pid {}", pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")),
    };
    if !quiet {
        say(format!("watching {title}; press Ctrl-C to stop"));
    }

    let mut session = Session::new(screen);
    let began = Instant::now();
    let mut seen_any = false;
    loop {
        match source.events.recv_timeout(Duration::from_millis(50)) {
            Ok(ev) => {
                seen_any = true;
                session.take(&ev);
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                say("the sensor stopped");
                break;
            }
        }
        // Watching named processes ends when the last of them has.
        let all_gone = scope != Scope::All && seen_any && session.report.alive() == 0;
        if signals.any() || session.screen.gone || all_gone {
            break;
        }
    }
    let elapsed_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
    source.finish();
    drain(&mut source, &mut session, Duration::from_secs(3));
    session.summarize(&Header { title, elapsed_ms, exit: None });
    0
}

/// `ceynox-watch --view <file>`: show a file written with `--json` the way
/// the run itself would have been shown. With `follow`, keep showing what
/// is appended until interrupted, which is how to watch a full-screen
/// program: it runs in one terminal with `-q --json`, this in another.
pub fn view(file: &std::ffi::OsStr, follow: bool, opts: Options) -> i32 {
    let input = match File::open(file) {
        Ok(f) => f,
        Err(e) => {
            say(format!("cannot read {}: {e}", file.to_string_lossy()));
            return FAILURE;
        }
    };
    let mut screen = match Screen::new(opts, false) {
        Ok(s) => s,
        Err(e) => {
            say(e);
            return FAILURE;
        }
    };
    // Paths are shown relative to where the recorded command started, which
    // is not where the viewer happens to be.
    screen.style.base = None;
    let signals = Signals::install();
    let mut session = Session::new(screen);
    // The watcher's pid in the recording is not ours.
    session.me = 0;

    let mut reader = BufReader::new(input);
    let mut line = String::new();
    let mut skipped = 0u64;
    let (mut first, mut last) = (None, 0);
    loop {
        // A line still being written arrives in pieces; keep what was read
        // and add to it until its newline comes.
        match reader.read_line(&mut line) {
            Ok(0) if follow && !signals.any() && !session.screen.gone => {
                thread::sleep(Duration::from_millis(150));
                continue;
            }
            Ok(0) | Err(_) => break,
            Ok(_) if !line.ends_with('\n') => continue,
            Ok(_) => {}
        }
        match serde_json::from_str::<Event>(line.trim_end()) {
            Ok(ev) => {
                // The first program's directory stands in for the starting one.
                if session.screen.style.base.is_none()
                    && let What::Exec { cwd: Some(cwd), .. } = &ev.what
                {
                    session.screen.style.base = Some(as_reported(cwd));
                }
                first.get_or_insert(ev.ts);
                last = last.max(ev.ts);
                session.take(&ev);
            }
            Err(_) => skipped += 1,
        }
        line.clear();
    }
    if skipped > 0 {
        say(format!("{skipped} lines were not ceynox-watch events and were skipped"));
    }
    let title = file.to_string_lossy().into_owned();
    session.summarize(&Header { title, elapsed_ms: last.saturating_sub(first.unwrap_or(last)), exit: None });
    0
}
