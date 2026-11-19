//! Which file and network activity deserves a second look.
//!
//! This is a plain, readable catalog: places where credentials live, places
//! where a program can make itself run again, and network peers that hand
//! out credentials or control the machine. It flags; it does not judge. A
//! flagged read can be perfectly legitimate (`git` reads `~/.gitconfig`,
//! `aws` reads `~/.aws/credentials`). The point is that you get to see it.
//!
//! To add a place, add a line to [`RULES`]. First match wins.

use std::net::IpAddr;

use crate::event::{Peer, Proto};

/// Why something is worth showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// Keys, tokens and passwords.
    Credentials,
    /// Browser profiles: saved logins, session cookies.
    Browser,
    /// What was typed before: shell and REPL history.
    History,
    /// A change that makes something run again later.
    Persistence,
    /// A peer that can hand out credentials or control this machine.
    Control,
    /// A service often used to carry data out: easy to post to, hard to
    /// trace back. Each has ordinary uses too.
    Dropoff,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::Browser => "browser data",
            Self::History => "history",
            Self::Persistence => "persistence",
            Self::Control => "control",
            Self::Dropoff => "often used to send data out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Finding {
    pub category: Category,
    /// Short description of what this is, e.g. "AWS credentials".
    pub what: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum On {
    /// Any open.
    Open,
    /// Only when opened for writing.
    Write,
}

/// Where a pattern is anchored.
#[derive(Clone, Copy)]
enum At {
    /// Relative to any user's home directory.
    Home,
    /// An absolute path.
    Root,
    /// Anywhere: the pattern is matched against the end of the path.
    Any,
}

struct Rule {
    at: At,
    /// `*` matches within one path component, `**` across components.
    pattern: &'static str,
    on: On,
    /// `None` marks a path as known-harmless, stopping the search.
    finding: Option<(Category, &'static str)>,
}

const fn flag(at: At, pattern: &'static str, on: On, category: Category, what: &'static str) -> Rule {
    Rule { at, pattern, on, finding: Some((category, what)) }
}

const fn skip(at: At, pattern: &'static str) -> Rule {
    Rule { at, pattern, on: On::Open, finding: None }
}

use At::{Any, Home, Root};
use Category::{Browser, Control, Credentials, Dropoff, History, Persistence};
use On::{Open, Write};

#[rustfmt::skip]
static RULES: &[Rule] = &[
    // ---- SSH ----
    flag(Home, ".ssh/authorized_keys*", Write, Persistence, "SSH authorized keys"),
    skip(Home, ".ssh/*.pub"),
    skip(Home, ".ssh/known_hosts*"),
    skip(Home, ".ssh/authorized_keys*"),
    flag(Home, ".ssh/config", Write, Persistence, "SSH client config"),
    skip(Home, ".ssh/config"),
    flag(Home, ".ssh", Open, Credentials, "SSH folder listed"),
    flag(Home, ".ssh/**", Open, Credentials, "SSH private key"),
    flag(Root, "/etc/ssh/ssh_host_*_key", Open, Credentials, "SSH host key"),

    // ---- looking around: the folders secrets live in, listed ----
    flag(Home, ".aws", Open, Credentials, "AWS folder listed"),
    flag(Home, ".gnupg", Open, Credentials, "GPG folder listed"),
    flag(Home, ".kube", Open, Credentials, "Kubernetes folder listed"),
    flag(Home, ".config/gcloud", Open, Credentials, "Google Cloud folder listed"),
    flag(Home, ".password-store", Open, Credentials, "password store listed"),
    flag(Home, "Library/Keychains", Open, Credentials, "keychain folder listed"),

    // ---- cloud ----
    flag(Home, ".aws/credentials", Open, Credentials, "AWS credentials"),
    flag(Home, ".aws/config", Open, Credentials, "AWS config"),
    flag(Home, ".aws/sso/cache/*", Open, Credentials, "AWS SSO token"),
    flag(Home, ".aws/cli/cache/*", Open, Credentials, "AWS session token"),
    flag(Home, ".config/gcloud/credentials.db", Open, Credentials, "Google Cloud credentials"),
    flag(Home, ".config/gcloud/access_tokens.db", Open, Credentials, "Google Cloud access tokens"),
    flag(Home, ".config/gcloud/application_default_credentials.json", Open, Credentials, "Google Cloud credentials"),
    flag(Home, ".config/gcloud/legacy_credentials/**", Open, Credentials, "Google Cloud credentials"),
    flag(Home, ".azure/msal_token_cache*", Open, Credentials, "Azure token cache"),
    flag(Home, ".azure/accessTokens.json", Open, Credentials, "Azure access tokens"),
    flag(Home, ".azure/azureProfile.json", Open, Credentials, "Azure profile"),
    flag(Home, ".kube/config", Open, Credentials, "Kubernetes credentials"),
    flag(Home, ".docker/config.json", Open, Credentials, "Docker registry credentials"),
    flag(Home, ".config/doctl/config.yaml", Open, Credentials, "DigitalOcean token"),
    flag(Home, ".oci/config", Open, Credentials, "Oracle Cloud credentials"),
    flag(Home, ".terraform.d/credentials.tfrc.json", Open, Credentials, "Terraform Cloud token"),
    flag(Home, ".vault-token", Open, Credentials, "Vault token"),
    flag(Home, ".config/hcloud/cli.toml", Open, Credentials, "Hetzner Cloud token"),
    flag(Home, ".fly/config.yml", Open, Credentials, "Fly.io token"),
    flag(Home, ".config/heroku/**", Open, Credentials, "Heroku credentials"),
    flag(Home, ".wrangler/config/*", Open, Credentials, "Cloudflare token"),
    flag(Home, ".config/.wrangler/config/*", Open, Credentials, "Cloudflare token"),
    flag(Root, "/var/run/secrets/**", Open, Credentials, "mounted secret"),
    flag(Root, "/run/secrets/**", Open, Credentials, "mounted secret"),

    // ---- package registries ----
    flag(Home, ".npmrc", Open, Credentials, "npm token"),
    flag(Home, ".yarnrc.yml", Open, Credentials, "Yarn config (registry token)"),
    flag(Home, ".pypirc", Open, Credentials, "PyPI token"),
    flag(Home, ".cargo/credentials", Open, Credentials, "crates.io token"),
    flag(Home, ".cargo/credentials.toml", Open, Credentials, "crates.io token"),
    flag(Home, ".gem/credentials", Open, Credentials, "RubyGems token"),
    flag(Home, ".local/share/gem/credentials", Open, Credentials, "RubyGems token"),
    flag(Home, ".m2/settings.xml", Open, Credentials, "Maven credentials"),
    flag(Home, ".m2/settings-security.xml", Open, Credentials, "Maven master password"),
    flag(Home, ".gradle/gradle.properties", Open, Credentials, "Gradle credentials"),
    flag(Home, ".composer/auth.json", Open, Credentials, "Composer credentials"),
    flag(Home, ".config/composer/auth.json", Open, Credentials, "Composer credentials"),
    flag(Home, ".nuget/NuGet/NuGet.Config", Open, Credentials, "NuGet credentials"),

    // ---- source control ----
    flag(Home, ".git-credentials", Open, Credentials, "Git credentials"),
    flag(Home, ".config/git/credentials", Open, Credentials, "Git credentials"),
    flag(Home, ".config/gh/hosts.yml", Open, Credentials, "GitHub CLI token"),
    flag(Home, ".config/glab-cli/config.yml", Open, Credentials, "GitLab CLI token"),
    flag(Home, ".netrc", Open, Credentials, "netrc logins"),
    flag(Home, ".gitconfig", Write, Persistence, "Git config"),
    flag(Any, ".git/hooks/*", Write, Persistence, "Git hook"),

    // ---- AI tools ----
    flag(Home, ".claude/.credentials.json", Open, Credentials, "Claude Code credentials"),
    flag(Home, ".codex/auth.json", Open, Credentials, "Codex credentials"),
    flag(Home, ".gemini/oauth_creds.json", Open, Credentials, "Gemini CLI credentials"),
    flag(Home, ".config/github-copilot/hosts.json", Open, Credentials, "GitHub Copilot token"),
    flag(Home, ".config/github-copilot/apps.json", Open, Credentials, "GitHub Copilot token"),
    flag(Home, ".cache/huggingface/token", Open, Credentials, "Hugging Face token"),
    flag(Home, ".huggingface/token", Open, Credentials, "Hugging Face token"),
    flag(Home, ".config/openai/**", Open, Credentials, "OpenAI credentials"),

    // ---- AI agents: what they are told, and which tools they load ----
    // A change here outlives the run: the agent reads it next time it starts.
    flag(Home, ".claude/settings.json", Write, Persistence, "Claude Code settings"),
    flag(Home, ".claude/settings.local.json", Write, Persistence, "Claude Code settings"),
    flag(Home, ".claude/CLAUDE.md", Write, Persistence, "Claude Code instructions"),
    flag(Home, ".codex/config.toml", Write, Persistence, "Codex config"),
    flag(Home, ".codex/AGENTS.md", Write, Persistence, "Codex instructions"),
    flag(Home, ".gemini/settings.json", Write, Persistence, "Gemini CLI settings"),
    flag(Home, ".gemini/GEMINI.md", Write, Persistence, "Gemini CLI instructions"),
    flag(Home, ".cursor/mcp.json", Write, Persistence, "Cursor MCP servers"),
    flag(Home, ".codeium/windsurf/mcp_config.json", Write, Persistence, "Windsurf MCP servers"),
    flag(Home, ".config/Claude/claude_desktop_config.json", Write, Persistence, "Claude Desktop MCP servers"),
    flag(Home, "Library/Application Support/Claude/claude_desktop_config.json", Write, Persistence, "Claude Desktop MCP servers"),
    flag(Home, ".config/Code/User/mcp.json", Write, Persistence, "VS Code MCP servers"),
    flag(Home, "Library/Application Support/Code/User/mcp.json", Write, Persistence, "VS Code MCP servers"),

    // ---- password stores and keys ----
    flag(Home, ".gnupg/private-keys-v1.d/**", Open, Credentials, "GPG private key"),
    flag(Home, ".gnupg/secring.gpg", Open, Credentials, "GPG private keyring"),
    flag(Home, ".password-store/**", Open, Credentials, "pass password store"),
    flag(Home, ".local/share/keyrings/**", Open, Credentials, "desktop keyring"),
    flag(Home, "Library/Keychains/**", Open, Credentials, "macOS keychain"),
    flag(Root, "/Library/Keychains/**", Open, Credentials, "macOS system keychain"),
    flag(Home, ".config/op/**", Open, Credentials, "1Password CLI data"),
    flag(Home, ".config/Bitwarden/**", Open, Credentials, "Bitwarden data"),
    flag(Home, ".config/Bitwarden CLI/**", Open, Credentials, "Bitwarden data"),
    flag(Any, "*.kdbx", Open, Credentials, "KeePass database"),

    // ---- wallets ----
    flag(Home, ".bitcoin/**/wallet.dat", Open, Credentials, "Bitcoin wallet"),
    flag(Home, ".bitcoin/wallet.dat", Open, Credentials, "Bitcoin wallet"),
    flag(Home, ".ethereum/keystore/**", Open, Credentials, "Ethereum keystore"),
    flag(Home, ".config/solana/id.json", Open, Credentials, "Solana keypair"),
    flag(Home, ".electrum/wallets/**", Open, Credentials, "Electrum wallet"),
    flag(Home, ".config/Exodus/**", Open, Credentials, "Exodus wallet"),
    flag(Home, "Library/Application Support/Exodus/**", Open, Credentials, "Exodus wallet"),

    // ---- browsers ----
    flag(Any, "Login Data", Open, Browser, "browser saved logins"),
    flag(Any, "Login Data For Account", Open, Browser, "browser saved logins"),
    flag(Any, "Cookies", Open, Browser, "browser cookies"),
    flag(Any, "Web Data", Open, Browser, "browser autofill data"),
    flag(Any, "Local Extension Settings/**", Open, Browser, "browser extension data"),
    flag(Home, ".mozilla/**/logins.json", Open, Browser, "Firefox saved logins"),
    flag(Home, ".mozilla/**/key4.db", Open, Browser, "Firefox key database"),
    flag(Home, ".mozilla/**/cookies.sqlite", Open, Browser, "Firefox cookies"),
    flag(Home, "Library/Application Support/Firefox/**/logins.json", Open, Browser, "Firefox saved logins"),
    flag(Home, "Library/Application Support/Firefox/**/key4.db", Open, Browser, "Firefox key database"),
    flag(Home, "Library/Application Support/Firefox/**/cookies.sqlite", Open, Browser, "Firefox cookies"),
    flag(Home, "Library/Cookies/**", Open, Browser, "Safari cookies"),

    // ---- environment files ----
    skip(Any, ".env.example"),
    skip(Any, ".env.sample"),
    skip(Any, ".env.template"),
    skip(Any, ".env.dist"),
    flag(Any, ".env", Open, Credentials, "environment file"),
    flag(Any, ".env.*", Open, Credentials, "environment file"),
    flag(Any, ".envrc", Open, Credentials, "environment file"),

    // ---- history ----
    flag(Home, ".bash_history", Open, History, "shell history"),
    flag(Home, ".zsh_history", Open, History, "shell history"),
    flag(Home, ".zhistory", Open, History, "shell history"),
    flag(Home, ".local/share/fish/fish_history", Open, History, "shell history"),
    flag(Home, ".python_history", Open, History, "Python REPL history"),
    flag(Home, ".node_repl_history", Open, History, "Node REPL history"),
    flag(Home, ".psql_history", Open, History, "psql history"),
    flag(Home, ".mysql_history", Open, History, "MySQL history"),

    // ---- other processes and system secrets ----
    flag(Root, "/proc/*/environ", Open, Credentials, "another process's environment"),
    flag(Root, "/proc/*/mem", Open, Credentials, "another process's memory"),
    flag(Root, "/etc/shadow", Open, Credentials, "password hashes"),
    flag(Root, "/etc/gshadow", Open, Credentials, "group password hashes"),
    flag(Root, "/etc/sudoers", Write, Persistence, "sudo rules"),
    flag(Root, "/etc/sudoers.d/*", Write, Persistence, "sudo rules"),
    flag(Root, "/etc/passwd", Write, Persistence, "user accounts"),

    // ---- runs again later ----
    flag(Home, ".bashrc", Write, Persistence, "shell startup file"),
    flag(Home, ".bash_profile", Write, Persistence, "shell startup file"),
    flag(Home, ".bash_login", Write, Persistence, "shell startup file"),
    flag(Home, ".profile", Write, Persistence, "shell startup file"),
    flag(Home, ".zshrc", Write, Persistence, "shell startup file"),
    flag(Home, ".zshenv", Write, Persistence, "shell startup file"),
    flag(Home, ".zprofile", Write, Persistence, "shell startup file"),
    flag(Home, ".zlogin", Write, Persistence, "shell startup file"),
    flag(Home, ".config/fish/config.fish", Write, Persistence, "shell startup file"),
    flag(Home, ".config/fish/conf.d/*", Write, Persistence, "shell startup file"),
    flag(Home, ".config/autostart/*", Write, Persistence, "desktop autostart entry"),
    flag(Home, ".config/systemd/user/**", Write, Persistence, "systemd user unit"),
    flag(Home, "Library/LaunchAgents/*", Write, Persistence, "macOS launch agent"),
    flag(Root, "/Library/LaunchAgents/*", Write, Persistence, "macOS launch agent"),
    flag(Root, "/Library/LaunchDaemons/*", Write, Persistence, "macOS launch daemon"),
    flag(Root, "/etc/systemd/system/**", Write, Persistence, "systemd unit"),
    flag(Root, "/usr/lib/systemd/system/**", Write, Persistence, "systemd unit"),
    flag(Root, "/etc/cron*/**", Write, Persistence, "cron job"),
    flag(Root, "/etc/crontab", Write, Persistence, "cron job"),
    flag(Root, "/var/spool/cron/**", Write, Persistence, "cron job"),
    flag(Root, "/etc/profile", Write, Persistence, "system shell startup file"),
    flag(Root, "/etc/profile.d/*", Write, Persistence, "system shell startup file"),
    flag(Root, "/etc/ld.so.preload", Write, Persistence, "library preload list"),
    flag(Root, "/etc/hosts", Write, Persistence, "hosts file"),
];

/// Hosts that packages and scripts rarely have a reason to talk to, and
/// that stolen data is often sent to. Matched against the host name and
/// everything under it (`hooks.slack.com` also matches `x.hooks.slack.com`).
///
/// To add one, add a line. Keep it to services whose main use is to receive
/// arbitrary data from anyone: a general-purpose site does not belong here.
#[rustfmt::skip]
static HOSTS: &[(&str, &str)] = &[
    // ---- paste and file-drop sites ----
    ("pastebin.com", "paste site"),
    ("paste.ee", "paste site"),
    ("hastebin.com", "paste site"),
    ("dpaste.com", "paste site"),
    ("rentry.co", "paste site"),
    ("termbin.com", "paste site"),
    ("ix.io", "paste site"),
    ("0x0.st", "file drop"),
    ("transfer.sh", "file drop"),
    ("file.io", "file drop"),
    ("gofile.io", "file drop"),
    ("catbox.moe", "file drop"),

    // ---- chat webhooks and bots ----
    ("discord.com", "Discord (webhooks)"),
    ("discordapp.com", "Discord (webhooks)"),
    ("api.telegram.org", "Telegram bot API"),
    ("hooks.slack.com", "Slack webhook"),

    // ---- request catchers ----
    ("webhook.site", "request catcher"),
    ("requestbin.com", "request catcher"),
    ("pipedream.net", "request catcher"),
    ("beeceptor.com", "request catcher"),
    ("interact.sh", "request catcher"),
    ("oast.fun", "request catcher"),
    ("oast.pro", "request catcher"),
    ("oast.live", "request catcher"),
    ("oast.site", "request catcher"),
    ("oast.online", "request catcher"),
    ("oast.me", "request catcher"),
    ("oastify.com", "request catcher"),
    ("burpcollaborator.net", "request catcher"),

    // ---- tunnels to someone's machine ----
    ("ngrok.io", "tunnelling service"),
    ("ngrok.app", "tunnelling service"),
    ("ngrok-free.app", "tunnelling service"),
    ("ngrok-free.dev", "tunnelling service"),
    ("trycloudflare.com", "tunnelling service"),
    ("serveo.net", "tunnelling service"),
    ("localhost.run", "tunnelling service"),
    ("loca.lt", "tunnelling service"),

    // ---- dynamic DNS ----
    ("duckdns.org", "dynamic DNS host"),
    ("ddns.net", "dynamic DNS host"),
    ("hopto.org", "dynamic DNS host"),
    ("zapto.org", "dynamic DNS host"),
    ("sytes.net", "dynamic DNS host"),
];

/// What kind of drop-off host `name` is, if it is on the list.
fn dropoff(name: &str) -> Option<&'static str> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    HOSTS.iter().find_map(|(host, what)| {
        let under = name.strip_suffix(host)?;
        (under.is_empty() || under.ends_with('.')).then_some(*what)
    })
}

/// Classifies paths and peers. Holds the home directories to recognise.
#[derive(Debug, Clone)]
pub struct Classifier {
    /// An extra home directory (no trailing slash), for homes outside the
    /// usual locations.
    home: Option<String>,
}

impl Classifier {
    pub fn new(home: Option<String>) -> Self {
        let home = home.map(|h| h.trim_end_matches('/').to_string()).filter(|h| h.len() > 1);
        Self { home }
    }

    /// The part of `path` below a home directory, if it is in one.
    pub fn home_relative<'p>(&self, path: &'p str) -> Option<&'p str> {
        if let Some(home) = &self.home
            && let Some(rest) = path.strip_prefix(home.as_str())
            && let Some(rest) = rest.strip_prefix('/')
        {
            return Some(rest);
        }
        for single in ["/root/", "/var/root/"] {
            if let Some(rest) = path.strip_prefix(single) {
                return Some(rest);
            }
        }
        for parent in ["/home/", "/Users/"] {
            if let Some(rest) = path.strip_prefix(parent) {
                let (user, rest) = rest.split_once('/')?;
                return (!user.is_empty() && user != "Shared").then_some(rest);
            }
        }
        None
    }

    pub fn open(&self, path: &str, write: bool) -> Option<Finding> {
        let in_home = self.home_relative(path);
        for rule in RULES {
            if rule.on == Write && !write {
                continue;
            }
            let hit = match rule.at {
                Home => in_home.is_some_and(|rest| glob(rule.pattern, rest)),
                Root => glob(rule.pattern, path),
                Any => glob_suffix(rule.pattern, path),
            };
            if hit {
                return rule.finding.map(|(category, what)| Finding { category, what });
            }
        }
        None
    }

    /// `name` is the host name the peer was looked up by, when known.
    pub fn peer(&self, peer: &Peer, name: Option<&str>) -> Option<Finding> {
        if let Some(what) = name.and_then(dropoff) {
            return Some(Finding { category: Dropoff, what });
        }
        let (category, what) = match peer {
            Peer::Ip { ip, .. } => match ip {
                // Link-local metadata services hand instance credentials to
                // anything on the machine that asks.
                IpAddr::V4(v4) if v4.octets() == [169, 254, 169, 254] || v4.octets() == [169, 254, 170, 2] => {
                    (Credentials, "cloud metadata service")
                }
                IpAddr::V6(v6) if v6.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254] => {
                    (Credentials, "cloud metadata service")
                }
                _ => return None,
            },
            Peer::Port { .. } => return None,
            Peer::Unix { path } => {
                let name = path.rsplit('/').next().unwrap_or(path);
                if name == "docker.sock" || name == "containerd.sock" || name == "podman.sock" || name == "crio.sock" {
                    (Control, "container runtime socket")
                } else if name.starts_with("agent.") && path.contains("/ssh-")
                    || path.contains("com.apple.launchd.") && name == "Listeners"
                    || name == "S.gpg-agent.ssh"
                {
                    (Credentials, "SSH agent")
                } else if name.starts_with("S.gpg-agent") {
                    (Credentials, "GPG agent")
                } else if path.contains("/keyring/") {
                    (Credentials, "desktop keyring")
                } else {
                    return None;
                }
            }
        };
        Some(Finding { category, what })
    }
}

/// Local plumbing every program touches without meaning anything by it:
/// name-service caches, the system log, the message bus. Left out of the
/// output unless everything is asked for.
pub fn is_background(peer: &Peer) -> bool {
    let path = match peer {
        // Asking the machine's or the network's own resolver for a name.
        // The names themselves show up on the connections that follow.
        Peer::Ip { ip, port: 53 | 5353, .. } => {
            return match ip {
                IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
                IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() || a.is_unicast_link_local(),
            };
        }
        // Without an address there is no telling whose resolver it is.
        Peer::Port { port } => return matches!(port, 53 | 5353),
        // Clock synchronisation.
        Peer::Ip { port: 123, proto: Proto::Udp, .. } => return true,
        // Datagrams to this machine itself: services talking to their own
        // helpers. (Local TCP stays visible: that is how a program reaches
        // a local proxy, database or agent.)
        Peer::Ip { ip, proto: Proto::Udp, .. } => return ip.is_loopback(),
        Peer::Ip { .. } => return false,
        Peer::Unix { path } => path,
    };
    // The system's own service plumbing: name-service caches, the log, the
    // message bus, and systemd's sockets for looking up users and reporting
    // readiness.
    path.ends_with("/nscd/socket")
        || path == "/dev/log"
        || path.starts_with("/run/systemd/")
        || path.starts_with("/var/run/systemd/")
        || path.ends_with("/system_bus_socket")
        || (path.starts_with("/run/user/") && (path.ends_with("/bus") || path.contains("/systemd/")))
        || path.ends_with("/var/run/mDNSResponder")
        || path.ends_with("/var/run/syslog")
}

#[cfg(any(target_os = "macos", test))]
/// The catalog as regular expressions, for sensors that have to tell the
/// operating system in advance which paths to report (the macOS sandbox).
/// Returns expressions for paths worth reporting when read. They may match
/// more than the catalog flags; every reported path still goes through
/// [`Classifier::open`].
pub fn read_patterns(home: &str) -> Vec<String> {
    let home = regex_escape(home.trim_end_matches('/'));
    let mut out: Vec<String> = RULES
        .iter()
        .filter(|r| r.on == Open && r.finding.is_some())
        .map(|r| {
            let body = glob_to_regex(r.pattern);
            match r.at {
                Home => format!("^{home}/{body}$"),
                // On macOS /etc, /var and /tmp live under /private.
                Root => format!("^(/private)?{body}$"),
                Any => format!("/{body}$"),
            }
        })
        .collect();
    out.dedup();
    out
}

#[cfg(any(target_os = "macos", test))]
fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | ' ' | '~' | '@' | ',' | ':' | '%')) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(any(target_os = "macos", test))]
fn glob_to_regex(pattern: &str) -> String {
    let mut out = String::new();
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("**/") {
            // `**/x` also matches `x` itself.
            out.push_str("(.*/)?");
            rest = after;
        } else if let Some(after) = rest.strip_prefix("**") {
            out.push_str(".*");
            rest = after;
        } else if let Some(after) = rest.strip_prefix('*') {
            out.push_str("[^/]*");
            rest = after;
        } else {
            let mut chars = rest.chars();
            let c = chars.next().unwrap_or_default();
            out.push_str(&regex_escape(c.encode_utf8(&mut [0; 4])));
            rest = chars.as_str();
        }
    }
    out
}

/// Does `pattern` match all of `text`? `*` matches any run of characters
/// inside one path component; `**` matches any run including `/`.
pub fn glob(pattern: &str, text: &str) -> bool {
    glob_bytes(pattern.as_bytes(), text.as_bytes())
}

/// Does `pattern` match the last components of `text`?
fn glob_suffix(pattern: &str, text: &str) -> bool {
    let parts = pattern.split('/').count();
    // Start of the suffix made of the last `parts` components (a `**` in the
    // pattern can still reach further back; try every component boundary).
    let has_deep = pattern.contains("**");
    let mut starts: Vec<usize> = text.match_indices('/').map(|(i, _)| i + 1).collect();
    starts.insert(0, 0);
    let from = if has_deep { 0 } else { starts.len().saturating_sub(parts) };
    starts[from..].iter().any(|&s| glob(pattern, &text[s..]))
}

fn glob_bytes(p: &[u8], t: &[u8]) -> bool {
    match p {
        [] => t.is_empty(),
        [b'*', b'*', rest @ ..] => {
            // `**/x` also matches `x` itself.
            let rest_no_slash = rest.strip_prefix(b"/").unwrap_or(rest);
            (0..=t.len()).any(|i| glob_bytes(rest, &t[i..]) || (i == 0 && glob_bytes(rest_no_slash, t)))
        }
        [b'*', rest @ ..] => {
            let limit = t.iter().position(|&c| c == b'/').unwrap_or(t.len());
            (0..=limit).any(|i| glob_bytes(rest, &t[i..]))
        }
        [c, rest @ ..] => t.first() == Some(c) && glob_bytes(rest, &t[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Proto;

    fn c() -> Classifier {
        Classifier::new(Some("/srv/homes/dana".into()))
    }

    fn what(path: &str, write: bool) -> Option<&'static str> {
        c().open(path, write).map(|f| f.what)
    }

    #[test]
    fn glob_semantics() {
        assert!(glob(".ssh/*", ".ssh/id_ed25519"));
        assert!(!glob(".ssh/*", ".ssh/keys/id"));
        assert!(glob(".ssh/**", ".ssh/keys/id"));
        assert!(glob(".mozilla/**/key4.db", ".mozilla/firefox/abc.default/key4.db"));
        assert!(glob(".bitcoin/**/wallet.dat", ".bitcoin/wallets/main/wallet.dat"));
        assert!(glob("/proc/*/environ", "/proc/123/environ"));
        assert!(!glob("/proc/*/environ", "/proc/123/task/5/environ"));
        assert!(glob(".env.*", ".env.production"));
        assert!(!glob(".env", ".envoy"));
        assert!(glob("a*c", "abc") && glob("a*c", "ac") && !glob("a*c", "ab"));
    }

    #[test]
    fn catalog_as_regular_expressions() {
        assert_eq!(glob_to_regex(".ssh/**"), "\\.ssh/.*");
        assert_eq!(glob_to_regex(".aws/sso/cache/*"), "\\.aws/sso/cache/[^/]*");
        assert_eq!(glob_to_regex(".mozilla/**/key4.db"), "\\.mozilla/(.*/)?key4\\.db");
        assert_eq!(regex_escape("/Users/a.b (c)"), "/Users/a\\.b \\(c\\)");
        let pats = read_patterns("/Users/sam/");
        assert!(pats.contains(&"^/Users/sam/\\.aws/credentials$".to_string()));
        assert!(pats.contains(&"^(/private)?/etc/shadow$".to_string()));
        assert!(pats.contains(&"/\\.env$".to_string()));
        assert!(pats.contains(&"/[^/]*\\.kdbx$".to_string()));
        // Write-only rules and exceptions are not reads to report.
        assert!(!pats.iter().any(|p| p.contains("bashrc") || p.contains("\\.pub")));
        // Nothing that could end the quoted expression it is embedded in.
        assert!(pats.iter().all(|p| !p.contains('"')));
    }

    #[test]
    fn recognises_home_directories() {
        let c = c();
        assert_eq!(c.home_relative("/home/sam/.npmrc"), Some(".npmrc"));
        assert_eq!(c.home_relative("/Users/sam/.aws/credentials"), Some(".aws/credentials"));
        assert_eq!(c.home_relative("/root/.ssh/id_rsa"), Some(".ssh/id_rsa"));
        assert_eq!(c.home_relative("/srv/homes/dana/.netrc"), Some(".netrc"));
        assert_eq!(c.home_relative("/srv/homes/danaX/.netrc"), None);
        assert_eq!(c.home_relative("/home/sam"), None);
        assert_eq!(c.home_relative("/Users/Shared/x"), None);
        assert_eq!(c.home_relative("/usr/lib/x"), None);
    }

    #[test]
    fn ssh_directory() {
        assert_eq!(what("/home/sam/.ssh/id_ed25519", false), Some("SSH private key"));
        assert_eq!(what("/home/sam/.ssh/work/deploy_key", false), Some("SSH private key"));
        assert_eq!(what("/home/sam/.ssh/id_ed25519.pub", false), None);
        assert_eq!(what("/home/sam/.ssh/known_hosts", false), None);
        assert_eq!(what("/home/sam/.ssh/config", false), None);
        assert_eq!(what("/home/sam/.ssh", false), Some("SSH folder listed"));
        assert_eq!(what("/Users/sam/.aws", false), Some("AWS folder listed"));
        assert_eq!(what("/Users/sam/Library/Keychains", false), Some("keychain folder listed"));
        assert_eq!(what("/home/sam/.ssh/authorized_keys", false), None);
        assert_eq!(what("/home/sam/.ssh/authorized_keys", true), Some("SSH authorized keys"));
        assert_eq!(what("/home/sam/.ssh/config", true), Some("SSH client config"));
    }

    #[test]
    fn credentials_and_env_files() {
        assert_eq!(what("/Users/sam/.aws/credentials", false), Some("AWS credentials"));
        assert_eq!(what("/root/.npmrc", false), Some("npm token"));
        assert_eq!(what("/srv/homes/dana/.config/gh/hosts.yml", false), Some("GitHub CLI token"));
        assert_eq!(what("/home/sam/app/.env", false), Some("environment file"));
        assert_eq!(what("/home/sam/app/.env.production", false), Some("environment file"));
        assert_eq!(what("/home/sam/app/.env.example", false), None);
        assert_eq!(what("/home/sam/app/.envoy/config", false), None);
        assert_eq!(what("/work/secrets.kdbx", false), Some("KeePass database"));
        assert_eq!(what("/proc/41/environ", false), Some("another process's environment"));
        assert_eq!(what("/var/run/secrets/kubernetes.io/serviceaccount/token", false), Some("mounted secret"));
    }

    #[test]
    fn browser_profiles() {
        assert_eq!(what("/home/sam/.config/google-chrome/Default/Login Data", false), Some("browser saved logins"));
        assert_eq!(
            what("/Users/sam/Library/Application Support/Google/Chrome/Profile 1/Cookies", false),
            Some("browser cookies")
        );
        assert_eq!(
            what(
                "/home/sam/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/abc/000003.log",
                false
            ),
            Some("browser extension data")
        );
        assert_eq!(what("/home/sam/.mozilla/firefox/x.default/key4.db", false), Some("Firefox key database"));
        assert_eq!(what("/home/sam/recipes/Cookies.md", false), None);
    }

    #[test]
    fn persistence_needs_a_write() {
        assert_eq!(what("/home/sam/.bashrc", false), None);
        assert_eq!(what("/home/sam/.bashrc", true), Some("shell startup file"));
        assert_eq!(what("/home/sam/proj/.git/hooks/pre-commit", true), Some("Git hook"));
        assert_eq!(what("/home/sam/proj/.git/hooks/pre-commit", false), None);
        assert_eq!(what("/Users/sam/Library/LaunchAgents/com.x.plist", true), Some("macOS launch agent"));
        assert_eq!(what("/etc/cron.d/job", true), Some("cron job"));
        assert_eq!(what("/etc/hosts", false), None);
    }

    #[test]
    fn agent_configuration_is_flagged_when_changed() {
        assert_eq!(what("/home/sam/.claude/settings.json", true), Some("Claude Code settings"));
        assert_eq!(what("/home/sam/.claude/settings.json", false), None, "agents read their own settings all day");
        assert_eq!(what("/home/sam/.cursor/mcp.json", true), Some("Cursor MCP servers"));
        assert_eq!(what("/home/sam/.codex/config.toml", true), Some("Codex config"));
        assert_eq!(
            what("/Users/sam/Library/Application Support/Claude/claude_desktop_config.json", true),
            Some("Claude Desktop MCP servers")
        );
        // Credentials stay flagged on any open, ahead of these.
        assert_eq!(what("/home/sam/.claude/.credentials.json", false), Some("Claude Code credentials"));
        // A project's own copy is the project's business.
        assert_eq!(what("/home/sam/proj/.claude/settings.json", true), None);
        // State an agent rewrites constantly would only teach people to stop reading.
        assert_eq!(what("/home/sam/.claude.json", true), None);
    }

    #[test]
    fn ordinary_files_are_not_flagged() {
        for p in [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/home/sam/proj/package.json",
            "/home/sam/proj/node_modules/left-pad/index.js",
            "/home/sam/.npm/_cacache/index-v5/aa/bb",
            "/home/sam/.cache/pip/http/a",
            "/etc/resolv.conf",
            "/tmp/x",
        ] {
            assert_eq!(what(p, false), None, "{p}");
            assert_eq!(what(p, true), None, "{p} (write)");
        }
    }

    #[test]
    fn peers() {
        let c = c();
        let ip = |s: &str| Peer::Ip { ip: s.parse().expect("ip"), port: 80, proto: Proto::Tcp };
        let unix = |s: &str| Peer::Unix { path: s.into() };
        assert_eq!(c.peer(&ip("169.254.169.254"), None).map(|f| f.what), Some("cloud metadata service"));
        assert_eq!(c.peer(&ip("fd00:ec2::254"), None).map(|f| f.what), Some("cloud metadata service"));
        assert_eq!(c.peer(&ip("104.16.1.1"), None), None);
        assert_eq!(c.peer(&unix("/var/run/docker.sock"), None).map(|f| f.what), Some("container runtime socket"));
        assert_eq!(c.peer(&unix("/tmp/ssh-XXXXabcd/agent.1234"), None).map(|f| f.what), Some("SSH agent"));
        assert_eq!(c.peer(&unix("/run/user/1000/gnupg/S.gpg-agent"), None).map(|f| f.what), Some("GPG agent"));
        assert_eq!(c.peer(&unix("/var/run/nscd/socket"), None), None);
        assert_eq!(c.peer(&unix("@/tmp/.X11-unix/X0"), None), None);
        assert!(is_background(&unix("/var/run/nscd/socket")));
        assert!(is_background(&unix("/run/systemd/journal/socket")));
        assert!(!is_background(&unix("/var/run/docker.sock")));
        assert!(!is_background(&ip("127.0.0.1")));
        let dns = |s: &str| Peer::Ip { ip: s.parse().expect("ip"), port: 53, proto: Proto::Udp };
        assert!(is_background(&dns("127.0.0.53")));
        assert!(is_background(&dns("192.168.1.1")));
        assert!(!is_background(&dns("8.8.8.8")));
        // Hosts often used to send data out, by name.
        let named = |name: &str| c.peer(&ip("203.0.113.9"), Some(name)).map(|f| (f.category, f.what));
        assert_eq!(named("pastebin.com"), Some((Dropoff, "paste site")));
        assert_eq!(named("Abc123.Ngrok-Free.app."), Some((Dropoff, "tunnelling service")));
        assert_eq!(named("hooks.slack.com"), Some((Dropoff, "Slack webhook")));
        assert_eq!(named("eu.api.telegram.org"), Some((Dropoff, "Telegram bot API")));
        assert_eq!(named("slack.com"), None, "only the webhook host, not the whole site");
        assert_eq!(named("notpastebin.com"), None, "a name that merely ends the same way");
        assert_eq!(named("pastebin.com.example.org"), None);
        assert_eq!(named("registry.npmjs.org"), None);
        assert_eq!(named("pypi.org"), None);
        // The metadata service is still recognised by address, name or not.
        assert_eq!(c.peer(&ip("169.254.169.254"), Some("x")).map(|f| f.what), Some("cloud metadata service"));

        assert!(is_background(&Peer::Port { port: 53 }));
        let udp = |s: &str, port| Peer::Ip { ip: s.parse().expect("ip"), port, proto: Proto::Udp };
        assert!(is_background(&udp("91.189.91.112", 123)), "time sync");
        assert!(is_background(&udp("127.0.0.1", 47367)), "a service talking to itself");
        assert!(is_background(&udp("::1", 9000)));
        assert!(!is_background(&udp("192.0.2.9", 9999)), "a datagram to somewhere else");
        assert!(!is_background(&ip("127.0.0.1")), "local TCP stays visible");
        for path in [
            "/run/systemd/userdb/io.systemd.DynamicUser",
            "/run/systemd/notify",
            "/run/systemd/io.systemd.Login",
            "/run/user/1000/bus",
            "/run/user/1000/systemd/private",
        ] {
            assert!(is_background(&unix(path)), "{path}");
        }
        assert!(!is_background(&unix("/run/user/1000/keyring/control")));
        assert!(!is_background(&unix("/run/user/1000/gnupg/S.gpg-agent")));
        assert!(!is_background(&unix("/run/docker.sock")));
        assert!(!is_background(&Peer::Port { port: 443 }));
        assert_eq!(c.peer(&Peer::Port { port: 443 }, None), None);
    }
}
