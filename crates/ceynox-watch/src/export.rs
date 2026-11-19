//! A run as a file to hand to someone: Markdown for a pull request or an
//! issue, HTML for everything else.
//!
//! Both are complete on their own. The HTML carries its styles inline and
//! loads nothing, so it can be opened from disk, attached or archived.
//! Everything a watched process controls goes through [`render::clean`] and
//! then through the escaping of the format it is written in.

use std::fmt::Write as _;

use crate::{
    baseline::Diff,
    render::{self, Header, Style, clean, count, duration, size, thousands},
    report::{Exit, NOTABLE_SENT, PeerRec, Report},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Html,
    Markdown,
}

impl Format {
    /// Chosen by the file name: `.html`, `.htm` or `.md`.
    pub fn of(file: &std::ffi::OsStr) -> Option<Self> {
        let name = file.to_string_lossy().to_ascii_lowercase();
        if name.ends_with(".html") || name.ends_with(".htm") {
            Some(Self::Html)
        } else if name.ends_with(".md") || name.ends_with(".markdown") {
            Some(Self::Markdown)
        } else {
            None
        }
    }
}

/// The comparison to include, with the name of what was compared against.
pub type Compared<'a> = Option<(&'a Diff, &'a str)>;

/// Rows kept per section. A report is for reading, and the recording has
/// the rest.
const MAX_ROWS: usize = 200;
const MAX_TREE: usize = 400;
/// The Markdown report is read in pull requests; its tree is kept short.
const MAX_TREE_MARKDOWN: usize = 60;

fn exit_text(exit: Option<Exit>) -> Option<String> {
    Some(match exit? {
        Exit::Code(c) => format!("exit {c}"),
        Exit::Signal(s) => format!("killed by signal {s}"),
    })
}

fn peers(report: &Report) -> Vec<&PeerRec> {
    let mut peers: Vec<&PeerRec> = report.peers.iter().filter(|p| !p.background).collect();
    peers.sort_by_key(|p| p.finding.is_none());
    peers
}

fn by(report: &Report, rec: &PeerRec) -> String {
    let names: Vec<String> = rec.by.iter().map(|n| clean(n)).collect();
    match report.package(rec.first_by) {
        Some(pkg) => format!("{} [{}]", names.join(", "), clean(&pkg)),
        None => names.join(", "),
    }
}

fn area_list(items: &[(String, usize)]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().take(12).map(|(a, n)| format!("{a} ({})", thousands(*n))).collect();
    if items.len() > 12 {
        out.push(format!("+{} more", items.len() - 12));
    }
    out
}

// ---- Markdown -----------------------------------------------------------------

/// Text for inside a code span, in or out of a table.
fn code(text: &str) -> String {
    let text = text.replace('`', "'").replace('|', "\\|");
    if text.is_empty() { String::new() } else { format!("`{text}`") }
}

/// Plain text in a table cell or a line.
fn md(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '~' | '&') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn markdown(report: &Report, header: &Header, style: &Style, compared: Compared<'_>) -> String {
    let style = &Style { color: false, ..style.clone() };
    let mut out = String::new();
    let _ = writeln!(out, "## ceynox-watch: {}\n", code(&clean(&header.title)));

    let mut facts = Vec::new();
    facts.extend(exit_text(header.exit).map(|e| format!("**{e}**")));
    facts.push(duration(header.elapsed_ms));
    facts.push(format!("{} run", count(report.execs as usize, "program")));
    facts.push(count(peers(report).len(), "destination"));
    facts.push(format!("{} read, {} written", count(report.read.len(), "file"), thousands(report.written.len())));
    let _ = writeln!(out, "{}\n", facts.join(" · "));

    let groups = render::finding_groups(report, style);
    if groups.is_empty() {
        let _ =
            writeln!(out, "Nothing touched the credential, browser, history or startup locations in the catalog.\n");
    } else {
        let _ = writeln!(out, "### Worth a look ({})\n", groups.len());
        let _ = writeln!(out, "| | What | Why it is listed | By |\n|---|---|---|---|");
        for g in groups.iter().take(MAX_ROWS) {
            let times = if g.times > 1 { format!(" ×{}", g.times) } else { String::new() };
            let _ = writeln!(
                out,
                "| {} | {}{times} | {} ({}) | {} |",
                g.verb.trim(),
                code(&g.subject),
                md(g.finding.what),
                g.finding.category.as_str(),
                code(&g.by)
            );
        }
        if groups.len() > MAX_ROWS {
            let _ = writeln!(out, "\n+{} more", groups.len() - MAX_ROWS);
        }
        out.push('\n');
    }

    if let Some((diff, against)) = compared {
        if diff.new.is_empty() {
            let _ = writeln!(out, "### Nothing new since {}\n", code(&clean(against)));
        } else {
            let _ = writeln!(out, "### New since {} ({})\n", code(&clean(against)), diff.new.len());
            for (kind, what) in diff.new.iter().take(MAX_ROWS) {
                let _ = writeln!(out, "- **{}** {}", kind.label(), code(&clean(what)));
            }
            if diff.new.len() > MAX_ROWS {
                let _ = writeln!(out, "- +{} more", diff.new.len() - MAX_ROWS);
            }
            out.push('\n');
        }
        if diff.gone > 0 {
            let _ = writeln!(out, "{} seen then, not seen now.\n", count(diff.gone, "thing"));
        }
    }

    let peers = peers(report);
    let _ = writeln!(out, "### Network ({})\n", count(peers.len(), "destination"));
    if !peers.is_empty() {
        let measured = peers.iter().any(|p| p.closed > 0);
        let _ = writeln!(
            out,
            "{}",
            if measured {
                "| Destination | Sent | Received | By |\n|---|---:|---:|---|"
            } else {
                "| Destination | By |\n|---|---|"
            }
        );
        for rec in peers.iter().take(MAX_ROWS) {
            let mut dest = code(&render::show_peer(&rec.peer, rec.name.as_deref()));
            if rec.count > 1 {
                let _ = write!(dest, " ×{}", thousands(rec.count as usize));
            }
            if let Some(f) = &rec.finding {
                let _ = write!(dest, " **{} ({})**", md(f.what), f.category.as_str());
            }
            let who = code(&by(report, rec));
            if measured {
                let (up, down) =
                    if rec.closed > 0 { (size(rec.sent), size(rec.received)) } else { (String::new(), String::new()) };
                let _ = writeln!(out, "| {dest} | {up} | {down} | {who} |");
            } else {
                let _ = writeln!(out, "| {dest} | {who} |");
            }
        }
        if peers.len() > MAX_ROWS {
            let _ = writeln!(out, "\n+{} more", peers.len() - MAX_ROWS);
        }
        out.push('\n');
    }

    // What ran, as a tree: which program started which, and for which
    // package. In a fenced block, where only a backtick could do harm.
    let execed: Vec<usize> = (0..report.procs.len()).filter(|&i| report.procs[i].execed).collect();
    if !execed.is_empty() {
        let _ = writeln!(out, "### Programs ({} run)\n\n```", thousands(report.execs as usize));
        for &i in execed.iter().take(MAX_TREE_MARKDOWN) {
            let pkg = report.package(i).map(|p| format!("  [{}]", clean(&p))).unwrap_or_default();
            let line = format!("{}{}{pkg}", "  ".repeat(report.depth(i).min(12)), clean(&report.procs[i].command()));
            let _ = writeln!(out, "{}", line.replace('`', "'"));
        }
        if execed.len() > MAX_TREE_MARKDOWN {
            let _ = writeln!(out, "+{} more", thousands(execed.len() - MAX_TREE_MARKDOWN));
        }
        let _ = writeln!(out, "```\n");
    }

    let _ = writeln!(out, "### Files\n");
    let _ = writeln!(out, "{} read, {} written.\n", thousands(report.read.len()), thousands(report.written.len()));
    for (label, set) in [("Written", &report.written), ("Read", &report.read)] {
        if !set.is_empty() {
            let areas: Vec<String> = area_list(&render::areas(report, style, set)).iter().map(|a| code(a)).collect();
            let _ = writeln!(out, "- {label}: {}", areas.join(", "));
        }
    }
    if report.lost > 0 {
        let _ = writeln!(
            out,
            "\n**{} events were dropped, so this record is incomplete.**",
            thousands(report.lost as usize)
        );
    }
    let _ = writeln!(
        out,
        "\n<sub>Recorded by [ceynox-watch](https://github.com/CeyNova-Labs/ceynox-watch) {}. It shows what happened; it does not decide what is malicious.</sub>",
        env!("CARGO_PKG_VERSION")
    );
    out
}

// ---- HTML ---------------------------------------------------------------------

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const CSS: &str = "\
:root{--bg:#fbfbfa;--card:#fff;--ink:#1c1c1a;--dim:#6b6b66;--line:#e4e4df;--flag:#b42318;--flagbg:#fef3f2;--warn:#93600a;--ok:#1a7f4b;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#121211;--card:#1b1b19;--ink:#ecece7;--dim:#9a9a93;--line:#2e2e2b;--flag:#ff8a80;--flagbg:#2a1614;--warn:#e5b45a;--ok:#6fd39b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:14px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);margin:0 0 8px}
.cmd{font:600 22px/1.3 var(--mono);overflow-wrap:anywhere;margin:0 0 6px}
.meta{color:var(--dim);margin:0 0 24px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0 0 28px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}
.tile span{color:var(--dim);font-size:13px}
.tile.hot{border-color:var(--flag);background:var(--flagbg)}.tile.hot b{color:var(--flag)}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:0 0 20px;overflow:hidden}
h2{font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin:0;padding:12px 16px;border-bottom:1px solid var(--line)}
h2 small{color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;margin-left:8px}
section.hot h2{color:var(--flag)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}
td,th{padding:8px 16px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
th{font-size:12px;font-weight:600;color:var(--dim)}
td.n,th.n{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
code,.mono{font:13px/1.5 var(--mono);overflow-wrap:anywhere}
.dim{color:var(--dim)}.flag{color:var(--flag);font-weight:600}.warn{color:var(--warn);font-weight:600}.ok{color:var(--ok)}
.verb{font:600 12px var(--mono);text-transform:uppercase;color:var(--flag);white-space:nowrap}
.pad{padding:12px 16px}.pad p{margin:0 0 8px}.pad p:last-child{margin:0}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chips span{font:13px var(--mono);border:1px solid var(--line);border-radius:6px;padding:2px 8px}
.tree{padding:10px 16px;font:13px/1.7 var(--mono);overflow-x:auto;white-space:nowrap}
.tree div{padding-left:calc(var(--d)*18px)}
.tree .hit{color:var(--flag);font-weight:600}
footer{color:var(--dim);font-size:13px;margin-top:28px}
footer a{color:inherit}";

fn tile(out: &mut String, value: &str, label: &str, hot: bool) {
    let class = if hot { "tile hot" } else { "tile" };
    let _ = write!(out, "<div class=\"{class}\"><b>{}</b><span>{}</span></div>", esc(value), esc(label));
}

pub fn html(report: &Report, header: &Header, style: &Style, compared: Compared<'_>) -> String {
    let style = &Style { color: false, ..style.clone() };
    let title = clean(&header.title);
    let groups = render::finding_groups(report, style);
    let peers = peers(report);
    let sent: u64 = report.peers.iter().map(|p| p.sent).sum();
    let measured = report.peers.iter().any(|p| p.closed > 0);

    let mut out = String::with_capacity(16 * 1024);
    let _ = write!(
        out,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"generator\" content=\"ceynox-watch {}\">\
         <title>ceynox-watch: {}</title><style>{CSS}</style></head><body><main>",
        env!("CARGO_PKG_VERSION"),
        esc(&title)
    );
    let _ = write!(out, "<h1>ceynox-watch</h1><p class=\"cmd\">{}</p>", esc(&title));
    let mut facts = vec![duration(header.elapsed_ms)];
    facts.extend(exit_text(header.exit));
    let _ = write!(out, "<p class=\"meta\">{}</p>", esc(&facts.join(" · ")));

    out.push_str("<div class=\"tiles\">");
    tile(&mut out, &thousands(groups.len()), "worth a look", !groups.is_empty());
    if let Some((diff, _)) = compared {
        tile(&mut out, &thousands(diff.new.len()), "new since last time", !diff.new.is_empty());
    }
    let one = |n: usize, one: &'static str, many: &'static str| if n == 1 { one } else { many };
    tile(&mut out, &thousands(report.execs as usize), one(report.execs as usize, "program run", "programs run"), false);
    tile(&mut out, &thousands(peers.len()), one(peers.len(), "destination", "destinations"), false);
    if measured {
        tile(&mut out, &size(sent), "sent over TCP", false);
    }
    tile(&mut out, &thousands(report.written.len()), one(report.written.len(), "file written", "files written"), false);
    tile(&mut out, &thousands(report.read.len()), one(report.read.len(), "file read", "files read"), false);
    out.push_str("</div>");

    // Findings.
    if groups.is_empty() {
        out.push_str(
            "<section><h2>Worth a look</h2><div class=\"pad\"><p class=\"ok\">Nothing touched the credential, \
             browser, history or startup locations in the catalog.</p></div></section>",
        );
    } else {
        let _ = write!(
            out,
            "<section class=\"hot\"><h2>Worth a look<small>{}</small></h2><div class=\"scroll\"><table>",
            groups.len()
        );
        for g in groups.iter().take(MAX_ROWS) {
            let times = if g.times > 1 { format!(" <span class=\"dim\">×{}</span>", g.times) } else { String::new() };
            let _ = write!(
                out,
                "<tr><td class=\"verb\">{}</td><td><code>{}</code>{times}<br><span class=\"dim mono\">{}</span></td>\
                 <td class=\"warn\">{} <span class=\"dim\">({})</span></td></tr>",
                esc(g.verb.trim()),
                esc(&g.subject),
                esc(&g.by),
                esc(g.finding.what),
                esc(g.finding.category.as_str())
            );
        }
        out.push_str("</table></div>");
        if groups.len() > MAX_ROWS {
            let _ = write!(out, "<div class=\"pad dim\">+{} more</div>", groups.len() - MAX_ROWS);
        }
        out.push_str("</section>");
    }

    // Comparison.
    if let Some((diff, against)) = compared {
        let against = esc(&clean(against));
        if diff.new.is_empty() {
            let _ = write!(
                out,
                "<section><h2>Compared with <code>{against}</code></h2><div class=\"pad\"><p class=\"ok\">Nothing new.</p>"
            );
        } else {
            let _ = write!(
                out,
                "<section class=\"hot\"><h2>New since <code>{against}</code><small>{}</small></h2><div class=\"scroll\"><table>",
                diff.new.len()
            );
            for (kind, what) in diff.new.iter().take(MAX_ROWS) {
                let _ = write!(
                    out,
                    "<tr><td class=\"verb\">{}</td><td><code>{}</code></td></tr>",
                    esc(kind.label()),
                    esc(&clean(what))
                );
            }
            out.push_str("</table></div><div class=\"pad\">");
            if diff.new.len() > MAX_ROWS {
                let _ = write!(out, "<p class=\"dim\">+{} more</p>", diff.new.len() - MAX_ROWS);
            }
        }
        if diff.gone > 0 {
            let _ = write!(out, "<p class=\"dim\">{} seen then, not seen now.</p>", count(diff.gone, "thing"));
        }
        out.push_str("</div></section>");
    }

    // Network.
    let _ = write!(out, "<section><h2>Network<small>{}</small></h2>", count(peers.len(), "destination"));
    if !peers.is_empty() {
        out.push_str("<div class=\"scroll\"><table><tr><th>Destination</th>");
        if measured {
            out.push_str("<th class=\"n\">Sent</th><th class=\"n\">Received</th>");
        }
        out.push_str("<th>By</th></tr>");
        for rec in peers.iter().take(MAX_ROWS) {
            let _ = write!(out, "<tr><td><code>{}</code>", esc(&render::show_peer(&rec.peer, rec.name.as_deref())));
            if rec.count > 1 {
                let _ = write!(out, " <span class=\"dim\">×{}</span>", thousands(rec.count as usize));
            }
            if let Some(f) = &rec.finding {
                let _ = write!(out, "<br><span class=\"flag\">{} ({})</span>", esc(f.what), esc(f.category.as_str()));
            }
            out.push_str("</td>");
            if measured {
                if rec.closed > 0 {
                    let class = if rec.sent >= NOTABLE_SENT { "n warn" } else { "n" };
                    let _ = write!(
                        out,
                        "<td class=\"{class}\">{}</td><td class=\"n\">{}</td>",
                        size(rec.sent),
                        size(rec.received)
                    );
                } else {
                    out.push_str("<td class=\"n\"></td><td class=\"n\"></td>");
                }
            }
            let _ = write!(out, "<td class=\"mono dim\">{}</td></tr>", esc(&by(report, rec)));
        }
        out.push_str("</table></div>");
        if peers.len() > MAX_ROWS {
            let _ = write!(out, "<div class=\"pad dim\">+{} more</div>", peers.len() - MAX_ROWS);
        }
    }
    out.push_str("</section>");

    // Files.
    let _ = write!(
        out,
        "<section><h2>Files<small>{} read, {} written</small></h2><div class=\"pad\">",
        thousands(report.read.len()),
        thousands(report.written.len())
    );
    for (label, set) in [("Written", &report.written), ("Read", &report.read)] {
        if !set.is_empty() {
            let _ = write!(out, "<p class=\"dim\">{label}</p><p class=\"chips\">");
            for area in area_list(&render::areas(report, style, set)) {
                let _ = write!(out, "<span>{}</span>", esc(&area));
            }
            out.push_str("</p>");
        }
    }
    out.push_str("</div></section>");

    // Processes, as a tree.
    let flagged: std::collections::HashSet<usize> = report.findings.iter().map(|f| f.proc).collect();
    let execed: Vec<usize> = (0..report.procs.len()).filter(|&i| report.procs[i].execed).collect();
    let _ = write!(
        out,
        "<section><h2>Programs<small>{} run</small></h2><div class=\"tree\">",
        thousands(report.execs as usize)
    );
    for &i in execed.iter().take(MAX_TREE) {
        let class = if flagged.contains(&i) { " class=\"hit\"" } else { "" };
        let pkg =
            report.package(i).map(|p| format!(" <span class=\"dim\">[{}]</span>", esc(&clean(&p)))).unwrap_or_default();
        let _ = write!(
            out,
            "<div{class} style=\"--d:{}\">{}{pkg}</div>",
            report.depth(i).min(12),
            esc(&clean(&report.procs[i].command()))
        );
    }
    out.push_str("</div>");
    if execed.len() > MAX_TREE {
        let _ = write!(out, "<div class=\"pad dim\">+{} more</div>", thousands(execed.len() - MAX_TREE));
    }
    out.push_str("</section>");

    if report.lost > 0 {
        let _ = write!(
            out,
            "<p class=\"warn\">{} events were dropped, so this record is incomplete.</p>",
            thousands(report.lost as usize)
        );
    }
    let _ = writeln!(
        out,
        "<footer>Recorded by <a href=\"https://github.com/CeyNova-Labs/ceynox-watch\">ceynox-watch</a> {}. \
         It shows what happened; it does not decide what is malicious.</footer></main></body></html>",
        env!("CARGO_PKG_VERSION")
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        baseline::Kind,
        classify::Classifier,
        event::{Event, Peer, Proto, What},
    };

    fn sample() -> Report {
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
        let peer = Peer::Ip { ip: "203.0.113.9".parse().expect("ip"), port: 443, proto: Proto::Tcp };
        for ev in [
            exec(10, 1, &["npm", "install"], "/home/sam/app"),
            Event { ts: 1, pid: 11, what: What::Fork { ppid: 10 } },
            exec(11, 10, &["node", "<img src=x onerror=alert(1)>.js", "a|b`c"], "/home/sam/app/node_modules/evil"),
            Event {
                ts: 5,
                pid: 11,
                what: What::Open { path: "/home/sam/.aws/credentials".into(), write: false, dir: false },
            },
            Event {
                ts: 6,
                pid: 11,
                what: What::Open { path: "/home/sam/app/<b>.txt".into(), write: true, dir: false },
            },
            Event { ts: 7, pid: 11, what: What::Connect { peer: peer.clone(), name: Some("x.ngrok-free.app".into()) } },
            Event { ts: 8, pid: 11, what: What::Close { peer, sent: 4_200_000, received: 300 } },
        ] {
            r.ingest(&ev);
        }
        r
    }

    fn header() -> Header {
        Header { title: "npm install".into(), elapsed_ms: 1500, exit: Some(Exit::Code(0)) }
    }

    fn style() -> Style {
        Style { color: false, width: 100, base: Some("/home/sam/app".into()) }
    }

    #[test]
    fn format_follows_the_file_name() {
        let f = |s: &str| Format::of(std::ffi::OsStr::new(s));
        assert_eq!(f("run.html"), Some(Format::Html));
        assert_eq!(f("RUN.HTM"), Some(Format::Html));
        assert_eq!(f("summary.md"), Some(Format::Markdown));
        assert_eq!(f("run.txt"), None);
        assert_eq!(f("html"), None);
    }

    #[test]
    fn html_escapes_everything_a_process_controls() {
        let text = html(&sample(), &header(), &style(), None);
        assert!(!text.contains("<img"), "a file name must not become markup");
        assert!(!text.contains("<b>.txt"));
        assert!(text.contains("&lt;img src=x onerror=alert(1)&gt;.js"));
        assert!(text.contains("<code>~/.aws/credentials</code>"));
        assert!(text.contains("AWS credentials"));
        assert!(text.contains("tunnelling service (often used to send data out)"));
        assert!(text.contains("<td class=\"n warn\">4.2 MB</td><td class=\"n\">300 B</td>"));
        assert!(text.contains("[npm:evil]"));
        assert!(text.starts_with("<!doctype html>") && text.ends_with("</html>\n"));
        // Nothing is fetched: no scripts, no links to load.
        for loader in ["<script", "<link", "<iframe", "url(", "@import"] {
            assert!(!text.contains(loader), "{loader}");
        }
    }

    #[test]
    fn markdown_survives_pipes_and_backticks() {
        let diff = Diff { new: vec![(Kind::Destination, "x.ngrok-free.app:443".into())], gone: 2 };
        let text = markdown(&sample(), &header(), &style(), Some((&diff, "base|line.json")));
        assert!(
            text.starts_with("## ceynox-watch: `npm install`\n\n**exit 0** · 1.5s · 2 programs run · 1 destination")
        );
        assert!(text.contains("| read | `~/.aws/credentials` | AWS credentials (credentials) |"));
        assert!(text.contains("a\\|b'c"), "pipes are escaped and backticks replaced inside code");
        assert!(text.contains("### New since `base\\|line.json` (1)\n\n- **destination** `x.ngrok-free.app:443`"));
        assert!(text.contains("2 things seen then, not seen now."));
        assert!(text.contains("| 4.2 MB | 300 B |"));
        assert!(text.contains(
            "### Programs (2 run)\n\n```\nnpm install\n  node '<img src=x onerror=alert(1)>.js' a|b'c  [npm:evil]\n```"
        ));
        // Every table row has the same number of cells as its header.
        for line in text.lines().filter(|l| l.starts_with("| read")) {
            assert_eq!(line.replace("\\|", "").matches('|').count(), 5, "{line}");
        }
    }

    #[test]
    fn a_quiet_run_says_so() {
        let mut r = Report::new(Classifier::new(None));
        r.ingest(&Event {
            ts: 0,
            pid: 1,
            what: What::Exec {
                ppid: 0,
                uid: 0,
                exe: "/bin/true".into(),
                argv: vec!["true".into()],
                cwd: None,
                existing: false,
            },
        });
        let h = Header { title: "true".into(), elapsed_ms: 3, exit: Some(Exit::Code(0)) };
        assert!(markdown(&r, &h, &style(), None).contains("Nothing touched the credential"));
        assert!(html(&r, &h, &style(), None).contains("Nothing touched the credential"));
    }
}
