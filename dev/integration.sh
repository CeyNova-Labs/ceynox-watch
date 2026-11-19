#!/bin/sh
# End-to-end tests: run real commands under ceynox-watch on a real kernel and
# check what it reports. Needs root, Linux, and the tools in dev/Dockerfile.
#
#   dev/run.sh dev/integration.sh
set -eu

BIN="${CEYNOX_WATCH_BIN:-/target/debug/ceynox-watch}"
[ -x "$BIN" ] || cargo build
install -m 755 "$BIN" /usr/local/bin/ceynox-watch

fails=0
ok()   { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
# has <file> <description> <fixed string>...: every string appears in the file
has() {
  file=$1; what=$2; shift 2
  for s in "$@"; do
    grep -qF -- "$s" "$file" || { fail "$what (missing: $s)"; return; }
  done
  ok "$what"
}
hasnt() {
  if grep -qF -- "$3" "$1"; then fail "$2 (unexpected: $3)"; else ok "$2"; fi
}

# A normal user with passwordless sudo and some fake secrets to trip over.
id dev >/dev/null 2>&1 || useradd -m dev
echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev
H=/home/dev
rm -rf $H/app   # a leftover node_modules would keep npm from running the install script
mkdir -p $H/.aws $H/.ssh $H/app $H/plain
echo fake > $H/.aws/credentials
echo fake > $H/.ssh/id_ed25519
echo fake > $H/.ssh/id_ed25519.pub
echo '//registry.npmjs.org/:_authToken=fake' > $H/.npmrc
echo 'TOKEN=fake' > $H/plain/.env
rm -rf $H/sneaky-package && cp -r "$(dirname "$0")/../demo/sneaky-package" $H/sneaky-package
cat > $H/app/package.json <<'JSON'
{"name":"app","version":"1.0.0","dependencies":{"sneaky-package":"file:../sneaky-package"}}
JSON
chown -R dev:dev $H
T=$(mktemp -d); chmod 777 "$T"
as_dev() { su dev -c "cd $H/plain && $1"; }

echo "command as a normal user, through sudo"
as_dev "ceynox-watch --color never --json $T/a.jsonl -- sh -c 'cat ~/.aws/credentials ~/.ssh/id_ed25519.pub .env >/dev/null; echo hi > out.txt; echo x >> ~/.bashrc; id -u > $T/uid'" > "$T/a.out" 2> "$T/a.err" || fail "exit status"
has "$T/a.err" "live lines" "READ   ~/.aws/credentials  AWS credentials" "READ   ./.env  environment file" "WRITE  ~/.bashrc  shell startup file"
has "$T/a.err" "summary" "WORTH A LOOK  3" "exit 0" "./out.txt"
hasnt "$T/a.err" "public keys are not flagged" "id_ed25519.pub  "
hasnt "$T/a.err" "the start gate stays out of the record" "ceynox-watch-"
[ "$(cat "$T/uid")" = "$(id -u dev)" ] && ok "the command ran as the user, not root" || fail "the command ran as uid $(cat "$T/uid")"
has "$T/a.jsonl" "json events" '"type":"exec"' '"type":"open","path":"/home/dev/.aws/credentials"' '"type":"exit","code":0'
[ ! -s "$T/a.out" ] && ok "nothing added to the command's stdout" || fail "stdout was touched"

echo "listing a folder of secrets"
as_dev "ceynox-watch --color never -- ls $H/.ssh" > /dev/null 2> "$T/d.err" || fail "ls"
has "$T/d.err" "the listing is flagged" "READ   ~/.ssh  SSH folder listed"

echo "exit status and signals pass through"
set +e
as_dev "ceynox-watch -q --no-summary --json /dev/null -- sh -c 'exit 7'"; [ $? -eq 7 ] && ok "exit 7" || fail "exit 7"
as_dev "ceynox-watch -q --no-summary --json /dev/null -- sh -c 'kill -TERM \$\$'"; [ $? -eq 143 ] && ok "killed by SIGTERM gives 143" || fail "signal status"
as_dev "ceynox-watch -q -- no-such-command-here" 2> "$T/nf.err"; [ $? -eq 127 ] && ok "missing command gives 127" || fail "missing command"
set -e
hasnt "$T/nf.err" "no summary for a command that never started" "PROCESSES"

echo "the helper gives up root"
as_dev "ceynox-watch -q --no-summary --json /dev/null -- sh -c 'sleep 2'" &
# The helper is the ceynox-watch process (not the sudo in front of it) in
# sensor mode; it drops root just before the command is released.
helper=""
for _ in $(seq 1 40); do
  sleep 0.1
  pgrep -x sleep >/dev/null || continue
  for p in $(pgrep -x ceynox-watch); do
    grep -qa __sensor /proc/$p/cmdline 2>/dev/null && helper=$p
  done
  break
done
if [ -n "$helper" ]; then
  uids=$(awk '/^Uid:/ {print $2 $3 $4}' /proc/$helper/status)
  caps=$(awk '/^CapEff:/ {print $2}' /proc/$helper/status)
  want=$(id -u dev)
  [ "$uids" = "$want$want$want" ] && ok "helper runs as the user" || fail "helper uids: $uids"
  [ "$caps" = "0000008000000000" ] && ok "helper holds only CAP_BPF" || fail "helper capabilities: $caps"
else
  fail "helper not found"
fi
wait

echo "network, with names"
as_dev "ceynox-watch --color never -- curl -s -m 10 -o /dev/null https://example.com" 2> "$T/n.err" || fail "curl"
has "$T/n.err" "connection shown by name" "example.com:443 (" "tcp, https"

echo "how much was sent"
cat > "$T/sink.py" <<'PY'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 9911)); s.listen(4)
while True:
    c, _ = s.accept()
    while c.recv(65536):
        pass
    c.sendall(b"x" * 1234); c.close()
PY
python3 "$T/sink.py" & sink=$!
sleep 0.5
as_dev "ceynox-watch --color never --json $T/up.jsonl -- python3 -c \"
import socket
s = socket.create_connection(('127.0.0.1', 9911)); s.sendall(b'a' * 300000); s.shutdown(socket.SHUT_WR)
while s.recv(65536): pass
s.close()\"" > /dev/null 2> "$T/up.err" || fail "upload"
kill $sink 2>/dev/null || true
has "$T/up.jsonl" "the byte counts are exact" '"type":"close"' '"sent":300000,"received":1234'
has "$T/up.err" "a large upload gets a line and a total" "sent   300.0 kB to 127.0.0.1:9911" "↑300.0 kB ↓1.2 kB"

echo "a script on standard input"
as_dev "echo 'cat ~/.aws/credentials > /dev/null' | ceynox-watch --color never -- sh" > /dev/null 2> "$T/pipe.err" || fail "piped script"
has "$T/pipe.err" "what the script does is shown" "READ   ~/.aws/credentials  AWS credentials (credentials)  cat"

echo "an AI agent's configuration is changed"
as_dev "ceynox-watch --color never -- sh -c 'mkdir -p ~/.cursor && echo {} > ~/.cursor/mcp.json'" > /dev/null 2> "$T/agent.err" || fail "agent config"
has "$T/agent.err" "the change is flagged" "WRITE  ~/.cursor/mcp.json  Cursor MCP servers (persistence)"

echo "compared with an earlier run"
as_dev "ceynox-watch -q --no-summary --write-baseline $T/base.json -- sh -c 'echo hi > out.txt'" 2> /dev/null || fail "writing a baseline"
has "$T/base.json" "the baseline is small and readable" '"ceynox-watch-baseline": 1' '"./out.txt"' '"sh"'
as_dev "ceynox-watch --color never --baseline $T/base.json --fail-on new -- sh -c 'echo hi > out.txt'" > /dev/null 2> "$T/same.err" && ok "the same run again passes" || fail "the same run again passes"
has "$T/same.err" "and says nothing is new" "Nothing new since base.json."
set +e
as_dev "ceynox-watch --color never --baseline $T/base.json --fail-on new --report $T/r.md --json $T/new.jsonl -- sh -c 'echo hi > out.txt; cat ~/.aws/credentials > /dev/null; curl -s -m 10 -o /dev/null https://example.com'" > /dev/null 2> "$T/new.err"
[ $? -eq 3 ] && ok "a run that does more exits 3" || fail "a run that does more exits 3"
as_dev "ceynox-watch -q --no-summary --fail-on flagged -- sh -c 'cat ~/.aws/credentials > /dev/null'" 2> "$T/flag.err"
[ $? -eq 3 ] && ok "--fail-on flagged exits 3" || fail "--fail-on flagged exits 3"
as_dev "ceynox-watch -q --no-summary --fail-on flagged -- sh -c 'cat ~/.aws/credentials > /dev/null; exit 7'" 2> /dev/null
[ $? -eq 7 ] && ok "a failing command keeps its own status" || fail "a failing command keeps its own status"
as_dev "ceynox-watch -q --no-summary --fail-on flagged -- sh -c 'echo hi > out.txt'" 2> /dev/null
[ $? -eq 0 ] && ok "nothing flagged, nothing failed" || fail "nothing flagged, nothing failed"
as_dev "ceynox-watch -q --no-summary --baseline $T/missing.json -- true" 2> "$T/missing.err"
[ $? -eq 125 ] && ok "a missing baseline is an error before anything runs" || fail "missing baseline"
set -e
has "$T/new.err" "what is new is listed" "NEW SINCE base.json" "flagged      read ~/.aws/credentials (AWS credentials) by cat" "destination  example.com:443" "program      curl"
has "$T/new.err" "and the reason for failing is given" "not in base.json (--fail-on new)"
has "$T/flag.err" "so is the reason for --fail-on flagged" "failing: 1 thing in the catalog touched"
has "$T/r.md" "the Markdown report has it all" '## ceynox-watch: `sh -c' '### Worth a look (1)' '### New since `base.json`' '`example.com:443'
ceynox-watch --view "$T/new.jsonl" --baseline "$T/base.json" --report "$T/r.html" -q > "$T/view.out" 2>&1 || fail "report from a recording"
has "$T/r.html" "a recording becomes an HTML report" "<!doctype html>" "AWS credentials" "New since <code>base.json</code>" "example.com:443"
has "$T/view.out" "a recording compares like the run did" "destination  example.com:443" "program      curl"

echo "a package run straight from the registry"
as_dev "ceynox-watch --color never -- npx --yes cowsay@1.6.0 hi" > /dev/null 2> "$T/npx.err" || fail "npx"
has "$T/npx.err" "its processes carry its name" "[npx:cowsay]"

echo "npm install with an install script"
su dev -c "cd $H/app && ceynox-watch --color never --json $T/npm.jsonl -- npm install --no-audit --no-fund --install-links" > /dev/null 2> "$T/npm.err" || fail "npm install"
has "$T/npm.err" "install script attributed to its package" "node collect.js  [npm:sneaky-package]"
has "$T/npm.err" "its reads are flagged" "READ   ~/.aws/credentials  AWS credentials (credentials)  node [npm:sneaky-package]" "READ   ~/.ssh/id_ed25519  SSH private key"
has "$T/npm.err" "its connection is shown" "example.com:443" "node [npm:sneaky-package]"

echo "pip install of a package with a setup script"
rm -rf $H/sneaky-pip $H/pyapp && cp -r "$(dirname "$0")/../demo/sneaky-pip" $H/sneaky-pip && mkdir -p $H/pyapp && chown -R dev:dev $H/sneaky-pip $H/pyapp
su dev -c "cd $H/pyapp && python3 -m venv .venv && ceynox-watch --color never -- .venv/bin/pip install -q ../sneaky-pip" > /dev/null 2> "$T/pip.err" || fail "pip install"
has "$T/pip.err" "the build is attributed to its package" "[pypi:sneaky-pip]"
has "$T/pip.err" "its reads are flagged" "READ   ~/.aws/credentials  AWS credentials (credentials)  python3 [pypi:sneaky-pip]" "READ   ~/.ssh/id_ed25519  SSH private key"
has "$T/pip.err" "its connection is shown by name" "example.com:443" "pypi.org:443"

echo "attach to a running process"
su dev -c "sh -c 'while true; do cat $H/plain/.env >/dev/null; sleep 0.2; done' & echo \$! > $T/loop.pid"
ceynox-watch --color never --pid "$(cat "$T/loop.pid")" > "$T/p.out" 2> "$T/p.err" &
watcher=$!
for _ in $(seq 1 50); do grep -q "watching" "$T/p.err" 2>/dev/null && break; sleep 0.1; done
sleep 1
kill -INT $watcher; wait $watcher || true
kill "$(cat "$T/loop.pid")" 2>/dev/null || true
has "$T/p.out" "children of an already-running process" "exec     cat $H/plain/.env" "environment file" "WORTH A LOOK  1"

echo "whole machine, as JSON"
ceynox-watch --all --json - > "$T/all.jsonl" 2> "$T/all.err" &
watcher=$!
for _ in $(seq 1 50); do grep -q "watching" "$T/all.err" 2>/dev/null && break; sleep 0.1; done
su dev -c "cat $H/.aws/credentials" >/dev/null
sleep 0.3
kill -INT $watcher; wait $watcher || true
has "$T/all.jsonl" "sees a process it did not start" '"path":"/home/dev/.aws/credentials"'
if grep -vq '^{' "$T/all.jsonl"; then fail "json output has non-json lines"; else ok "json output is only json"; fi

echo
if [ "$fails" -eq 0 ]; then echo "all passed"; else echo "$fails failed"; echo "--- kept in $T"; exit 1; fi
rm -rf "$T"
