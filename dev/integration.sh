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
