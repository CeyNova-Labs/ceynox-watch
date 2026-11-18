#!/bin/sh
# End-to-end tests for macOS: run real commands under ceynox-watch and check
# what it reports. No root needed. Uses a throwaway home directory, so
# nothing of yours is read.
#
#   cargo build --release && dev/integration-macos.sh
set -eu

BIN="${CEYNOX_WATCH_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/ceynox-watch}"
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

fails=0
ok()   { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
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

T=$(cd "$(mktemp -d)" && pwd -P)
export HOME="$T/home"
mkdir -p "$HOME/.aws" "$HOME/.ssh" "$T/proj"
echo fake > "$HOME/.aws/credentials"
echo fake > "$HOME/.ssh/id_ed25519"
echo fake > "$HOME/.ssh/id_ed25519.pub"
echo 'TOKEN=fake' > "$T/proj/.env"
cd "$T/proj"

echo "a command, with no root"
"$BIN" --color never --json "$T/a.jsonl" -- /bin/sh -c 'cat ~/.aws/credentials ~/.ssh/id_ed25519.pub .env >/dev/null; echo hi > out.txt; echo x >> ~/.zshrc' > "$T/a.out" 2> "$T/a.err" || fail "exit status"
has "$T/a.err" "live lines" "READ   ~/.aws/credentials  AWS credentials" "READ   ./.env  environment file" "WRITE  ~/.zshrc  shell startup file"
has "$T/a.err" "summary" "WORTH A LOOK  3" "exit 0" "./out.txt"
hasnt "$T/a.err" "public keys are not flagged" "id_ed25519.pub  "
has "$T/a.jsonl" "json events" '"type":"exec"' '"type":"open","path":"'"$(echo "$HOME" | sed 's|^/private||')"'/.aws/credentials"'
[ ! -s "$T/a.out" ] && ok "nothing added to the command's stdout" || fail "stdout was touched"

echo "additional credential locations"
mkdir -p "$HOME/.config/rclone" "$HOME/.config/sops/age" "$HOME/Library/Application Support/sops/age"
for credential_file in \
  "$HOME/.pgpass" \
  "$HOME/.config/rclone/rclone.conf" \
  "$HOME/.config/sops/age/keys.txt" \
  "$HOME/Library/Application Support/sops/age/keys.txt"; do
  echo fake > "$credential_file"
done
"$BIN" --color never -- /bin/sh -c '
  cat "$HOME/.pgpass" "$HOME/.config/rclone/rclone.conf" \
    "$HOME/.config/sops/age/keys.txt" "$HOME/Library/Application Support/sops/age/keys.txt" >/dev/null
' > "$T/credentials.out" 2> "$T/credentials.err" || fail "credential reads"
has "$T/credentials.err" "new credential locations" \
  "READ   ~/.pgpass  PostgreSQL passwords" \
  "READ   ~/.config/rclone/rclone.conf  rclone storage credentials" \
  "READ   ~/.config/sops/age/keys.txt  age private keys (sops)" \
  "READ   ~/Library/Application Support/sops/age/keys.txt  age private keys (sops)"
has "$T/credentials.err" "all four credential files counted" "WORTH A LOOK  4"
[ ! -s "$T/credentials.out" ] && ok "credential contents stay off stdout" || fail "credential stdout was touched"

echo "children are attached to their parent"
"$BIN" --color never -- /bin/sh -c '/bin/sh -c "cat .env > /dev/null"' 2> "$T/t.err" || fail "nested shells"
has "$T/t.err" "indented under the command" "exec     " "environment file"

echo "listing a folder of secrets"
"$BIN" --color never -- /bin/ls "$HOME/.ssh" > /dev/null 2> "$T/d.err" || fail "ls"
has "$T/d.err" "the listing is flagged" "READ   ~/.ssh  SSH folder listed"

echo "compared with an earlier run"
"$BIN" -q --no-summary --write-baseline "$T/base.json" -- /bin/sh -c 'echo hi > out.txt' 2> /dev/null || fail "writing a baseline"
has "$T/base.json" "the baseline is small and readable" '"ceynox-watch-baseline": 1' '"./out.txt"'
set +e
"$BIN" --color never --baseline "$T/base.json" --fail-on new --report "$T/r.md" --json "$T/new.jsonl" -- /bin/sh -c 'echo hi > out.txt; /bin/cat ~/.aws/credentials > /dev/null' > /dev/null 2> "$T/new.err"
[ $? -eq 3 ] && ok "a run that does more exits 3" || fail "a run that does more exits 3"
"$BIN" -q --no-summary --fail-on flagged -- /bin/sh -c 'echo hi > out.txt' 2> /dev/null
[ $? -eq 0 ] && ok "nothing flagged, nothing failed" || fail "nothing flagged, nothing failed"
set -e
has "$T/new.err" "what is new is listed" "NEW SINCE base.json" "flagged      read ~/.aws/credentials (AWS credentials) by cat"
has "$T/r.md" "the Markdown report has it" '### Worth a look (1)' '### New since `base.json`'
"$BIN" --view "$T/new.jsonl" --report "$T/r.html" -q > /dev/null 2>&1 || fail "report from a recording"
has "$T/r.html" "a recording becomes an HTML report" "<!doctype html>" "AWS credentials" "~/.aws/credentials"

echo "exit status passes through"
set +e
"$BIN" -q --no-summary --json /dev/null -- /bin/sh -c 'exit 7'; [ $? -eq 7 ] && ok "exit 7" || fail "exit 7"
"$BIN" -q -- no-such-command-here 2> "$T/nf.err"; [ $? -eq 127 ] && ok "missing command gives 127" || fail "missing command"
"$BIN" --pid 1 2> "$T/pid.err"; [ $? -eq 125 ] && ok "attach is refused" || fail "attach"
/usr/bin/sandbox-exec -p '(version 1)(allow default)' "$BIN" -q -- /usr/bin/true 2> "$T/nest.err"; [ $? -eq 125 ] && ok "refuses to run inside a sandbox" || fail "nested sandbox"
set -e
has "$T/pid.err" "attach explains itself" "works on Linux only"
has "$T/nest.err" "nested sandbox explains itself" "cannot run inside another sandbox"

echo "network"
"$BIN" --color never -- /usr/bin/nc -z -w 3 1.1.1.1 443 > /dev/null 2> "$T/n.err" || true
has "$T/n.err" "connection reported by port" "port 443  https, address not visible"

echo
if [ "$fails" -eq 0 ]; then echo "all passed"; rm -rf "$T"; else echo "$fails failed"; echo "--- kept in $T"; exit 1; fi
