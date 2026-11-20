#!/bin/sh
# A two-minute check that ceynox-watch works on this machine: it runs one
# small command under it and looks for what should have been reported.
# Nothing of yours is read: the command gets a throwaway home directory.
#
#   dev/smoke.sh /path/to/ceynox-watch
#
# Needs Linux, sudo and curl. The output is meant to be pasted into an
# issue, working or not.
set -u
BIN=${1:?usage: dev/smoke.sh /path/to/ceynox-watch}
T=$(mktemp -d)
mkdir -p "$T/home/.aws"
echo fake > "$T/home/.aws/credentials"

echo "system:  $(uname -srm)"
[ -r /etc/os-release ] && echo "distro:  $(. /etc/os-release; echo "$PRETTY_NAME")"
echo "btf:     $([ -r /sys/kernel/btf/vmlinux ] && echo present || echo MISSING)"
echo "version: $("$BIN" --version 2>&1)"

HOME="$T/home" "$BIN" --color never --json "$T/run.jsonl" -- \
  sh -c "cat ~/.aws/credentials > /dev/null; echo hi > $T/out.txt; curl -s -m 20 -o /dev/null https://example.com" \
  > /dev/null 2> "$T/err"
status=$?
HOME="$T/home" "$BIN" -q --no-summary --json /dev/null -- sh -c 'exit 7' > /dev/null 2>&1
seven=$?

fails=0
check() { # check <description> <file> <fixed string>
  if grep -qF -- "$3" "$2" 2>/dev/null; then echo "  ok    $1"; else echo "  FAIL  $1"; fails=$((fails + 1)); fi
}
[ "$status" -eq 0 ] && echo "  ok    the command ran and exited 0" || { echo "  FAIL  exit status $status"; fails=$((fails + 1)); }
check "programs started are reported"        "$T/err"       "exec     cat"
check "a credential read is flagged"         "$T/err"       ".aws/credentials  AWS credentials (credentials)"
check "a file written is reported"           "$T/run.jsonl" "\"path\":\"$T/out.txt\",\"write\":true"
check "a connection is shown by name"        "$T/err"       "example.com:443"
check "bytes sent and received are counted"  "$T/run.jsonl" '"type":"close"'
check "the process tree ends with exits"     "$T/run.jsonl" '"type":"exit","code":0'
[ "$seven" -eq 7 ] && echo "  ok    the command's exit status passes through" || { echo "  FAIL  exit status 7 came back as $seven"; fails=$((fails + 1)); }

if [ "$fails" -eq 0 ]; then
  echo "result:  works"
else
  echo "result:  $fails failed"
  echo "--- what ceynox-watch said:"
  # The start and the end: a kernel that refuses a program says why last.
  if [ "$(wc -l < "$T/err")" -gt 24 ]; then
    head -4 "$T/err" | cut -c1-300 | sed 's/^/    /'; echo "    ..."; tail -12 "$T/err" | cut -c1-300 | sed 's/^/    /'
  else
    cut -c1-300 "$T/err" | sed 's/^/    /'
  fi
fi
rm -rf "$T"
[ "$fails" -eq 0 ]
