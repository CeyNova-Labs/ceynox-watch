#!/bin/sh
# How much slower is a command when it is being watched?
#
# Times a real `npm ci` (from a warm cache, no network) on its own, under
# strace in three configurations (including its fastest, --seccomp-bpf),
# and under ceynox-watch. Runs are interleaved so
# that drift in the machine affects all three alike, and the median of
# each is reported. Needs root, Linux, strace and npm: dev/run.sh dev/bench.sh
set -eu
BIN="${CEYNOX_WATCH_BIN:-/target/release/ceynox-watch}"
RUNS="${RUNS:-9}"
W=$(mktemp -d)
cd "$W"
cat > package.json <<'JSON'
{"name":"bench","version":"1.0.0","private":true,
 "dependencies":{"express":"4.21.2","typescript":"5.7.2","eslint":"9.17.0","esbuild":"0.24.2","webpack":"5.97.1"}}
JSON
echo "preparing (this is the only step that uses the network)..."
npm install --no-audit --no-fund --loglevel=error >/dev/null 2>&1
echo "packages installed: $(ls node_modules | wc -l)   strace: $(strace --version | head -1)   kernel: $(uname -rm)"

now() { date +%s%N; }
once() { # once <label> <command...>: seconds taken
  shift
  rm -rf node_modules
  s=$(now); "$@" >/dev/null 2>"$W/err" || { echo "failed: $*" >&2; tail -5 "$W/err" >&2; exit 1; }; e=$(now)
  echo "$(( (e - s) / 1000000 ))"
}
NPM="npm ci --offline --no-audit --no-fund --loglevel=error"
: > plain.t; : > strace.t; : > strace_f.t; : > strace_s.t; : > watch.t; : > true.t; : > wtrue.t
once warm $NPM >/dev/null
i=0
while [ "$i" -lt "$RUNS" ]; do
  once plain    $NPM >> plain.t
  once strace   strace -f -o /dev/null $NPM >> strace.t
  once stracef  strace -f -e trace=execve,openat,connect -o /dev/null $NPM >> strace_f.t
  once straces  strace -f --seccomp-bpf -e trace=execve,openat,connect -o /dev/null $NPM >> strace_s.t
  once watch    "$BIN" -q --no-summary --json /dev/null -- $NPM >> watch.t
  # What ceynox-watch costs before the command starts: the same, for a
  # command that does nothing.
  once true     true >> true.t
  once wtrue    "$BIN" -q --no-summary --json /dev/null -- true >> wtrue.t
  i=$((i + 1))
done
median() { sort -n "$1" | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
spread() { sort -n "$1" | awk 'NR==1{lo=$1} {hi=$1} END{print lo "-" hi}'; }
p=$(median plain.t)
printf '\n%-44s %8s %12s %9s\n' "npm ci, $RUNS runs each" "median" "range (ms)" "slowdown"
for row in "plain.t:on its own" "strace.t:strace -f (every system call)" "strace_f.t:strace -f -e execve,openat,connect" "strace_s.t:  the same with --seccomp-bpf" "watch.t:ceynox-watch"; do
  f=${row%%:*}; label=${row#*:}; m=$(median "$f")
  printf '%-44s %6sms %12s %8s%%\n' "$label" "$m" "$(spread "$f")" "$(( (m - p) * 100 / p ))"
done
echo
echo "ceynox-watch start-up, measured on a command that does nothing: $(( $(median wtrue.t) - $(median true.t) ))ms"
echo "events ceynox-watch recorded in one run: $("$BIN" -q --no-summary --json /dev/stdout -- sh -c "rm -rf node_modules; $NPM >/dev/null 2>&1" 2>/dev/null | wc -l)"
rm -rf "$W"
