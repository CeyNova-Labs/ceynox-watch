#!/bin/sh
# Regenerate docs/gallery: what installing some well-known packages does,
# recorded with `ceynox-watch --inspect`. Needs Docker, and a ceynox-watch
# on PATH (or in CEYNOX_WATCH_BIN) that can inspect.
#
#   dev/gallery.sh
set -eu
cd "$(dirname "$0")/.."
BIN="${CEYNOX_WATCH_BIN:-ceynox-watch}"
out=docs/gallery
mkdir -p "$out"

# Pin what is recorded, so the page says exactly which release it is about.
latest() {
  case "$1" in
    npm:*)  docker run --rm node:lts-slim npm view "${1#npm:}" version 2>/dev/null ;;
    pypi:*) docker run --rm python:3-slim sh -c "pip index versions '${1#pypi:}' 2>/dev/null | sed -n '1s/.*(\(.*\)).*/\1/p'" ;;
  esac
}

for package in npm:esbuild npm:core-js npm:bcrypt npm:puppeteer pypi:requests; do
  version="$(latest "$package")"
  case "$package" in npm:*) spec="$package@$version" ;; *) spec="$package==$version" ;; esac
  file="$out/$(echo "${package#*:}" | tr '/@' '--').md"
  echo "== $spec -> $file"
  "$BIN" -q --no-summary --inspect "$spec" --report "$file"
done
