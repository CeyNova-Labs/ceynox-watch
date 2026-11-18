#!/bin/sh
# Run a command in the Linux dev container (see dev/Dockerfile).
#   dev/run.sh cargo test
#   dev/run.sh            # interactive shell
set -eu
cd "$(dirname "$0")/.."
tty=""; [ -t 0 ] && tty="-it"
exec docker run --rm $tty --privileged --cgroupns=host \
  -v "$PWD":/src \
  -v ceynox-watch-target:/target \
  -v ceynox-watch-cargo:/usr/local/cargo/registry \
  -w /src ceynox-watch-dev "${@:-bash}"
