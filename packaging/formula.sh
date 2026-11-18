#!/bin/sh
# Print the Homebrew formula for a release.
#
#   packaging/formula.sh <version> <dir with the release archives>
#
# The release workflow runs this and attaches the result to the release;
# it goes into the tap repository as Formula/ceynox-watch.rb.
set -eu
version=$1
dir=$2
base="https://github.com/CeyNova-Labs/ceynox-watch/releases/download/v$version"
sum() { shasum -a 256 "$dir/$1" | cut -d' ' -f1; }

mac="ceynox-watch-$version-macos-universal.tar.gz"
arm="ceynox-watch-$version-linux-aarch64.tar.gz"
x86="ceynox-watch-$version-linux-x86_64.tar.gz"

cat <<RUBY
class CeynoxWatch < Formula
  desc "See what a command really does: programs, network, credentials touched"
  homepage "https://github.com/CeyNova-Labs/ceynox-watch"
  version "$version"
  license "Apache-2.0"

  on_macos do
    url "$base/$mac"
    sha256 "$(sum "$mac")"
  end

  on_linux do
    on_arm do
      url "$base/$arm"
      sha256 "$(sum "$arm")"
    end
    on_intel do
      url "$base/$x86"
      sha256 "$(sum "$x86")"
    end
  end

  def install
    bin.install "ceynox-watch"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ceynox-watch --version")
  end
end
RUBY
