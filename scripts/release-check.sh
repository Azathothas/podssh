#!/bin/sh
# A release binary runs on its own platform (T-218): it prints the version of
# Cargo.toml, writes the whole manual, makes a key with no passphrase, and
# prints that key's public key again from the private key. No target ships
# that no run executed. The key is a throwaway, made in a directory of this
# run and removed with it.
#
#   sh scripts/release-check.sh target/release/podssh
#
# It runs where the binary runs: a runner of each system, or a container of
# the target's platform. It needs a POSIX shell, sed, cut and mktemp only.
set -u

bin=${1:-}
if [ -z "$bin" ] || [ ! -f "$bin" ]; then
    echo "usage: release-check.sh BINARY (got '$bin')" >&2
    exit 64
fi

fail() {
    echo "release-check: $*" >&2
    exit 1
}

# The checkout can hold CRLF line ends, and Windows prints CR too.
want=$(tr -d '\r' < Cargo.toml | sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p')
[ -n "$want" ] || fail "no version in Cargo.toml"
got=$("$bin" --version | tr -d '\r') || fail "--version failed"
[ "$got" = "podssh $want" ] || fail "the binary prints \"$got\", not \"podssh $want\""
echo "ok   --version: $got"

dir=$(mktemp -d "${TMPDIR:-/tmp}/podssh-release-check.XXXXXX") || fail "no scratch directory"
trap 'rm -rf "$dir"' EXIT HUP INT TERM

"$bin" man --no-pager > "$dir/man.txt" || fail "man --no-pager failed"
lines=$(wc -l < "$dir/man.txt")
# The whole manual is thousands of lines; a stub or a cut one is not.
[ "$lines" -gt 1000 ] || fail "the manual has $lines lines"
echo "ok   man --no-pager: $lines lines"

"$bin" keygen -q -t ed25519 -N '' -C release-check -f "$dir/key" || fail "keygen failed"
"$bin" keygen -y -f "$dir/key" > "$dir/again.pub" || fail "keygen -y failed"
made=$(tr -d '\r' < "$dir/key.pub" | cut -d' ' -f1,2)
again=$(tr -d '\r' < "$dir/again.pub" | cut -d' ' -f1,2)
if [ -z "$made" ] || [ "$made" != "$again" ]; then
    fail "keygen -y gives another key: '$again', not '$made'"
fi
echo "ok   keygen, then keygen -y: ${made%% *}"
