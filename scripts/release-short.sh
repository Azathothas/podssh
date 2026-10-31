#!/bin/sh
# The short form of the release check (T-251), on each target's own platform
# (T-218): a release binary prints the version of Cargo.toml, writes the
# whole manual, makes a key with no passphrase, prints that key's public key
# again from the private key, and has the iroh road (T-348). With --net, it
# also reads GitHub's SSH banner through the live relay (podssh proxy
# github.com 22), a test target of AGENTS.md. No target ships that no run executed. The key is a
# throwaway, made in a directory of this run and removed with it. Where
# PODSSH_BUILD_COMMIT names the commit of the build (the release's builds,
# T-210), the binary must name it in --version; else it may name a commit.
#
#   sh scripts/release-short.sh target/release/podssh [--net]
#
# It runs where the binary runs: a runner of each system, or a container of
# the target's platform. It needs a POSIX shell, sed, cut, tr, wc, head and
# mktemp, and for --net, timeout, or sleep and kill where there is none.
set -u

bin=${1:-}
net=${2:-}
if [ -z "$bin" ] || [ ! -f "$bin" ] || { [ -n "$net" ] && [ "$net" != --net ]; }; then
    echo "usage: release-short.sh BINARY [--net] (got '$*')" >&2
    exit 64
fi

fail() {
    echo "release-short: $*" >&2
    exit 1
}

# The checkout can hold CRLF line ends, and Windows prints CR too.
want=$(tr -d '\r' < Cargo.toml | sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p')
[ -n "$want" ] || fail "no version in Cargo.toml"
got=$("$bin" --version | tr -d '\r') || fail "--version failed"
commit=${PODSSH_BUILD_COMMIT:-}
if [ -n "$commit" ]; then
    [ "$got" = "podssh $want ($commit)" ] || fail "the binary prints \"$got\", not \"podssh $want ($commit)\""
else
    case "$got" in
        "podssh $want" | "podssh $want ("*")") ;;
        *) fail "the binary prints \"$got\", not \"podssh $want\"" ;;
    esac
fi
echo "ok   --version: $got"

dir=$(mktemp -d "${TMPDIR:-/tmp}/podssh-release-short.XXXXXX") || fail "no scratch directory"
trap 'rm -rf "$dir"' EXIT HUP INT TERM

"$bin" man --no-pager > "$dir/man.txt" || fail "man --no-pager failed"
lines=$(wc -l < "$dir/man.txt" | tr -d " ")
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

# The iroh road is in the binary (T-348): a ticket that is no ticket is read
# as one and refused as a usage error (64), where a build without the road
# refuses each iroh: destination with 70. Nothing is dialled.
"$bin" ssh -o BatchMode=yes iroh:x true < /dev/null > /dev/null 2> "$dir/iroh.err"
rc=$?
if [ "$rc" != 64 ] || ! grep -q "not an iroh ticket" "$dir/iroh.err"; then
    fail "iroh:x exited $rc, not 64, so the binary has no iroh road: $(tr -d '\r' < "$dir/iroh.err" | head -n 2)"
fi
echo "ok   the iroh road: iroh:x is read as a ticket, and refused as one"

[ -n "$net" ] || exit 0

# limited SECONDS COMMAND...: COMMAND, ended after SECONDS. macOS has no
# timeout(1); there a killer in the background stands in, its output away
# from the pipe so that the pipe ends with COMMAND.
limited() {
    if command -v timeout > /dev/null 2>&1; then
        timeout "$@"
        return
    fi
    secs=$1
    shift
    "$@" &
    pid=$!
    (sleep "$secs" && kill "$pid") > /dev/null 2>&1 &
    killer=$!
    wait "$pid"
    rc=$?
    kill "$killer" 2> /dev/null
    return "$rc"
}

# The relay mints its own token. podssh proxy keeps the stream after stdin
# ends, so the time limit ends it; the first line is the answer.
banner=$(limited 40 "$bin" proxy github.com 22 < /dev/null 2> "$dir/proxy.err" | head -n 1 | tr -d '\r')
case "$banner" in
    SSH-2.0-*) echo "ok   proxy github.com 22: $banner" ;;
    *) fail "proxy github.com 22 gave '$banner': $(tail -n 3 "$dir/proxy.err")" ;;
esac
