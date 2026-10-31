#!/bin/sh
# This host's rustc against the highest rust-version that a crate of the
# release's binary declares (T-343). The armv7 build takes the rust that its
# Alpine ships, and the crates' minimum rises with their dependencies (Q48),
# so the job stops here, with both versions named, before a build that
# would fail an hour in. The crates are those of the workspace in the
# binary's graph with the release's features; each declares what its own
# dependencies need, which the gate's steps msrv check.
#
#   sh scripts/check-rustc.sh FEATURES
#
# It runs at the root of the repository, where cargo and rustc are.
set -u

features=${1:-}
have=$(rustc -V | sed -n 's/^rustc \([0-9][0-9.]*\).*/\1/p')
if [ -z "$have" ]; then
    echo "check-rustc: rustc -V names no version" >&2
    exit 1
fi

# Whether the dotted version $1 is above $2.
above() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        n = split(a, x, "."); m = split(b, y, ".")
        for (i = 1; i <= (n > m ? n : m); i++) {
            if (x[i] + 0 > y[i] + 0) exit 0
            if (x[i] + 0 < y[i] + 0) exit 1
        }
        exit 1
    }'
}

workspace=$(tr -d '\r' < Cargo.toml | sed -n '/^\[workspace.package\]/,/^\[/s/^rust-version = "\(.*\)"$/\1/p')
graph=$(cargo tree --locked -p podssh-cli --features "$features" -e normal,build --prefix none) || {
    echo "check-rustc: cargo tree failed" >&2
    exit 1
}
need=0
who=none
# A crate of the workspace is one with a path: `name vX (/its/dir)`.
for dir in $(printf '%s\n' "$graph" | sed -n 's/^[^ ]* v[^ ]* (\(\/[^)]*\)).*/\1/p' | sort -u); do
    v=$(tr -d '\r' < "$dir/Cargo.toml" | sed -n 's/^rust-version = "\(.*\)"$/\1/p' | head -n 1)
    [ -n "$v" ] || v=$workspace
    if [ -n "$v" ] && above "$v" "$need"; then
        need=$v
        who=$(basename "$dir")
    fi
done
if [ "$who" = none ]; then
    echo "check-rustc: no crate of the workspace in the graph of podssh-cli" >&2
    exit 1
fi
if above "$need" "$have"; then
    echo "check-rustc: rustc $have is older than the $need that $who declares; the build would fail" >&2
    exit 1
fi
echo "ok   rustc $have, at least the $need that $who declares (features: ${features:-none})"
