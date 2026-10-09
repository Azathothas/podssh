#!/bin/sh
# Proves the gate's no-C-compiler rule is load-bearing.
#
# The build image ships a working `cc`, so the rule is enforced only by the
# `CC=/nonexistent` in scripts/gate.sh, over the library crates (the binary
# links aws-lc for SSH and needs cc). This script plants a dependency that
# genuinely needs a C compiler (`ring`) into a library crate and checks
# that the build fails *because cc is missing*, twice, then that the tree
# builds again once the plant is removed. A guard nobody has seen fail is not
# a guard.
#
# Runs in the build image with the tree at /work (`sh scripts/dev.sh plant`,
# and CI). Cargo.toml and Cargo.lock are restored on every exit path.

set -u
cd /work || exit 71

: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

F=crates/podssh-ws/Cargo.toml
if [ ! -f "$F" ]; then
    echo "plant: $F does not exist, so there is nothing to plant into."
    exit 1
fi

cp "$F" "$F.orig"
cp Cargo.lock Cargo.lock.orig
restore() {
    cp "$F.orig" "$F" && rm -f "$F.orig"
    cp Cargo.lock.orig Cargo.lock && rm -f Cargo.lock.orig
}
# Restore on exit; on a signal, exit (which runs the EXIT trap) instead of
# carrying on with the originals already deleted.
trap restore EXIT
trap 'exit 130' INT TERM

# The crates the rule covers; the same list as scripts/gate.sh.
LIBS="-p podssh-ws -p podssh-relay -p podssh-core -p podssh-terminal -p podssh-probe"

build() {
    # shellcheck disable=SC2086  # $LIBS is a list of flags
    CC=/nonexistent CXX=/nonexistent cargo build $LIBS "$@" >/tmp/plant-build.out 2>&1
}

echo "== baseline: the library crates build with no C compiler"
build --locked
rc=$?
echo "exit=$rc"
if [ "$rc" -ne 0 ]; then
    echo "UNEXPECTED: the clean tree already fails, so the plant would prove nothing."
    tail -30 /tmp/plant-build.out
    exit 1
fi

for n in 1 2; do
    echo
    echo "== plant $n: ring (needs cc) added to [dependencies] of $F"
    # The plant goes into the [dependencies] table by name (not appended to the
    # end of the file, which may be another table), and tolerates a CRLF file.
    if ! grep -q '^\[dependencies\]' "$F.orig"; then
        echo "plant: $F has no [dependencies] table"
        exit 1
    fi
    sed -e '/^\[dependencies\]\r\{0,1\}$/a ring = "0.17"' "$F.orig" > "$F"
    if ! grep -q '^ring = ' "$F"; then
        echo "THE PLANT DID NOT PLANT: no ring line in $F; this run proves nothing."
        exit 1
    fi
    # Not --locked: the plant changes the dependency graph, and a lockfile
    # refusal would be a failure for the wrong reason.
    build
    rc=$?
    echo "exit=$rc"
    if [ "$rc" -eq 0 ]; then
        echo "THE GATE IS VACUOUS: a dependency that needs cc built without one."
        exit 1
    fi
    if ! grep -qE 'failed to find tool|ToolNotFound|custom build command for `ring' /tmp/plant-build.out; then
        echo "The build failed, but not because cc is missing; this run proves nothing:"
        tail -30 /tmp/plant-build.out
        exit 1
    fi
    echo "failed because no C compiler was available, as intended"
    cp "$F.orig" "$F"
    cp Cargo.lock.orig Cargo.lock
done

echo
echo "== control: plant removed, the tree builds again"
build --locked
rc=$?
echo "exit=$rc"
if [ "$rc" -ne 0 ]; then
    echo "CONTROL FAILED: the tree does not build with the plant removed."
    tail -30 /tmp/plant-build.out
    exit 1
fi

# The C++ plant: a crate whose build script compiles one C++ file with the
# `cc` crate, which reads CXX for C++. The build must fail and name
# /nonexistent, which proves CXX was read; the control, with CC alone, must
# not name it, which proves CXX is what stopped it.
P=/tmp/podssh-plant-cxx
rm -rf "$P"
mkdir -p "$P/src"
printf '[package]\nname = "podssh-plant-cxx"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[build-dependencies]\ncc = "1"\n' >"$P/Cargo.toml"
: >"$P/src/lib.rs"
printf 'fn main() {\n    cc::Build::new().cpp(true).file("plant.cpp").compile("plant");\n}\n' >"$P/build.rs"
printf 'int podssh_plant() { return 1; }\n' >"$P/plant.cpp"
echo
echo "== plant: a C++ dependency added to [dependencies] of $F"
sed -e "/^\[dependencies\]\r\{0,1\}\$/a podssh-plant-cxx = { path = \"$P\" }" "$F.orig" > "$F"
if ! grep -q '^podssh-plant-cxx = ' "$F"; then
    echo "THE PLANT DID NOT PLANT: no podssh-plant-cxx line in $F; this run proves nothing."
    exit 1
fi
build
rc=$?
echo "exit=$rc"
if [ "$rc" -eq 0 ]; then
    echo "THE GATE IS VACUOUS: a C++ dependency built with CXX=/nonexistent."
    exit 1
fi
if ! grep -q '/nonexistent' /tmp/plant-build.out; then
    echo "The build failed, but not at CXX=/nonexistent; this run proves nothing:"
    tail -30 /tmp/plant-build.out
    exit 1
fi
echo "failed at CXX=/nonexistent, as intended"
echo
echo "== control: the same plant with CC=/nonexistent alone"
# shellcheck disable=SC2086
CC=/nonexistent cargo build $LIBS >/tmp/plant-build.out 2>&1
rc=$?
echo "exit=$rc"
if grep -q '/nonexistent' /tmp/plant-build.out; then
    echo "CONTROL FAILED: with CC alone the C++ build still named /nonexistent, so CXX is not what stopped it."
    tail -30 /tmp/plant-build.out
    exit 1
fi
echo "with CC alone, the C++ build did not reach /nonexistent: CXX is load-bearing"
cp "$F.orig" "$F"
cp Cargo.lock.orig Cargo.lock
rm -rf "$P"

echo
echo "VERDICT: the gate fails on a C dependency (twice) and on a C++ dependency, and passes without them."
