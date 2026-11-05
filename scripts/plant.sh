#!/bin/sh
# Proves that the check of the one rule of the build is load-bearing: each
# released binary is statically compiled (the operator, 2026-11-05; T-685).
#
# scripts/check-static.sh reads a Linux ELF and refuses one that names a
# program interpreter or a shared library. This script links one small C
# program twice with the image's cc: dynamically, which the check must
# refuse (the plant), and with -static, which it must pass (the control). A
# guard nobody has seen fail is not a guard.
#
# It replaces the plant of the retired rule "no C in the library crates"
# (CC=/nonexistent), which the operator retired on 2026-11-05.
#
# Runs in the build image with the tree at /work (`sh scripts/dev.sh plant`,
# and CI). It changes no file of the tree.

set -u
cd /work || exit 71

P=${TMPDIR:-/tmp}/podssh-plant-static
rm -rf "$P"
mkdir -p "$P"
trap 'rm -rf "$P"' EXIT
trap 'exit 130' INT TERM
printf 'int main(void) { return 0; }\n' >"$P/plant.c"

if ! command -v cc >/dev/null 2>&1; then
    echo "plant: no cc in this image, so there is nothing to link; this run proves nothing."
    exit 1
fi

echo "== plant: a binary linked dynamically"
cc -o "$P/dynamic" "$P/plant.c" >"$P/cc.out" 2>&1
rc=$?
echo "exit=$rc"
if [ "$rc" -ne 0 ]; then
    echo "THE PLANT DID NOT PLANT: cc could not link the program:"
    cat "$P/cc.out"
    exit 1
fi
sh scripts/check-static.sh "$P/dynamic"
rc=$?
echo "exit=$rc"
if [ "$rc" -eq 0 ]; then
    echo "THE CHECK IS VACUOUS: a binary linked dynamically passed it."
    exit 1
fi
if [ "$rc" -ne 1 ]; then
    echo "The check did not run (exit $rc), so this run proves nothing."
    exit 1
fi
echo "refused, as intended"

echo
echo "== control: the same program linked with -static"
cc -static -o "$P/static" "$P/plant.c" >"$P/cc.out" 2>&1
rc=$?
echo "exit=$rc"
if [ "$rc" -ne 0 ]; then
    echo "CONTROL FAILED: cc could not link the program statically:"
    cat "$P/cc.out"
    exit 1
fi
sh scripts/check-static.sh "$P/static"
rc=$?
echo "exit=$rc"
if [ "$rc" -ne 0 ]; then
    echo "CONTROL FAILED: the check refused a static binary."
    exit 1
fi

echo
echo "plant: the check of a static binary is load-bearing"
exit 0
