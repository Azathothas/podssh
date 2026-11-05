#!/bin/sh
# check-static.sh BINARY: exit 0 when the Linux ELF BINARY is statically
# compiled, 1 when it is not, 2 when the check cannot run.
#
# The one rule of the build (the operator, 2026-11-05): each released binary
# is statically compiled. A static ELF has no program interpreter (no INTERP
# header) and no shared library to load (no NEEDED entry). The gate's step
# release and release.yml's Linux jobs run it; scripts/plant.sh proves that
# it refuses a binary linked dynamically (T-685).
#
# POSIX sh. Each exit code is read from its own process, never through a pipe.

set -u

if [ "$#" -ne 1 ]; then
    echo "usage: sh scripts/check-static.sh BINARY" >&2
    exit 2
fi
B=$1
if [ ! -f "$B" ]; then
    echo "check-static: $B: no such file" >&2
    exit 2
fi
# A check that cannot run is not a pass.
if ! command -v readelf >/dev/null 2>&1; then
    echo "check-static: readelf is missing; the check did not run" >&2
    exit 2
fi

out=${TMPDIR:-/tmp}/check-static.$$
trap 'rm -f "$out.dyn" "$out.phdr"' EXIT
readelf -d "$B" >"$out.dyn" 2>&1
dyn_rc=$?
readelf -l "$B" >"$out.phdr" 2>&1
phdr_rc=$?
if [ "$dyn_rc" -ne 0 ] || [ "$phdr_rc" -ne 0 ]; then
    echo "check-static: readelf could not read $B:" >&2
    cat "$out.dyn" "$out.phdr" >&2
    exit 2
fi
if grep -qi 'NEEDED' "$out.dyn"; then
    echo "check-static: FAIL $B has dynamic dependencies:"
    grep -i 'NEEDED' "$out.dyn"
    exit 1
fi
if grep -q 'INTERP' "$out.phdr"; then
    echo "check-static: FAIL $B asks for a program interpreter, so it is not static"
    exit 1
fi
echo "check-static: $B is static: no NEEDED entry and no program interpreter"
exit 0
