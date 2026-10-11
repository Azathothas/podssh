# The result lines of the interop harnesses (T-199). Sourced by
# scripts/interop.sh and scripts/interop-man.sh before their checks, and so
# used by each harness that interop.sh sources.
#
# A check prints one line: `VERDICT ID TEXT`. The verdict is padded to six
# columns: `ok`, `FAIL`, `skip`, or `env` for a precondition of the host that
# is missing. The ID is stable: dotted parts of [a-z0-9_-], the first naming
# the harness (`ssh` for interop.sh, else the name after `interop-`), with a
# loop's label in place of a value (`for srv in openssh:2201 ...` gives
# `${srv%%:*}`). The TEXT may hold values of the run: seconds, a tty, bytes.
# scripts/interop-baseline.txt holds the verdict that each ID must give, and
# `cargo todo interop` checks the scripts and the logs against it.
#
# Each helper returns 0, so `cond && ok ID T || bad ID T` prints one line.

pass=0
fail=0
skip=0
unmet=0

# ok ID TEXT
ok() {
    pass=$((pass + 1))
    printf 'ok    %s %s\n' "$1" "$2"
    return 0
}

# bad ID TEXT [LOG]: the first 20 lines of LOG follow, indented.
bad() {
    fail=$((fail + 1))
    printf 'FAIL  %s %s\n' "$1" "$2"
    if [ $# -gt 2 ]; then
        sed 's/^/      | /' "$3" | head -20
    fi
    return 0
}

# skipped ID TEXT: the check did not run, by the harness's choice.
skipped() {
    skip=$((skip + 1))
    printf 'skip  %s %s\n' "$1" "$2"
    return 0
}

# unmet ID TEXT: a precondition of the host is missing (not named `env`,
# which would hide env(1)).
unmet() {
    unmet=$((unmet + 1))
    printf 'env   %s %s\n' "$1" "$2"
    return 0
}

# expect_rc ID TEXT WANT GOT [LOG]
expect_rc() {
    if [ "$4" = "$3" ]; then
        ok "$1" "$2 (exit $4)"
    else
        bad "$1" "$2: wanted exit $3, got $4" "${5:-/dev/null}"
    fi
}
