# The result lines of the interop harnesses (T-199), and the reference of an
# exit code (T-225). Sourced by scripts/interop.sh and scripts/interop-man.sh
# before their checks, and so used by each harness that interop.sh sources.
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
    # After p_ref or direct_ref (T-225): the case's id, its literal,
    # podssh's code, OpenSSH's code, its text and OpenSSH's command line,
    # for scripts/interop-reference.sh, and OpenSSH's stderr beside them.
    if [ -n "${stock_rc:-}" ]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$3" "$4" "$stock_rc" "$2" "$stock_cmd" >>"$W/refs"
        cp "$W/ref.err" "$W/ref.$1.err" 2>/dev/null
        stock_rc=
    fi
    return 0
}

# The reference of an exit code (T-225): OpenSSH's own client runs first,
# with the arguments that podssh then gets. scripts/interop.sh defines p,
# $W, $BIN and $KH; the next expect_rc records both codes.
stock_rc=
stock_cmd=

# stock_raw [ssh arguments...]: OpenSSH's ssh with no ssh_config, the
# environment of p and stdin from /dev/null, ended at 60 s. Its code is in
# $stock_rc (`none` with no ssh), its stderr in $W/ref.err.
stock_raw() {
    stock_cmd="ssh -F /dev/null $*"
    if command -v ssh >/dev/null 2>&1; then
        timeout 60 env -u SSH_AUTH_SOCK HOME="$W" ssh -F /dev/null "$@" </dev/null >"$W/ref.out" 2>"$W/ref.err"
        stock_rc=$?
    else
        : >"$W/ref.err"
        stock_rc=none
    fi
    return 0
}

# stock PORT [arguments...]: stock_raw with the settings of p, but a
# known_hosts of its own, so that the host key checks read the keys that
# podssh recorded.
stock() {
    _sport=$1
    shift
    stock_raw -p "$_sport" -o UserKnownHostsFile="$W/known_hosts.openssh" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes "$@"
}

# wait_port PORT: wait up to 5 s for a listener on 127.0.0.1:PORT; a server
# that never listens fails the checks that follow, each with its reason.
wait_port() {
    _tries=0
    while ! python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 1).close()" 2>/dev/null; do
        _tries=$((_tries + 1))
        [ "$_tries" -ge 50 ] && return 0
        sleep 0.1
    done
    return 0
}

# p_ref PORT [arguments...]: stock, then p with the same arguments; its
# code is p's.
p_ref() {
    stock "$@"
    p "$@"
}

# direct_ref [arguments...]: stock_raw, then podssh ssh --direct with the
# same arguments and the environment of p; its code is podssh's.
direct_ref() {
    stock_raw "$@"
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct "$@"
}

# INTEROP_ONLY="faults cp" sources only those parts of interop.sh (the name
# after `interop-`), once its servers run: a planted defect of T-251 runs the
# part that holds its check (scripts/plants/). Unset, each part runs.
part() {
    _part=${1#interop-}
    _part=${_part%.sh}
    case " ${INTEROP_ONLY:-$_part} " in
        # shellcheck disable=SC1090  # the part is named by its caller
        *" $_part "*) . "$HERE/$1" ;;
        *) echo "== $1: not run (INTEROP_ONLY=$INTEROP_ONLY)" ;;
    esac
}
