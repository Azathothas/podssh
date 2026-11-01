#!/bin/sh
# The check of a release from end to end, with no human (T-251). Before the
# tag (--local): the gate's static binary of the last push and a build of
# this host. After the tag (TAG): the published files, whose SHA256SUMS, its
# signature and the provenance of each binary are checked first; a source
# that does not verify stops the run before any binary runs. Each check has
# a time limit, and its exit code is read from its own process. The end is a
# table, a verdict and the exit code.
#
#   sh scripts/release-check.sh --local --binary PATH [--build PATH] [--sums FILE] [OPTIONS]
#   sh scripts/release-check.sh TAG [--dir DIR] [OPTIONS]
#   sh scripts/release-check.sh --list [--local | TAG]
#
# OPTIONS:
#   --actions-run NAME=ID  a run of GitHub Actions whose conclusion an ACTIONS
#                          row reads through the public API (repeat it; --list
#                          names each NAME and the run to start)
#   --only ID[,ID...]      the sources, then these checks alone (an ID, or the
#                          part before its dot); a partial run never exits 0
#   --table FILE           the header lines and the table, in Markdown, also
#                          into FILE (docs/STATUS.md, "The release check")
#   --logs DIR             the log of each check (default .work/release-check/DATE)
#   --repo OWNER/NAME      the repository (default Azathothas/podssh)
#   --commit SHA           --local: the artifact's commit (default HEAD)
#
# The artifact: the job `gate (release)` of build.yml uploads it at each
# push, as podssh-x86_64-unknown-linux-musl; with gh's login:
#   gh run download RUN -R Azathothas/podssh -n podssh-x86_64-unknown-linux-musl -D .work/artifact
#
# The plant of the Prove: one byte of a checked binary changed. After the
# tag, from a download of the release (`gh release download TAG -D DIR`):
#   printf x | dd of=DIR/podssh-x86_64-unknown-linux-musl bs=1 seek=4096 conv=notrunc
#   sh scripts/release-check.sh TAG --dir DIR
# Before it, with --sums written at the download and the byte changed after.
# The row sums.check fails, the run prints "no check ran", and exits 1.
#
# Exit: 0 each check passed (each SKIP names the entry or the question that
# holds it); 1 a check failed, or a source did not verify; 3 none failed, but
# an ACTIONS row was not read or --only ran a part; 64 a usage error; 69 a
# tool that every check needs is missing.

set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(CDPATH= cd -- "$HERE/.." && pwd -P)
TAB=$(printf '\t')

MODE= TAG= BINARY= BUILD= SUMS= DIR= ONLY= TABLE= LOGS= COMMIT= LIST=0
SLUG=Azathothas/podssh
RUNS=
# The command line for the table, each path as PATH: the table goes into
# docs/STATUS.md, which holds no path of a session's machine.
ARGS_SHOWN=

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}
refuse() {
    echo "release-check: $*" >&2
    echo "release-check: sh scripts/release-check.sh --help" >&2
    exit 64
}

while [ $# -gt 0 ]; do
    case $1 in
        -h | --help) usage; exit 0 ;;
        --local) MODE=local; ARGS_SHOWN="$ARGS_SHOWN $1" ;;
        --list) LIST=1 ;;
        --binary | --build | --sums | --dir | --only | --table | --logs | --repo | --commit | --actions-run)
            [ $# -ge 2 ] || refuse "$1 needs a value"
            case $1 in
                --only | --repo | --commit | --actions-run) ARGS_SHOWN="$ARGS_SHOWN $1 $2" ;;
                *) ARGS_SHOWN="$ARGS_SHOWN $1 PATH" ;;
            esac
            case $1 in
                --binary) BINARY=$2 ;;
                --build) BUILD=$2 ;;
                --sums) SUMS=$2 ;;
                --dir) DIR=$2 ;;
                --only) ONLY=$2 ;;
                --table) TABLE=$2 ;;
                --logs) LOGS=$2 ;;
                --repo) SLUG=$2 ;;
                --commit) COMMIT=$2 ;;
                --actions-run) RUNS="$RUNS $2" ;;
            esac
            shift
            ;;
        v[0-9]*) [ -z "$TAG" ] || refuse "two tags: $TAG and $1"; TAG=$1; ARGS_SHOWN="$ARGS_SHOWN $1" ;;
        *) refuse "no argument '$1'" ;;
    esac
    shift
done

# Each value that reaches a URL, a command or a file name is checked first.
[ -z "$TAG" ] || MODE=${MODE:-tag}
case $MODE/$TAG in
    local/v*) refuse "--local or TAG, not both" ;;
esac
case $TAG in *[!A-Za-z0-9.-]*) refuse "a tag of letters, digits, dots and dashes: '$TAG'" ;; esac
case $SLUG in */*/* | /* | */ | *[!A-Za-z0-9._/-]*) refuse "--repo is OWNER/NAME: '$SLUG'" ;; */*) ;; *) refuse "--repo is OWNER/NAME" ;; esac
case $ONLY in *[!a-z0-9.,-]*) refuse "--only takes the IDs of --list: '$ONLY'" ;; esac
case $COMMIT in *[!0-9a-f]*) refuse "--commit is a hexadecimal commit: '$COMMIT'" ;; esac
for _r in $RUNS; do
    case $_r in [a-z]*=[0-9]*) ;; *) refuse "--actions-run NAME=ID, with the NAME of --list: '$_r'" ;; esac
    case ${_r#*=} in *[!0-9]*) refuse "--actions-run: the ID of a run is a number: '$_r'" ;; esac
done

# A path of the command line is the caller's, from the caller's directory;
# each check then runs from the tree's root.
abs() {
    case $1 in /* | '') printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac
}
BINARY=$(abs "$BINARY") BUILD=$(abs "$BUILD") SUMS=$(abs "$SUMS")
DIR=$(abs "$DIR") TABLE=$(abs "$TABLE") LOGS=$(abs "$LOGS")
cd "$REPO" || exit 71
# shellcheck source=scripts/release-check-catalog.sh
. "$HERE/release-check-catalog.sh"

if [ "$LIST" = 1 ]; then
    list_catalog "$MODE"
    exit 0
fi
[ -n "$MODE" ] || refuse "--local, or a tag such as v1.0.0"
if [ "$MODE" = local ]; then
    [ -n "$BINARY" ] || refuse "--local needs --binary PATH, the gate's static binary (--help says how to get it)"
    [ -f "$BINARY" ] || refuse "--binary $BINARY: no such file"
    [ -z "$BUILD" ] || [ -f "$BUILD" ] || refuse "--build $BUILD: no such file"
    [ -z "$SUMS" ] || [ -f "$SUMS" ] || refuse "--sums $SUMS: no such file"
    [ -z "$DIR" ] || refuse "--dir is for a tag's files"
else
    [ -z "$BINARY$BUILD$SUMS" ] || refuse "--binary, --build and --sums are for --local"
    [ -z "$DIR" ] || [ -d "$DIR" ] || refuse "--dir $DIR: no such directory"
    [ -z "$COMMIT" ] || refuse "--commit is for --local: a tag names its commit"
fi
command -v timeout >/dev/null 2>&1 || { echo "release-check: timeout is not on PATH: each wait here needs a bound" >&2; exit 69; }

W=$(mktemp -d "${TMPDIR:-/tmp}/podssh-release-check.XXXXXX") || { echo "release-check: no scratch directory" >&2; exit 73; }
case $W in *[[:space:]]*) rm -rf "$W"; echo "release-check: a scratch path with a space: set TMPDIR" >&2; exit 73 ;; esac
chmod 700 "$W"
mkdir -p "$W/bin" "$W/home" "$W/cache"
ROWS=$W/rows.tsv
: >"$ROWS"
LOGS=${LOGS:-$REPO/.work/release-check/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$LOGS" || { echo "release-check: cannot make $LOGS" >&2; exit 73; }

# Each podssh of a check: a home and a cache of this run, so that its relay
# token is minted, used and removed with the scratch directory, and no agent
# or commit of the caller's environment reaches it.
PENV="env -u SSH_AUTH_SOCK -u PODSSH_BUILD_COMMIT HOME=$W/home PODSSH_CACHE_DIR=$W/cache"

# Background processes and pairs of the relay, ended at any exit: a node
# left running, or a pair left open, would outlive the run.
cleanup() {
    if [ -f "$W/pids" ]; then
        while read -r _pid; do kill "$_pid" 2>/dev/null; done <"$W/pids"
    fi
    if [ -f "$W/pairs" ]; then
        while read -r _bin _name; do
            timeout -k 5 60 $PENV "$_bin" relay revoke "$_name" </dev/null >/dev/null 2>&1
        done <"$W/pairs"
    fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# wanted ID: the run takes this check (each, or those of --only).
wanted() {
    [ -z "$ONLY" ] && return 0
    case ",$ONLY," in *",$1,"* | *",${1%%.*},"*) return 0 ;; esac
    return 1
}

# row STATE ID BINARY SECONDS DETAIL: one row of the table. The entry, the
# place and the limit are the catalog's; a row with no line there fails.
row() {
    _line=$(catalog | awk -F'|' -v id="$2" '$1 == id')
    _state=$1
    # No field is empty: read with a tab in IFS joins empty fields.
    _detail=$(printf '%s' "${5:--}" | tr '\t\n\r|' '   /')
    if [ -z "$_line" ]; then
        _state=FAIL
        _detail="not in the catalog of scripts/release-check-catalog.sh; $_detail"
        _line="$2|both|T-251|?|0|"
    fi
    _entry=$(printf '%s' "$_line" | cut -d'|' -f3)
    _where=$(printf '%s' "$_line" | cut -d'|' -f4)
    _limit=$(printf '%s' "$_line" | cut -d'|' -f5)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$_state" "$2" "${_entry:--}" "${_where:--}" "${3:--}" "${_limit:-0}" \
        "${4:-0}" "${_detail:--}" >>"$ROWS"
    printf '%-7s %-20s %-10s %s\n' "$_state" "$2" "${3:--}" "$_detail"
}

# timed_io LIMIT IN OUT ERR COMMAND...: COMMAND ended after LIMIT seconds,
# stdin from IN, stdout to OUT, stderr to ERR (- joins it to OUT). Sets RC,
# its own exit code, and SECS.
timed_io() {
    _t_lim=$1 _t_in=$2 _t_out=$3 _t_err=$4
    shift 4
    _t_0=$(date +%s)
    if [ "$_t_err" = - ]; then
        timeout -k 10 "$_t_lim" "$@" <"$_t_in" >"$_t_out" 2>&1
    else
        timeout -k 10 "$_t_lim" "$@" <"$_t_in" >"$_t_out" 2>"$_t_err"
    fi
    RC=$?
    SECS=$(($(date +%s) - _t_0))
}

# timed LIMIT LOG COMMAND...: the same, with no input and one log.
timed() {
    _t_l=$1 _t_g=$2
    shift 2
    timed_io "$_t_l" /dev/null "$_t_g" - "$@"
}

# why: RC in words.
why() {
    case $RC in
        124 | 137) echo "no end within its limit (exit $RC)" ;;
        126 | 127) echo "did not start (exit $RC)" ;;
        *) echo "exit $RC" ;;
    esac
}

# show LOG: the end of a failed check's log, indented.
show() {
    [ -s "$1" ] && tail -n 12 "$1" | sed 's/^/          | /'
    return 0
}

# by_rc ID BINARY WANT LOG DETAIL: PASS when RC is WANT, else FAIL with why
# and the end of LOG.
by_rc() {
    if [ "$RC" = "$3" ]; then
        row PASS "$1" "$2" "$SECS" "$5"
    else
        row FAIL "$1" "$2" "$SECS" "$(why), not $3; $5"
        show "$4"
    fi
}

# digest FILE: its SHA-256, or none.
digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        _dg=$(sha256sum "$1" 2>/dev/null) || { echo none; return; }
    else
        _dg=$(shasum -a 256 "$1" 2>/dev/null) || { echo none; return; }
    fi
    echo "${_dg%% *}"
}

# rand_hex N: N random bytes in hexadecimal, for the throwaway names.
rand_hex() {
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

# The checks.
# shellcheck source=scripts/release-check-sources.sh
. "$HERE/release-check-sources.sh"
# shellcheck source=scripts/release-check-here.sh
. "$HERE/release-check-here.sh"
# shellcheck source=scripts/release-check-node.sh
. "$HERE/release-check-node.sh"
# shellcheck source=scripts/release-check-actions.sh
. "$HERE/release-check-actions.sh"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf 'release-check: %s, from %s, at %s, on %s\n' "${TAG:-the local sources}" "$REPO" "$STARTED" "$(uname -srm)"
printf 'release-check: the logs are in %s\n\n' "$LOGS"

if [ "$MODE" = tag ]; then sources_tag; else sources_local; fi
if grep -q "^FAIL$TAB" "$ROWS"; then
    SOURCES_FAILED=1
else
    SOURCES_FAILED=0
    checks_here
    checks_node
    checks_actions
    checks_skipped
fi

# finish: each row of the catalog that this run owed and did not make
# fails, then the header, the table and the verdict.
finish() {
    if [ "$SOURCES_FAILED" = 0 ]; then
        catalog | while IFS='|' read -r _id _modes _rest; do
            case $_modes in both | "$MODE") ;; *) continue ;; esac
            # The sources run in each run, --only or not.
            case $_id in src.* | sums.* | provenance | static | build.local) ;; *) wanted "$_id" || continue ;; esac
            awk -F'\t' -v id="$_id" '$2 == id { found = 1 } END { exit !found }' "$ROWS" ||
                row FAIL "$_id" - 0 "no step of the script made this row"
        done
    fi
    _pass=$(awk -F'\t' '$1 == "PASS"' "$ROWS" | wc -l | tr -d ' ')
    _fail=$(awk -F'\t' '$1 == "FAIL"' "$ROWS" | wc -l | tr -d ' ')
    _skip=$(awk -F'\t' '$1 == "SKIP"' "$ROWS" | wc -l | tr -d ' ')
    _open=$(awk -F'\t' '$1 == "ACTIONS"' "$ROWS" | wc -l | tr -d ' ')
    {
        printf 'The release check of %s at `%s`, %s, on %s (`sh scripts/release-check.sh%s`).\n' \
            "${TAG:-the local sources}" "$(printf '%.7s' "${COMMIT:-unknown}")" "$STARTED" "$(uname -sm)" "$ARGS_SHOWN"
        [ -z "${DIGESTS:-}" ] || printf '%s\n' "$DIGESTS"
        printf '\n| Check | Entry | Where | Binary | Limit | Time | Result | Detail |\n'
        printf '| --- | --- | --- | --- | --- | --- | --- | --- |\n'
        while IFS="$TAB" read -r _s _i _e _w _b _l _t _d; do
            [ "$_l" = 0 ] && _l=- || _l="$_l s"
            [ "$_t" = 0 ] && _t=- || _t="$_t s"
            printf '| `%s` | %s | %s | %s | %s | %s | %s | %s |\n' "$_i" "$_e" "$_w" "$_b" "$_l" "$_t" "$_s" "$_d"
        done <"$ROWS"
    } >"$W/table.md"
    printf '\n'
    cat "$W/table.md"
    [ -z "$TABLE" ] || cp "$W/table.md" "$TABLE"
    printf '\n'
    if [ "$SOURCES_FAILED" = 1 ]; then
        echo "release-check: a source did not verify: no check ran. FAILED."
        return 1
    fi
    awk -F'\t' '$1 == "SKIP" { printf "release-check: SKIP %s: %s\n", $2, $8 }' "$ROWS"
    awk -F'\t' '$1 == "ACTIONS" { printf "release-check: ACTIONS %s: %s\n", $2, $8 }' "$ROWS"
    if [ "$_fail" != 0 ]; then
        echo "release-check: $_pass passed, $_fail failed, $_skip skipped, $_open ACTIONS rows not read. FAILED:" \
            "$(awk -F'\t' '$1 == "FAIL" { printf "%s ", $2 }' "$ROWS")"
        return 1
    fi
    if [ "$_open" != 0 ] || [ -n "$ONLY" ]; then
        echo "release-check: $_pass passed, $_skip skipped, $_open ACTIONS rows not read${ONLY:+, and --only ran a part}." \
            "INCOMPLETE: this is not the release check."
        return 3
    fi
    echo "release-check: $_pass passed, $_skip skipped (each named above). PASSED."
    return 0
}
finish
exit $?
