#!/bin/sh
# scripts/dev.sh - the one command that builds and checks podssh.
#
# Every developer and every agent runs this. Nobody types wsl-toolkit, and
# nobody reads a manual to use it: the two facts about it that used to require
# a manual are encoded below, once, with the reason next to each.
#
#   sh scripts/dev.sh check      the host checks, then each step of the gate
#   sh scripts/dev.sh gate       the gate only, in the container
#   sh scripts/dev.sh test       cargo test only
#   sh scripts/dev.sh build      cargo build only
#   sh scripts/dev.sh plant      the plant of the no-C rule, both directions
#   sh scripts/dev.sh run -- CMD run CMD in the build image, with the tree
#   sh scripts/dev.sh images     report the build image and its toolchain
#   sh scripts/dev.sh clean      list (not remove) leftover wsl-toolkit jobs
#   sh scripts/dev.sh help       this text
#
# It builds inside a Linux container, because the artefact that ships is a
# static Linux binary and the gate's checks (no C compiler for the library
# crates, static linkage) are Linux facts. Day-to-day `cargo test` runs fine
# natively; see docs/development.md.
#
# Container runs are serialized by a lock and capped at PODSSH_JOBS cargo jobs
# (default 4): on 2026-10-07 three uncapped builds at once nearly exhausted
# the developer machine's memory through WSL.
#
# POSIX sh throughout. The container's shell is a POSIX shell, and a bashism
# here fails as "Bad substitution" partway through a run that had already
# passed its real checks — which is how a green run gets reported as a failure.
#
# Every exit code is read from the process that produced it. Nothing is
# piped into another program to find out whether it worked: a pipeline reports
# the pipe's status, and a failure then reads as success.

set -u

# ----------------------------------------------------------------- self location
script_src=$0
while [ -L "$script_src" ]; do
    link=$(readlink "$script_src")
    case $link in
        /*) script_src=$link ;;
        *) script_src=$(dirname "$script_src")/$link ;;
    esac
done
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$script_src")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

# The Windows transport: wsl-toolkit through PowerShell, the copy of the tree
# and what it leaves out, the preflight (scripts/dev-wsl.sh).
# shellcheck source=scripts/dev-wsl.sh
. "$SCRIPT_DIR/dev-wsl.sh"

# ------------------------------------------------------------------ configuration
# Overridable, so a future session can point at a different image without
# reading this file first. The tool's settings are in scripts/dev-wsl.sh.

# The image that a Dockerfile of .github/images/ names on its FROM line: the
# one place that names it, pinned to a digest. A CR is dropped, as a checkout
# on Windows can add one.
image_of() {
    _ref=$(tr -d '\r' <"$1" 2>/dev/null | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in
        *@sha256:*) printf '%s\n' "$_ref" ;;
        *)
            echo "podssh: $1 names no image pinned to a digest" >&2
            return 1
            ;;
    esac
}

# The build image, from .github/images/build/Dockerfile. podssh ships a static
# musl binary, and `rust:1-alpine` is musl with rustc and cargo installed. The
# image DOES carry a working `cc` (the binary and the Tailscale feature need
# one), so the no-C rule of the library crates is enforced by
# `CC=/nonexistent` in scripts/gate.sh, and scripts/plant.sh proves that
# setting is load-bearing.
if [ -z "${PODSSH_BUILD_IMAGE:-}" ]; then
    PODSSH_BUILD_IMAGE=$(image_of "$REPO_ROOT/.github/images/build/Dockerfile") || exit 78
fi
PODSSH_TARGET=${PODSSH_TARGET:-x86_64-unknown-linux-musl}
# Cargo jobs inside the container. Raise it only on a machine with the memory
# for it (roughly 3 GB per job for this workspace).
PODSSH_JOBS=${PODSSH_JOBS:-4}


# **The host interpreter, PROVED to run before its exit code is trusted.**
#
# On Windows a `python` on PATH can be the Microsoft Store execution alias: it
# prints *"Python was not found; run without arguments to install from the
# Microsoft Store"* and exits **without running anything**, so a step that read
# only `$?` would report whatever the alias returned and a check that never ran
# would read as a pass. This repository has already had exactly that
# (`scripts/check-relay-spec.py`'s header records it, and it is why the alias
# exists there as a named hazard).
#
# So the probe is the interpreter's own output, not `command -v`: an alias has
# no version to print. MEASURED 2026-10-05, this machine: `command -v python3`
# resolves to `.../WindowsApps/python3` (the alias, which prints its message and
# exits 49) while `python` resolves to a real 3.13 — so the order below and
# the version check are both load-bearing, and a host where BOTH are aliases
# fails here rather than reporting a green check.
host_python() {
    for _cand in python python3; do
        command -v "$_cand" >/dev/null 2>&1 || continue
        _ver=$("$_cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
        case ${_ver:-} in
            3.*) printf '%s' "$_cand"; return 0 ;;
        esac
    done
    return 1
}

# **A subcommand that takes no arguments refuses one rather than dropping it.**
# MEASURED 2026-10-01: `dev.sh build --release` produced no release artefact and
# exited 0. Silently ignoring `dev.sh check --all-features` is the same defect
# with the other polarity, and the two behaviours (a refused *subcommand*, a
# dropped *argument*) disagreeing is how the next reader learns the wrong thing.
no_arguments() {
    [ $# -eq 0 ] && return 0
    echo "podssh: '$_sub' takes no arguments, and '$1' would be dropped." >&2
    echo "podssh: 'sh scripts/dev.sh help' shows what each subcommand takes." >&2
    exit 64
}


set_usage() {
    cat <<'USAGE'
podssh - build and check, in a container, with one command

  sh scripts/dev.sh check    the host checks, then each step of the gate
  sh scripts/dev.sh gate     the gate only, in the container (scripts/gate.sh)
  sh scripts/dev.sh test     cargo test only
  sh scripts/dev.sh build    cargo build only
  sh scripts/dev.sh plant    the plant of the no-C rule, both directions
  sh scripts/dev.sh run -- CMD...   run CMD with the tree mounted at /work
  sh scripts/dev.sh images   the build image and its toolchain
  sh scripts/dev.sh clean    list leftover wsl-toolkit jobs (removes nothing)
  sh scripts/dev.sh help     this text

`build` and `test` pass their arguments straight to cargo, so
`sh scripts/dev.sh test -p podssh-core` runs that crate's tests. They do not
set CC=/nonexistent, so `--features ts` (which needs cc) works too.

`check` runs these on the host, and stops if one fails:

  1  python scripts/check-repo.py     the 500-line rule, doc links, no
                                      credentials, LF, pinned images, no listener
  2  python scripts/check-scripts.py  shell scripts are LF and parse under dash;
                                      the gate's steps agree with its list

then scripts/gate.sh in the container: each of its steps, in order, where
each command must exit 0 (docs/development.md, "The container gate", tells
what each one checks). One step alone:

  sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh STEP'

`plant` proves that the no-C rule of the step libs is load-bearing: it plants
a dependency that needs cc into a library crate and checks that the build
fails for that reason, twice; that a crate that compiles C++ stops at
CXX=/nonexistent; and that the tree builds again without them.

Only one container run at a time (a lock in .work/), PODSSH_JOBS cargo jobs.
Overrides: PODSSH_JOBS, PODSSH_TOOL, PODSSH_PS, PODSSH_BUILD_IMAGE, PODSSH_TARGET.
USAGE
    # The names come from the gate itself, so this text cannot name a step
    # that the gate does not have.
    _steps=$(sh "$SCRIPT_DIR/gate.sh" --list)
    # shellcheck disable=SC2086  # one line of names
    printf '\nThe steps of the gate: %s\n' "$(echo $_steps)"
}


# One cargo subcommand, for `dev.sh build` and `dev.sh test`.
#
# No CC override here: these are dev conveniences that must build and test
# ANY crate the user names — including `podssh-cli`, which needs cc (aws-lc,
# through russh). The no-C constraint is not enforced per-invocation; it is
# enforced by the step `libs` of `scripts/gate.sh` over the library crates,
# which is the only place that can hold it without breaking the crates that
# legitimately need a compiler. A `CC=/nonexistent` hardcoded
# here would make `dev.sh test -p podssh-cli` fail for a reason unrelated to
# any defect — the exact failure mode the gate comments warn about.
#
# The heredoc is UNQUOTED on purpose, so $_verb and $_extra expand here, on
# the host, where they are known. Everything the container must compute is
# escaped with a backslash. Measured 2026-10-01: with the delimiter quoted,
# nothing expanded on the host and the container received the literal text
# `$_verb`, failing with "_verb: not found".
cargo_script() {
    _verb=$1
    _extra=$2
    cat <<CARGO
set -u
cd /work || exit 71
echo "== cargo $_verb $_extra =="
cargo $_verb $_extra
rc=\$?
echo "exit=\$rc"
exit \$rc
CARGO
}

# cmd_cargo <verb> [extra args]   one cargo verb in the build image.
# The verb and the extra args are pasted into a generated script, so they
# are code, not data. That is acceptable because the caller is a human typing
# a subcommand; it is NOT acceptable for a value that came off the network.
cmd_cargo() {
    _verb=$1
    shift
    _gw=$(cargo_script "$_verb" "$*" | scratch_file "podssh-$_verb")
    run_in_image ws "$_gw" script
}

# The gate, as the container runs it: scripts/gate.sh, the one place that
# knows what the gate is.
#
# `run <label> <command...>` redirects to a file and reads $? on its own
# line. A `cargo ... | tail -2` followed by `echo $?` reports TAIL's status,
# so a failed build prints exit=0. That is this repository's standing trap:
# "a command piped into anything reports the pipe's status".
# The gate is `scripts/gate.sh` and nothing else. It used to be a heredoc
# inside this file as well, **which is a second copy that can drift from the
# first** — and CI runs that script, so a divergence here would be a pipeline
# proving something the developer never ran. There is now exactly one gate.
cmd_gate() {
    wt_workspace "$(win_path "$REPO_ROOT/scripts/gate.sh")"
}

cmd_images() {
    # No workspace: this is a question about the image, not about the tree.
    # base64, not -c. A -c payload containing spaces is split by the bridge's
    # field separator and arrives as several arguments, which the tool reports
    # as "run takes flags, not positional arguments". Measured 2026-10-01, and
    # it is the same reason the gate scripts travel as --script.
    _c=$(printf '%s\n' 'uname -srm
rustc --version
cargo --version
ldd --version 2>&1 | head -1
if command -v cc >/dev/null 2>&1; then echo "cc present (expected: the gate uses CC=/nonexistent for the library crates)"; else echo "no cc in the image: the binary and the ts feature will fail to build"; fi' \
        | base64 | tr -d '\r\n')
    wt run --image "$PODSSH_BUILD_IMAGE" --command-base64 "$_c" \
        --container-lifecycle ephemeral --timeout 10m
}

cmd_run() {
    if [ "${1:-}" = "--" ]; then shift; fi
    if [ $# -eq 0 ]; then
        echo "podssh: run needs a command. Try: sh scripts/dev.sh help" >&2
        return 64
    fi
    _s=$(printf '%s\n' "$*" | base64 | tr -d '\r\n')
    run_in_image ws "$_s" command
}

# wt_workspace <script-token>   run the build image with the tree at /work.
wt_workspace() {
    run_in_image ws "$1" script
}


# The plant is `scripts/plant.sh` and nothing else, for the same reason the
# gate is one file: a second copy is a copy that drifts.
cmd_plant() {
    wt_workspace "$(win_path "$REPO_ROOT/scripts/plant.sh")"
}

cmd_clean() {
    # A dry run on purpose. `wsl-toolkit gc` cannot filter by project, so
    # `--apply` would also delete other projects' jobs on this machine. Runs
    # made by this script are ephemeral and leave nothing behind; this lists
    # what older runs left, and the operator decides.
    wt gc --older-than 0s
    _rc=$?
    echo
    echo "podssh: nothing was removed. This lists every wsl-toolkit job on this machine,"
    echo "podssh: not only podssh's. To remove them: wsl-toolkit gc --older-than 0s --apply"
    return $_rc
}


# ------------------------------------------------------------------------ gates
cmd_check() {
    rc=0
    # The interpreter first, and nothing after it runs if this fails: a gate
    # whose host half did not run must not reach the container half and print
    # "check green".
    PY=$(host_python) || {
        cat >&2 <<'EOF'
podssh: no working python 3 on PATH, so the host half of `check` cannot run.

  `python` (and `python3`) resolved to something that prints no version —
  usually the Windows Store execution alias, which exits without running the
  script. A check that did not run is not a pass, so this is a failure rather
  than a skipped step.

  Install a real Python 3, or put one first on PATH and re-run.
EOF
        return 1
    }
    printf -- '--- 1. repository checks\n'
    printf 'podssh: interpreter %s (%s)\n' "$PY" "$(command -v "$PY")"
    "$PY" "$REPO_ROOT/scripts/check-repo.py"
    r=$?
    printf 'exit=%s\n' "$r"
    [ $r -ne 0 ] && rc=1

    # The shell scripts are checked here as well as in CI, so a script that
    # dash cannot parse is caught before the container run.
    printf -- '\n--- 2. the shell scripts are portable\n'
    "$PY" "$REPO_ROOT/scripts/check-scripts.py"
    r=$?
    printf 'exit=%s\n' "$r"
    [ $r -ne 0 ] && rc=1

    # The container gate takes minutes; do not start it when a cheap check has
    # already failed.
    if [ $rc -ne 0 ]; then
        printf -- '\n========================================\n'
        echo "podssh: check FAILED before the container gate; fix the above first."
        return $rc
    fi

    printf -- '\n--- 3. the container gate: each step of scripts/gate.sh\n'
    cmd_gate
    r=$?
    [ $r -ne 0 ] && rc=1

    printf -- '\n========================================\n'
    if [ $rc -eq 0 ]; then echo "podssh: check green."; else echo "podssh: check FAILED."; fi
    return $rc
}

# One container run at a time. Overlapping builds are what exhausted the
# developer machine's memory on 2026-10-07, so a second run refuses rather
# than waits. `mkdir` is atomic, so two runs cannot both take the lock.
LOCK_DIR="$REPO_ROOT/.work/dev.lock"
acquire_lock() {
    mkdir -p "$REPO_ROOT/.work" 2>/dev/null
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        echo "podssh: another 'scripts/dev.sh' run holds $LOCK_DIR" >&2
        if [ -f "$LOCK_DIR/info" ]; then
            echo "podssh: held by: $(cat "$LOCK_DIR/info")" >&2
        fi
        echo "podssh: container runs are serialized so they cannot exhaust memory together." >&2
        echo "podssh: if no run is active, remove that directory and retry." >&2
        exit 75
    fi
    printf 'pid %s, %s, started %s\n' "$$" "$_sub" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >"$LOCK_DIR/info"
    trap 'rm -rf "$LOCK_DIR"' EXIT
    trap 'exit 130' INT TERM
}

[ $# -gt 0 ] || { set_usage; exit 0; }
_sub=$1
shift

case $_sub in
    check|build|test|plant|run|images|gate) acquire_lock ;;
esac

case $_sub in
    help|-h|--help) set_usage; exit 0 ;;
    check)          no_arguments "$@"; cmd_check ;;
    # No `shift` here. The case arm consumed the subcommand name with the
    # `shift` at the top of the dispatch, and `cmd_cargo` shifts once more to
    # take its verb. A second shift in the arm ate the first argument a user
    # typed — MEASURED 2026-10-01: `dev.sh test -p podssh-core` ran
    # `cargo test podssh-core`, and `dev.sh build --release` produced no release
    # artefact while **exiting 0**, because cargo reads the mangled form as a
    # bare target pattern and builds. **A silently wrong build that reports
    # success is the failure mode this repository is most afraid of.**
    build)          cmd_cargo build "$@" ;;
    test)           cmd_cargo test "$@" ;;
    plant)          no_arguments "$@"; cmd_plant ;;
    run)            cmd_run "$@" ;;
    images)         no_arguments "$@"; cmd_images ;;
    clean)          no_arguments "$@"; cmd_clean ;;
    gate)           no_arguments "$@"; cmd_gate ;;
    *)
        echo "podssh: no subcommand '$_sub'." >&2
        echo "podssh: 'sh scripts/dev.sh help' lists them." >&2
        exit 64 ;;
esac
exit $?
