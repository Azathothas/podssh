#!/bin/sh
# scripts/dev.sh - the one command that builds and checks podssh.
#
# ⛔ Every developer and every agent runs this. Nobody types wsl-toolkit, and
# nobody reads a manual to use it: the two facts about it that used to require
# a manual are encoded below, once, with the reason next to each.
#
#   sh scripts/dev.sh check      the full gate: record, build, test, constraints
#   sh scripts/dev.sh test       cargo test only
#   sh scripts/dev.sh build      cargo build only
#   sh scripts/dev.sh plant      the planted-defect gate, both directions
#   sh scripts/dev.sh run -- CMD run CMD in the build image, with the tree
#   sh scripts/dev.sh images     report the build image and its toolchain
#   sh scripts/dev.sh clean      list (not remove) leftover wsl-toolkit jobs
#   sh scripts/dev.sh help       this text
#
# It builds inside a Linux container, because the artefact that ships is a
# static Linux binary and the gate's checks (no C compiler for the default
# build, static linkage) are Linux facts. Day-to-day `cargo test` runs fine
# natively; see docs/development.md.
#
# Container runs are serialized by a lock and capped at PODSSH_JOBS cargo jobs
# (default 4): on 2026-10-07 three uncapped builds at once nearly exhausted
# the developer machine's memory through WSL.
#
# ⛔ POSIX sh throughout. The container's shell is a POSIX shell, and a bashism
# here fails as "Bad substitution" partway through a run that had already
# passed its real checks — which is how a green run gets reported as a failure.
#
# ⛔ Every exit code is read from the process that produced it. Nothing is
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

# ------------------------------------------------------------------ configuration
# Overridable, so a future session can point at a different tool or image
# without reading this file first.
PODSSH_TOOL=${PODSSH_TOOL:-wsl-toolkit}
PODSSH_PS=${PODSSH_PS:-powershell.exe}
PODSSH_PS_SCRIPT=${PODSSH_PS_SCRIPT:-powershell.exe}

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
# image DOES carry a working `cc` (the Tailscale feature needs one), so the
# no-C rule for the default build is enforced by `CC=/nonexistent` in
# scripts/gate.sh, and scripts/plant.sh proves that setting is load-bearing.
if [ -z "${PODSSH_BUILD_IMAGE:-}" ]; then
    PODSSH_BUILD_IMAGE=$(image_of "$REPO_ROOT/.github/images/build/Dockerfile") || exit 78
fi
PODSSH_TARGET=${PODSSH_TARGET:-x86_64-unknown-linux-musl}
# Cargo jobs inside the container. Raise it only on a machine with the memory
# for it (roughly 3 GB per job for this workspace).
PODSSH_JOBS=${PODSSH_JOBS:-4}

# ⛔ Why the tree is copied at all, and what is left out.
#
# wsl-toolkit copies the workspace into the container. That means the host's
# `target/` goes with it, and a Windows `target/` is 848 MB against a 1 GiB
# cap — so the run is refused for being too large rather than for any real
# reason. Measured 2026-10-01: "workspace refused: the workspace passes
# 1.0 GiB at target/...". Build output is not source, and is excluded.
#
# ⛔ The list is a single space-separated string and `exclude_args` turns it
# into flags. ⛔ TWO things about that are load-bearing, and both were broken
# before they were measured:
#
#   * It must not be expanded unquoted. `set -- $EXCLUDES` splits on spaces
#     correctly AND THEN GLOBS each word, so `target/**` becomes every file
#     under target. Measured 2026-10-01: 5 patterns became 84 arguments, and
#     the run stalled for minutes instead of starting.
#   * It must not be a single quoted word either. One word with newlines in it
#     is passed whole, and the tool then reads the words after the first as
#     positional arguments — measured: "run takes flags, not positional
#     arguments, and "target/debug" is one".
#
# `set -f` disables globbing for the split and is the whole mechanism: a
# mechanism that cannot glob is a mechanism that cannot break this way again.
#
# ⛔ `target/**` covers the workspace root only. The vendored fork builds on
# the host too (its own workspace, its own `target/`), and a host-built
# `librustls-*.rlib` alone passes 1.0 GiB — measured 2026-10-06:
# "workspace refused: the workspace passes 1.0 GiB at
# vendor/tailscale-rs/target/...". So the fork's build output is excluded by
# its literal path beside the root one.
#
# `.env/` holds live credentials and never enters a build container (persistent
# job directories used to keep a copy of it). `.codegraph/` is a local index.
EXCLUDES="target/** vendor/tailscale-rs/target/** .git/** .work/** .tmp/** .env/** .codegraph/** agents.md"

# ⛔ **The split lives in `run_in_image` and nowhere else.** The globbing has to
# be disabled at BOTH places the words are split: once in the loop below, and
# once where the loop's result is word-split into flags. Measured 2026-10-01
# with only one of the two disabled: 5 patterns became 80 arguments, and the run
# stalled for minutes instead of starting. ⛔ A second copy of the loop — as a
# helper named for the job, called from nowhere — is exactly the drift this
# warns about, and there is only one.

# run_in_image <workspace|--no-workspace> <script-token|command> <is-script>
# The one place a run is built. ⛔ Every argument is quoted here, so nothing
# downstream can re-split a glob by accident.
run_in_image() {
    _ws=$1
    _payload=$2
    _as_script=$3
    set -f
    set -- $EXCLUDES
    set +f
    set -- "$@"
    _args=
    while [ $# -gt 0 ]; do
        _args="$_args --exclude $1"
        shift
    done
    set -f
    # shellcheck disable=SC2086  # $_args is flags; split, do not glob
    set -- $_args
    set +f
    if [ "$_ws" = ws ]; then
        _w=$(win_path "$REPO_ROOT")
        set -- --image "$PODSSH_BUILD_IMAGE" --workspace "$_w" "$@"
    else
        set -- --image "$PODSSH_BUILD_IMAGE" "$@"
    fi
    if [ "$_as_script" = script ]; then
        set -- "$@" --script "$_payload"
    else
        set -- "$@" --command-base64 "$_payload"
    fi
    # Ephemeral: the container and its job directory (a copy of the tree) are
    # removed when the run ends, instead of accumulating on the WSL disk.
    wt run "$@" \
        --env "CARGO_BUILD_JOBS=$PODSSH_JOBS" \
        --env "PODSSH_TARGET=$PODSSH_TARGET" \
        --container-lifecycle ephemeral \
        --timeout 60m
}

# ⛔ Why arguments travel as base64 in one environment variable, twice.
#
# Git Bash rewrites a guest path that begins with `/` into a Windows path
# before the program starts, and it rewrites the VALUE of a variable whose
# name ends in a path-like suffix. Both are properties of MSYS, not of
# wsl-toolkit, and both are silent. Three channels were measured: an argument
# list after -Command is unusable (PowerShell re-parses and splits it), an
# environment variable is unusable (MSYS rewrites the value), and base64 in
# the environment is the one that arrives intact. The count of fields comes
# from $# rather than from a number written at the call site, because a count
# that is one too small silently drops its last argument — which for --dir or
# --script is the argument that decides what runs.
PODSSH_PS_BRIDGE='
$ErrorActionPreference = "Continue"
$fields = $env:PODSSH_ARGV -split ":"
$count  = [int]$fields[0]
$argv   = New-Object System.Collections.ArrayList
for ($i = 1; $i -le $count; $i++) {
    $tok = $fields[$i]
    if (-not $tok.StartsWith("e")) { Write-Error "bad field $i"; exit 64 }
    $null = $argv.Add([Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($tok.Substring(1))))
}
$tool = $env:PODSSH_TOOL
if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    Write-Error "podssh: $tool is not on PATH."
    exit 127
}
& $tool @argv

# 🛘 A NULL $LASTEXITCODE IS NOT A PASS. MEASURED 2026-10-01:
# `$null -eq $LASTEXITCODE` is True before any native process has run, and
# `exit $LASTEXITCODE` with a null value exits 0. 🛘 **So if the tool
# terminated as a PowerShell error rather than a process, this bridge reported
# success — and the whole verdict of `dev.sh check` is that bridge.** 🛘 This
# is the preflight bug again with a different trigger: the preflight only sees
# `command -v`, and a tool that exists and then fails this way slips past it.
#
# 🛘 The exit code is read from the PROCESS, which is the rule this whole
# repository is built on. A null here means no process ran, and that is a
# failure, not a zero.
if ($null -eq $LASTEXITCODE) {
    Write-Error "podssh: $tool ran but set no exit code; treating as failure."
    exit 1
}
exit $LASTEXITCODE
'

b64() { printf '%s' "$1" | base64 | tr -d '\r\n'; }

# ⛔ **The host interpreter, PROVED to run before its exit code is trusted.**
#
# On Windows a `python` on PATH can be the Microsoft Store execution alias: it
# prints *"Python was not found; run without arguments to install from the
# Microsoft Store"* and exits **without running anything**, so a step that read
# only `$?` would report whatever the alias returned and a check that never ran
# would read as a pass. ⛔ This repository has already had exactly that
# (`scripts/check-relay-spec.py`'s header records it, and it is why the alias
# exists there as a named hazard).
#
# ⛔ So the probe is the interpreter's own output, not `command -v`: an alias has
# no version to print. MEASURED 2026-10-05, this machine: `command -v python3`
# resolves to `.../WindowsApps/python3` (the alias, which prints its message and
# exits 49) while `python` resolves to a real 3.13 — ⛔ so the order below and
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

# ⛔ **A subcommand that takes no arguments refuses one rather than dropping it.**
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

# ⛔ The preflight. Measured 2026-10-01, and it is why this function exists.
#
# With `wsl-toolkit` off PATH, a subcommand printed
#
#     scripts/dev.sh: line 182: powershell.exe: command not found
#
# and **exited 0**. A gate that reports success when it did not run is worse
# than no gate, and this is the same defect the repository already documents
# twice: the `????` that means "a probe could not run" and the `del field,
# value` that passed everything. ⛔ **A missing prerequisite must be a missing
# prerequisite, loudly, with a non-zero exit and the command that installs it.**
#
# ⛔ It runs once per invocation, before anything expensive, and it is cheap:
# three `command -v` calls and nothing else.
PREFLIGHT_DONE=0
preflight() {
    [ "$PREFLIGHT_DONE" = 1 ] && return 0
    PREFLIGHT_DONE=1
    if ! command -v "$PODSSH_TOOL" >/dev/null 2>&1; then
        cat >&2 <<EOF
podssh: '$PODSSH_TOOL' is not on PATH, so the container gate cannot run here.

  The gate builds in the image of .github/images/build/Dockerfile so that
  its result does not depend on what this machine happens to have installed. On Windows this
  script drives that container through wsl-toolkit, a single executable
  kept on PATH (usually ~/bin). Anywhere else, run the gate in the image
  directly, as CI does:

    docker run --rm -v "\$PWD:/work" $PODSSH_BUILD_IMAGE sh /work/scripts/gate.sh

  Override the tool with PODSSH_TOOL=/path/to/executable.
EOF
        return 127
    fi
    if ! command -v "$PODSSH_PS" >/dev/null 2>&1; then
        cat >&2 <<EOF
podssh: '$PODSSH_PS' is not on PATH.

  Git Bash rewrites a guest path that begins with / into a Windows path
  before the tool starts, and the tool refuses the rewrite, so every call
  goes through PowerShell rather than around it. See scripts/dev.sh, the
  comment on PODSSH_PS_BRIDGE.

  Override it with PODSSH_PS=/path/to/powershell.
EOF
        return 127
    fi
    return 0
}

# wt <token>...   run wsl-toolkit with these arguments. Returns its own code.
wt() {
    preflight || return $?
    _payload=$#
    for _tok in "$@"; do
        _payload=$_payload:e$(b64 "$_tok")
    done
    PODSSH_ARGV=$_payload \
    PODSSH_TOOL=$PODSSH_TOOL \
    MSYS2_ARG_CONV_EXCL='*' \
    MSYS_NO_PATHCONV=1 \
        "$PODSSH_PS" -NoProfile -Command "$PODSSH_PS_BRIDGE"
}

# step <label> <command...>   run it, keep its last lines, report its own code.
# ⛔ Not a pipe: the output goes to a file and $? is read on its own line.
step() {
    _label=$1
    shift
    printf '\n--- %s\n' "$_label"
    "$@" >"${TMPDIR:-/tmp}/podssh-step.out" 2>&1
    _rc=$?
    tail -6 "${TMPDIR:-/tmp}/podssh-step.out"
    printf 'exit=%s\n' "$_rc"
    return $_rc
}

set_usage() {
    cat <<'USAGE'
podssh - build and check, in a container, with one command

  sh scripts/dev.sh check    the full gate, in order
  sh scripts/dev.sh test     cargo test only
  sh scripts/dev.sh build    cargo build only
  sh scripts/dev.sh plant    the planted-defect gate, both directions
  sh scripts/dev.sh run -- CMD...   run CMD with the tree mounted at /work
  sh scripts/dev.sh images   the build image and its toolchain
  sh scripts/dev.sh clean    list leftover wsl-toolkit jobs (removes nothing)
  sh scripts/dev.sh help     this text

`build` and `test` pass their arguments straight to cargo, so
`sh scripts/dev.sh test -p podssh-core` runs that crate's tests. They do not
set CC=/nonexistent, so `--features ts` (which needs cc) works too.

`check` runs these on the host, and stops if one fails:

  1  python scripts/check-repo.py     500-line rule, doc links, no credentials
  2  python scripts/check-scripts.py  shell scripts are LF and parse under dash

then scripts/gate.sh in the container, where every step must exit 0:

  3  default members build with CC=/nonexistent (no C compiler)
  4  default members: cargo test
  5  Tailscale adapter: cargo test --features podssh-cli/ts (needs cc)
  6  static musl release with CC=/nonexistent: no NEEDED, no interpreter

`plant` proves step 3 is load-bearing: it plants a dependency that needs cc
and checks the build fails for that reason, twice, then passes without it.

Only one container run at a time (a lock in .work/), PODSSH_JOBS cargo jobs.
Overrides: PODSSH_JOBS, PODSSH_TOOL, PODSSH_PS, PODSSH_BUILD_IMAGE, PODSSH_TARGET.
USAGE
}

# win_path <path>   the same path, in the spelling PowerShell understands.
# ⛔ A DIRECTORY, never a file. `cd` into a file fails, and the error reads
# "cd: /tmp/.../gate.sh: Not a directory" — which looks like a missing file and
# is really a function that only worked for directories. Measured 2026-10-01.
win_path() {
    _abs=$(CDPATH= cd -- "${1%/*}" && pwd -W) || return 1
    case $1 in
        */*) printf '%s/%s
' "$_abs" "${1##*/}" ;;
        *)   printf '%s/%s
' "$_abs" "$1" ;;
    esac
}

# scratch_file <prefix>   a script file on this machine, with its Windows path on
# stdout. ⛔ Never mktemp under /tmp and hand that path to the tool: /tmp is
# Git Bash's, and PowerShell resolves it to C:\tmp, which does not exist.
# Measured 2026-10-01: "cd: /tmp/podssh-gate-XXXX.sh: Not a directory".
# --script sends this machine's file bytes, so the file must be somewhere
# both of them can name.
scratch_file() {
    _d=$(mktemp -d "${TMPDIR:-/tmp}/$1-XXXXXX")
    _f="$_d/$1.sh"
    cat > "$_f"
    win_path "$_f"
}

# One cargo subcommand, for `dev.sh build` and `dev.sh test`.
#
# ⛔ No CC override here: these are dev conveniences that must build and test
# ANY crate the user names — including `podssh-cli`, which links the fork
# since 4b and needs cc. The no-C constraint is not enforced per-invocation;
# it is enforced by `scripts/gate.sh` steps 4–5 over the named pure-Rust
# crates, which is the only place that can hold it without breaking the
# crates that legitimately need a compiler. A `CC=/nonexistent` hardcoded
# here would make `dev.sh test -p podssh-cli` fail for a reason unrelated to
# any defect — the exact failure mode the gate comments warn about.
#
# ⛔ The heredoc is UNQUOTED on purpose, so $_verb and $_extra expand here, on
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
# ⛔ The verb and the extra args are pasted into a generated script, so they
# are code, not data. That is acceptable because the caller is a human typing
# a subcommand; it is NOT acceptable for a value that came off the network.
cmd_cargo() {
    _verb=$1
    shift
    _gw=$(cargo_script "$_verb" "$*" | scratch_file "podssh-$_verb")
    run_in_image ws "$_gw" script
}

# The build and check script, as the container runs it. Written here rather
# than kept as a separate file so there is one place that knows what the gate
# is, and no chance of the two disagreeing.
#
# ⛔ `run <label> <command...>` redirects to a file and reads $? on its own
# line. A `cargo ... | tail -2` followed by `echo $?` reports TAIL's status,
# so a failed build prints exit=0. That is this repository's standing trap:
# "a command piped into anything reports the pipe's status".
# ⛔ The gate is `scripts/gate.sh` and nothing else. It used to be a heredoc
# inside this file as well, ⛔ **which is a second copy that can drift from the
# first** — and CI runs that script, so a divergence here would be a pipeline
# proving something the developer never ran. There is now exactly one gate.
cmd_gate() {
    wt_workspace "$(win_path "$REPO_ROOT/scripts/gate.sh")"
}

cmd_images() {
    # No workspace: this is a question about the image, not about the tree.
    # ⛔ base64, not -c. A -c payload containing spaces is split by the bridge's
    # field separator and arrives as several arguments, which the tool reports
    # as "run takes flags, not positional arguments". Measured 2026-10-01, and
    # it is the same reason the gate scripts travel as --script.
    _c=$(printf '%s\n' 'uname -srm
rustc --version
cargo --version
ldd --version 2>&1 | head -1
if command -v cc >/dev/null 2>&1; then echo "cc present (expected: the gate uses CC=/nonexistent for the default build)"; else echo "no cc in the image: the ts feature lane will fail to build"; fi' \
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


# ⛔ The plant is `scripts/plant.sh` and nothing else, for the same reason the
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
    # ⛔ The interpreter first, and nothing after it runs if this fails: a gate
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

    printf -- '\n--- 3-6. the container gate\n'
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
    # ⛔ No `shift` here. The case arm consumed the subcommand name with the
    # `shift` at the top of the dispatch, and `cmd_cargo` shifts once more to
    # take its verb. ⛔ A second shift in the arm ate the first argument a user
    # typed — MEASURED 2026-10-01: `dev.sh test -p podssh-core` ran
    # `cargo test podssh-core`, and `dev.sh build --release` produced no release
    # artefact while **exiting 0**, because cargo reads the mangled form as a
    # bare target pattern and builds. ⛔ **A silently wrong build that reports
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
