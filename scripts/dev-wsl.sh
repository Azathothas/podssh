#!/bin/sh
# shellcheck shell=sh
# scripts/dev-wsl.sh - how scripts/dev.sh reaches the build container from
# Git Bash on Windows: wsl-toolkit, called through PowerShell, with a copy of
# the tree. scripts/dev.sh sources it; alone it runs nothing, it only sets
# the transport's settings and defines its functions.
#
# Its functions read REPO_ROOT, PODSSH_BUILD_IMAGE, PODSSH_JOBS and
# PODSSH_TARGET, which scripts/dev.sh sets, when they run.

# The tool, and the shell that carries its arguments. Overridable, so a
# future session can point at a different tool without reading this file
# first.
PODSSH_TOOL=${PODSSH_TOOL:-wsl-toolkit}
PODSSH_PS=${PODSSH_PS:-powershell.exe}

# Why the tree is copied at all, and what is left out.
#
# wsl-toolkit copies the workspace into the container. That means the host's
# `target/` goes with it, and a Windows `target/` is 848 MB against a 1 GiB
# cap — so the run is refused for being too large rather than for any real
# reason. Measured 2026-10-01: "workspace refused: the workspace passes
# 1.0 GiB at target/...". Build output is not source, and is excluded.
#
# The list is a single space-separated string and `exclude_args` turns it
# into flags. TWO things about that are load-bearing, and both were broken
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
# `target/**` covers the workspace root only. The vendored fork builds on
# the host too (its own workspace, its own `target/`), and a host-built
# `librustls-*.rlib` alone passes 1.0 GiB — measured 2026-10-06:
# "workspace refused: the workspace passes 1.0 GiB at
# vendor/tailscale-rs/target/...". So the fork's build output is excluded by
# its literal path beside the root one.
#
# `.env/` holds live credentials and never enters a build container (persistent
# job directories used to keep a copy of it). `.codegraph/` is a local index.
EXCLUDES="target/** vendor/tailscale-rs/target/** .git/** .work/** .tmp/** .env/** .codegraph/**"

# **The split lives in `run_in_image` and nowhere else.** The globbing has to
# be disabled at BOTH places the words are split: once in the loop below, and
# once where the loop's result is word-split into flags. Measured 2026-10-01
# with only one of the two disabled: 5 patterns became 80 arguments, and the run
# stalled for minutes instead of starting. A second copy of the loop — as a
# helper named for the job, called from nowhere — is exactly the drift this
# warns about, and there is only one.

# run_in_image <workspace|--no-workspace> <script-token|command> <is-script>
# The one place a run is built. Every argument is quoted here, so nothing
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

# Why arguments travel as base64 in one environment variable, twice.
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

# A NULL $LASTEXITCODE IS NOT A PASS. MEASURED 2026-10-01:
# `$null -eq $LASTEXITCODE` is True before any native process has run, and
# `exit $LASTEXITCODE` with a null value exits 0. **So if the tool
# terminated as a PowerShell error rather than a process, this bridge reported
# success — and the whole verdict of `dev.sh check` is that bridge.** This
# is the preflight bug again with a different trigger: the preflight only sees
# `command -v`, and a tool that exists and then fails this way slips past it.
#
# The exit code is read from the PROCESS, which is the rule this whole
# repository is built on. A null here means no process ran, and that is a
# failure, not a zero.
if ($null -eq $LASTEXITCODE) {
    Write-Error "podssh: $tool ran but set no exit code; treating as failure."
    exit 1
}
exit $LASTEXITCODE
'

b64() { printf '%s' "$1" | base64 | tr -d '\r\n'; }

# The preflight. Measured 2026-10-01, and it is why this function exists.
#
# With `wsl-toolkit` off PATH, a subcommand printed
#
#     scripts/dev.sh: line 182: powershell.exe: command not found
#
# and **exited 0**. A gate that reports success when it did not run is worse
# than no gate, and this is the same defect the repository already documents
# twice: the `????` that means "a probe could not run" and the `del field,
# value` that passed everything. **A missing prerequisite must be a missing
# prerequisite, loudly, with a non-zero exit and the command that installs it.**
#
# It runs once per invocation, before anything expensive, and it is cheap:
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
  goes through PowerShell rather than around it. See scripts/dev-wsl.sh, the
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

# win_path <path>   the same path, in the spelling PowerShell understands.
# A DIRECTORY, never a file. `cd` into a file fails, and the error reads
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
# stdout. Never mktemp under /tmp and hand that path to the tool: /tmp is
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
