#!/bin/sh
# shellcheck shell=sh
# scripts/dev-native.sh - how scripts/dev.sh reaches the build container on a
# Linux host that has a container engine of its own: Docker or Podman, called
# directly, with a copy of the tree. A Linux workstation, a CI runner and a
# cloud session use it (scripts/cloud-setup.sh makes such a host ready).
# scripts/dev.sh sources it; alone it runs nothing, it only sets the
# transport's settings and defines its functions.
#
# Its functions read REPO_ROOT, PODSSH_BUILD_IMAGE, PODSSH_JOBS and
# PODSSH_TARGET, which scripts/dev.sh sets, when they run.
#
# The contract is the one of scripts/dev-wsl.sh, so that a gate here and a
# gate on Windows prove the same things: an ephemeral container of the build
# image, the tree at /work as a copy without the build output, the
# credentials and the scratch, and the run's own exit code.

# The engine: PODSSH_ENGINE, else the first of docker and podman that
# answers. A client whose daemon is down does not answer `info`, so the next
# engine is tried instead of a run that fails later with a socket error.
PODSSH_ENGINE=${PODSSH_ENGINE:-}

# The limit of one run, in minutes, as wsl-toolkit's --timeout is on Windows.
# A whole gate in one container on a host with 4 CPUs takes longer than CI's
# jobs, which run the steps at the same time.
PODSSH_TIMEOUT_MIN=${PODSSH_TIMEOUT_MIN:-180}

# The container's network. `host` when the host's proxy listens on its own
# loopback (a cloud session's agent proxy), since a container with a network
# of its own cannot reach that address; else the engine's default, as CI.
PODSSH_NETWORK=${PODSSH_NETWORK:-}

# What the copy of the tree leaves out, as EXCLUDES of scripts/dev-wsl.sh:
# the build output (the fuzz workspace has its own), git, the scratch, the
# read-only copies of other projects, the live credentials of .env/, a local
# index, and the worktrees of drafting agents, each a whole checkout. Paths
# from the root of the tree, one word each.
NATIVE_EXCLUDES="target vendor/tailscale-rs/target fuzz/target .git .work .tmp .env .codegraph .claude/worktrees"

# The work directory of the runs, under .work/ (which git ignores and the
# copy leaves out, so a copy never holds an older copy).
NATIVE_DIR="$REPO_ROOT/.work/native"

# native_engine   print the engine to use, or explain why there is none.
native_engine() {
    if [ -n "$PODSSH_ENGINE" ]; then
        if "$PODSSH_ENGINE" info >/dev/null 2>&1; then
            printf '%s' "$PODSSH_ENGINE"
            return 0
        fi
        echo "podssh: PODSSH_ENGINE=$PODSSH_ENGINE does not answer '$PODSSH_ENGINE info'." >&2
        return 69
    fi
    for _e in docker podman; do
        command -v "$_e" >/dev/null 2>&1 || continue
        if "$_e" info >/dev/null 2>&1; then
            printf '%s' "$_e"
            return 0
        fi
    done
    cat >&2 <<'EOF'
podssh: no container engine answers here (docker info, podman info).

  The gate builds in the image of images/build/Dockerfile, so that
  its result does not depend on what this host happens to have installed.
  On a Linux host with root (a cloud session, a fresh VM), one command
  installs Podman, starts a Docker daemon that is installed but stopped,
  and installs the tools of the interop checks:

    sh scripts/cloud-setup.sh

  Else install Docker or Podman, or name one with PODSSH_ENGINE.
EOF
    return 69
}

# native_network   the --network value of a run, or nothing for the default.
native_network() {
    if [ -n "$PODSSH_NETWORK" ]; then
        printf '%s' "$PODSSH_NETWORK"
        return 0
    fi
    case ${HTTPS_PROXY:-${https_proxy:-}} in
        *://127.*|*://localhost*|*://\[::1\]*) printf host ;;
    esac
}

# native_ca   the host's CA file for the tools in the image, or nothing.
# A host behind a TLS-intercepting proxy names the proxy's CA in
# SSL_CERT_FILE; apk, rustup, cargo and git in the image need it too.
# PODSSH_HOST_CA overrides; an empty value passes none.
native_ca() {
    _ca=${PODSSH_HOST_CA-${SSL_CERT_FILE:-}}
    if [ -n "$_ca" ] && [ -r "$_ca" ]; then
        printf '%s' "$_ca"
    fi
}

# native_copy DIR   copy the tree into DIR, without NATIVE_EXCLUDES.
# The two halves of the tar are separate processes with separate exit codes:
# a pipe would report only the reader's.
native_copy() {
    _dst=$1
    _tar="$NATIVE_DIR/tree.$$.tar"
    _args=
    set -f
    for _x in $NATIVE_EXCLUDES; do
        _args="$_args --exclude=./$_x"
    done
    # shellcheck disable=SC2086  # $_args is flags; split, do not glob
    set -- $_args
    set +f
    tar -C "$REPO_ROOT" "$@" -cf "$_tar" .
    _rc=$?
    if [ $_rc -ne 0 ]; then
        echo "podssh: the copy of the tree failed (tar exit $_rc)" >&2
        rm -f "$_tar"
        return 71
    fi
    tar -C "$_dst" -xf "$_tar"
    _rc=$?
    rm -f "$_tar"
    if [ $_rc -ne 0 ]; then
        echo "podssh: the copy of the tree failed (tar -x exit $_rc)" >&2
        return 71
    fi
    return 0
}

# native_remove DIR   remove a run's directory. Files that a rootful
# engine wrote as root are removed by the engine when this user cannot.
native_remove() {
    rm -rf "$1" 2>/dev/null && return 0
    "$NATIVE_ENGINE" run --rm -v "$1:/gone" "$PODSSH_BUILD_IMAGE" \
        sh -c 'rm -rf /gone/* /gone/.[!.]* 2>/dev/null; true' >/dev/null 2>&1
    rm -rf "$1"
}

# The script that runs first in the container: the host's CA for the tools
# of the image, then the payload, from /work when the tree is there. podssh
# itself gets no CA variable, so its tests trust what they trust in CI.
native_entry() {
    cat <<'ENTRY'
#!/bin/sh
# One run of scripts/dev-native.sh, in the build image.
set -u
if [ -r /podssh-run/host-ca.crt ]; then
    mkdir -p /usr/local/share/ca-certificates
    cp /podssh-run/host-ca.crt /usr/local/share/ca-certificates/podssh-host.crt
    if ! update-ca-certificates >/dev/null 2>&1; then
        cat /podssh-run/host-ca.crt >>/etc/ssl/certs/ca-certificates.crt
    fi
    export CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt
fi
if [ -d /work ]; then
    cd /work || exit 71
fi
sh /podssh-run/payload.sh
ENTRY
}

# run_in_image <ws|--no-workspace> <script-path|command-base64> <script|command>
# The one place a run is built, as in scripts/dev-wsl.sh.
run_in_image() {
    _ws=$1
    _payload=$2
    _as_script=$3
    NATIVE_ENGINE=$(native_engine) || return $?
    mkdir -p "$NATIVE_DIR" || return 71
    _run=$(mktemp -d "$NATIVE_DIR/run.XXXXXX") || return 71
    if [ "$_as_script" = script ]; then
        cp "$_payload" "$_run/payload.sh" || { native_remove "$_run"; return 71; }
        case $_payload in
            "$NATIVE_DIR"/scratch/*) rm -f "$_payload" ;;
        esac
    else
        printf '%s' "$_payload" | base64 -d >"$_run/payload.sh" || { native_remove "$_run"; return 64; }
    fi
    native_entry >"$_run/entry.sh"
    set -- --rm --init --name "podssh-dev-${_run##*.}" --label podssh-dev=1 \
        -v "$_run:/podssh-run" \
        -e "CARGO_BUILD_JOBS=$PODSSH_JOBS" -e "PODSSH_TARGET=$PODSSH_TARGET"
    if [ "$_ws" = ws ]; then
        mkdir "$_run/work" && native_copy "$_run/work" || { native_remove "$_run"; return 71; }
        set -- "$@" -v "$_run/work:/work" -w /work
    fi
    _net=$(native_network)
    if [ -n "$_net" ]; then
        set -- "$@" --network "$_net"
    fi
    for _v in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy ALL_PROXY all_proxy; do
        eval "_val=\${$_v:-}"
        if [ -n "$_val" ]; then
            set -- "$@" -e "$_v"
        fi
    done
    _ca=$(native_ca)
    if [ -n "$_ca" ]; then
        cp "$_ca" "$_run/host-ca.crt" || { native_remove "$_run"; return 71; }
    fi
    # The crates that cargo downloads, kept between runs: content checked by
    # Cargo.lock's sums, so a kept copy changes no result. PODSSH_NO_CACHE=1
    # starts each run empty, as CI.
    if [ "${PODSSH_NO_CACHE:-0}" != 1 ]; then
        set -- "$@" -v podssh-cargo-registry:/usr/local/cargo/registry
    fi
    # The limit: the engine removes the container, and the run then ends.
    # Its stderr is dropped: a killed sleep makes its shell say "Terminated".
    ( sleep $((PODSSH_TIMEOUT_MIN * 60)) && "$NATIVE_ENGINE" rm -f "podssh-dev-${_run##*.}" >/dev/null 2>&1 ) 2>/dev/null &
    _watch=$!
    "$NATIVE_ENGINE" run "$@" "$PODSSH_BUILD_IMAGE" sh /podssh-run/entry.sh
    _rc=$?
    # The watchdog's sleep first: killed alone, the subshell leaves it behind.
    pkill -P "$_watch" 2>/dev/null
    kill "$_watch" 2>/dev/null
    wait "$_watch" 2>/dev/null
    if [ "${PODSSH_KEEP:-0}" = 1 ]; then
        echo "podssh: PODSSH_KEEP=1: the run's tree and its target/ are kept in $_run/work" >&2
    else
        native_remove "$_run"
    fi
    return $_rc
}

# scratch_file <prefix>   a script file on this machine, with its path on
# stdout. run_in_image copies it into the run and removes it.
scratch_file() {
    mkdir -p "$NATIVE_DIR/scratch" || return 71
    _f=$(mktemp "$NATIVE_DIR/scratch/$1-XXXXXX") || return 71
    cat >"$_f"
    printf '%s\n' "$_f"
}

# win_path <path>   the path itself, absolute: no other spelling is needed.
win_path() {
    _abs=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd -P) || return 1
    printf '%s/%s\n' "$_abs" "$(basename -- "$1")"
}

# native_images   the build image's toolchain, with no tree.
native_images() {
    _c=$(printf '%s\n' 'uname -srm
rustc --version
cargo --version
ldd --version 2>&1 | head -1
if command -v cc >/dev/null 2>&1; then echo "cc present (expected: the gate uses CC=/nonexistent for the library crates)"; else echo "no cc in the image: the binary and the ts feature will fail to build"; fi' \
        | base64 | tr -d '\r\n')
    run_in_image --no-workspace "$_c" command
}

# native_clean   remove what an interrupted run left: podssh's own
# containers (by label) and the copies under .work/native. Unlike
# wsl-toolkit's gc, both are podssh's alone, so they are removed, not listed;
# never while a run holds the lock.
native_clean() {
    if [ -d "$REPO_ROOT/.work/dev.lock" ]; then
        echo "podssh: a run holds .work/dev.lock; nothing removed." >&2
        return 75
    fi
    NATIVE_ENGINE=$(native_engine) || return $?
    _ids=$("$NATIVE_ENGINE" ps -aq --filter label=podssh-dev=1)
    if [ -n "$_ids" ]; then
        # shellcheck disable=SC2086  # a list of ids
        "$NATIVE_ENGINE" rm -f $_ids >/dev/null
        echo "podssh: removed the containers: $(echo $_ids)"
    fi
    for _d in "$NATIVE_DIR"/run.* "$NATIVE_DIR"/scratch; do
        [ -e "$_d" ] || continue
        native_remove "$_d"
        echo "podssh: removed $_d"
    done
    echo "podssh: clean. The cache of crates stays: $NATIVE_ENGINE volume rm podssh-cargo-registry"
    return 0
}
