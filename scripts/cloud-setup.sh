#!/bin/sh
# scripts/cloud-setup.sh - make a Linux host ready for work on podssh: a
# Claude Code cloud session, a fresh VM, a container with root. Each step
# probes first and changes nothing when its result is already there, so a
# second run is a no-op and a session can run it at each start.
#
#   sh scripts/cloud-setup.sh            each step, then the report
#   sh scripts/cloud-setup.sh --check    the report only; changes nothing
#   sh scripts/dev.sh setup              the same as the first
#
# The steps: the packages of the tests and of the interop checks (apt), a
# Docker daemon that is installed but not running, Podman's settings for a
# host with no systemd, the pinned images of the gate and of the box, the
# gate's Rust on the host, the operator's git identity for the commits, and
# in a Claude Code cloud session, cargo settings that fit its disk.
# docs/development.md ("A Linux host, or a cloud session") tells why each is
# needed.
#
# POSIX sh, as scripts/dev.sh. Each exit code is read from its own process.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
LOG_DIR="$REPO_ROOT/.work/setup"
failed=0

say() { printf 'setup: %s\n' "$*"; }
warn() { printf 'setup: WARN %s\n' "$*" >&2; }
fail() { printf 'setup: FAIL %s\n' "$*" >&2; failed=1; }

CHECK_ONLY=0
case ${1:-} in
    --check) CHECK_ONLY=1 ;;
    "") ;;
    -h | --help)
        sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "setup: unknown argument '$1' (try --check or --help)" >&2
        exit 64
        ;;
esac

# Root, or sudo with no password: package installs and the daemon need one.
# sudo -E keeps the session's proxy variables, which apt and dockerd need.
if [ "$(id -u)" = 0 ]; then
    SUDO=
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo -E"
else
    SUDO=none
fi

# The image that a Dockerfile of .github/images/ names on its FROM line.
image_of() {
    tr -d '\r' <"$REPO_ROOT/.github/images/$1/Dockerfile" |
        sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p'
}
BUILD_IMAGE=$(image_of build)
BOX_IMAGE=$(image_of box)
BOX_PROXY_IMAGE=$(image_of box-proxy)

# ------------------------------------------------------------------ packages
# Each tool and the reason it is here:
#   podman, uidmap, slirp4netns, fuse-overlayfs, netavark, aardvark-dns,
#   catatonit       the box like the target sandbox (scripts/test_in_box.sh)
#                   and an engine for scripts/dev.sh where Docker is missing
#   openssh-*, dropbear-bin   servers that podssh did not write, for the
#                   interop checks run natively (AGENTS.md, rule 2 of section 6)
#   groff, mandoc   the manual renders (scripts/interop-man.sh)
#   tmux            the terminal oracle (PODSSH_TEST_TMUX)
#   musl-tools      a static binary built natively, beside the gate's
#   zstd socat shellcheck lrzsz jq curl file binutils git python3 procps less
#                   the scripts and the checks
PACKAGES="podman uidmap slirp4netns fuse-overlayfs netavark aardvark-dns catatonit
openssh-client openssh-server openssh-sftp-server dropbear-bin groff mandoc tmux
musl-tools zstd socat shellcheck lrzsz jq curl file binutils git python3 procps less"

missing_packages() {
    for _p in $PACKAGES; do
        _s=$(dpkg-query -W -f='${db:Status-Status}' "$_p" 2>/dev/null)
        [ "$_s" = installed ] || printf '%s ' "$_p"
    done
}

step_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "no apt-get: install by hand: $(echo $PACKAGES)"
        return 0
    fi
    _miss=$(missing_packages)
    if [ -z "$_miss" ]; then
        say "packages: each is installed"
        return 0
    fi
    if [ "$CHECK_ONLY" = 1 ] || [ "$SUDO" = none ]; then
        warn "packages missing: $_miss"
        return 0
    fi
    say "packages: installing $_miss"
    mkdir -p "$LOG_DIR"
    $SUDO env DEBIAN_FRONTEND=noninteractive timeout 600 apt-get update -q >"$LOG_DIR/apt-update.log" 2>&1
    _rc=$?
    [ $_rc -eq 0 ] || warn "apt-get update exit $_rc (see $LOG_DIR/apt-update.log); installing from the lists it has"
    # shellcheck disable=SC2086  # a list of package names
    $SUDO env DEBIAN_FRONTEND=noninteractive timeout 900 apt-get install -y -q --no-install-recommends $_miss \
        >"$LOG_DIR/apt-install.log" 2>&1
    _rc=$?
    if [ $_rc -ne 0 ]; then
        fail "apt-get install exit $_rc; the end of $LOG_DIR/apt-install.log:"
        tail -5 "$LOG_DIR/apt-install.log" >&2
        return 1
    fi
    _miss=$(missing_packages)
    [ -z "$_miss" ] || { fail "still missing after the install: $_miss"; return 1; }
    say "packages: installed"
}

# -------------------------------------------------------------------- docker
# A cloud session's image can carry Docker with no init system to start it.
# The daemon gets the session's proxy for its pulls; the CA of a proxy that
# intercepts TLS is in the system's store, which the daemon reads.
step_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        say "docker: not installed; Podman is the engine of scripts/dev.sh"
        return 0
    fi
    if timeout 20 docker info >/dev/null 2>&1; then
        say "docker: the daemon answers"
        return 0
    fi
    if [ "$CHECK_ONLY" = 1 ] || [ "$SUDO" = none ] || ! command -v dockerd >/dev/null 2>&1; then
        warn "docker: the daemon does not answer"
        return 0
    fi
    mkdir -p "$LOG_DIR"
    say "docker: starting dockerd (log: $LOG_DIR/dockerd.log)"
    # nohup and a subshell, so the daemon outlives this script and its session.
    ( $SUDO nohup dockerd >"$LOG_DIR/dockerd.log" 2>&1 & )
    _i=0
    while [ $_i -lt 60 ]; do
        if timeout 10 docker info >/dev/null 2>&1; then
            say "docker: the daemon answers"
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    fail "docker: dockerd did not answer in 60 s; the end of its log:"
    tail -5 "$LOG_DIR/dockerd.log" >&2
    return 1
}

# -------------------------------------------------------------------- podman
# With no systemd as PID 1 there is no systemd cgroup manager and no
# journald, which Podman's defaults use. With hybrid cgroups (v1 controllers
# and a v2 mount at /sys/fs/cgroup/unified) crun refuses each container
# ("cgroups in hybrid mode not supported"), and runc runs them.
PODMAN_CONF=/etc/containers/containers.conf.d/50-podssh-nosystemd.conf

podman_conf() {
    _runtime=
    if [ -d /sys/fs/cgroup/unified ] && command -v runc >/dev/null 2>&1 &&
        [ "$(awk '$2 == "/sys/fs/cgroup" { print $3 }' /proc/mounts)" = tmpfs ]; then
        _runtime='runtime = "runc"'
    fi
    cat <<EOF
# Written by scripts/cloud-setup.sh: this host has no systemd, so Podman
# uses cgroupfs and plain files. A runtime of runc is set when the cgroups
# are hybrid, which crun refuses.
[containers]
log_driver = "k8s-file"

[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
$_runtime
EOF
}

step_podman() {
    if ! command -v podman >/dev/null 2>&1; then
        warn "podman: not installed (the box needs it)"
        return 0
    fi
    if [ "$(cat /proc/1/comm 2>/dev/null)" != systemd ]; then
        _want=$(podman_conf)
        if [ "$(cat "$PODMAN_CONF" 2>/dev/null)" != "$_want" ]; then
            if [ "$CHECK_ONLY" = 1 ] || [ "$SUDO" = none ]; then
                warn "podman: $PODMAN_CONF is missing or old"
            else
                $SUDO mkdir -p "$(dirname "$PODMAN_CONF")"
                printf '%s\n' "$_want" | $SUDO tee "$PODMAN_CONF" >/dev/null
                say "podman: wrote $PODMAN_CONF"
            fi
        fi
    fi
    if timeout 30 podman info >/dev/null 2>&1; then
        say "podman: answers ($(podman --version))"
    else
        fail "podman: 'podman info' fails"
        return 1
    fi
}

# -------------------------------------------------------------------- images
# The gate's image for scripts/dev.sh, through scripts/pull-image.sh and its
# mirrors; the box's two images for Podman, which scripts/test_in_box.sh
# builds on. A pull by digest is the same bytes or nothing.
step_images() {
    if [ "$CHECK_ONLY" = 1 ]; then
        return 0
    fi
    if timeout 20 docker info >/dev/null 2>&1; then
        if docker image inspect "$BUILD_IMAGE" >/dev/null 2>&1; then
            say "images: the build image is in Docker"
        elif _got=$(sh "$SCRIPT_DIR/pull-image.sh" "$BUILD_IMAGE"); then
            say "images: pulled $_got into Docker"
        else
            fail "images: the build image did not pull into Docker"
        fi
    fi
    if command -v podman >/dev/null 2>&1 && timeout 30 podman info >/dev/null 2>&1; then
        # The build image too, when Podman is the only engine.
        _for_podman="$BOX_IMAGE $BOX_PROXY_IMAGE"
        timeout 20 docker info >/dev/null 2>&1 || _for_podman="$BUILD_IMAGE $_for_podman"
        for _img in $_for_podman; do
            if podman image exists "$_img" 2>/dev/null; then
                continue
            fi
            if timeout 900 podman pull -q "$_img" >/dev/null 2>&1; then
                say "images: pulled ${_img%@*} into Podman"
            else
                fail "images: ${_img%@*} did not pull into Podman"
            fi
        done
    fi
}

# ---------------------------------------------------------------------- rust
# The host's default toolchain is the gate's: clippy's lints change between
# releases, and the clippy that counts is the gate's (docs/development.md,
# "Checks"). With the musl target, a static binary builds natively too.
step_rust() {
    if ! command -v rustup >/dev/null 2>&1; then
        warn "rust: no rustup; install it (https://rustup.rs) for native builds"
        return 0
    fi
    _want=
    for _eng in docker podman; do
        command -v "$_eng" >/dev/null 2>&1 || continue
        timeout 20 "$_eng" image inspect "$BUILD_IMAGE" >/dev/null 2>&1 || continue
        _want=$(timeout 60 "$_eng" run --rm "$BUILD_IMAGE" rustc --version 2>/dev/null | awk '{print $2}')
        [ -n "$_want" ] && break
    done
    if [ -z "$_want" ]; then
        _want=stable
        warn "rust: the build image is not here; using the newest stable release"
    fi
    _have=$(rustc --version 2>/dev/null | awk '{print $2}')
    _musl=$(rustup target list --installed 2>/dev/null | grep -c '^x86_64-unknown-linux-musl$')
    if [ "$_have" = "$_want" ] && [ "$_musl" = 1 ]; then
        say "rust: $_have, the gate's, with the musl target"
        return 0
    fi
    if [ "$CHECK_ONLY" = 1 ]; then
        warn "rust: the host has ${_have:-none}, the gate has $_want"
        return 0
    fi
    mkdir -p "$LOG_DIR"
    timeout 900 rustup toolchain install "$_want" --profile minimal -c clippy -c rustfmt \
        -t x86_64-unknown-linux-musl >"$LOG_DIR/rustup.log" 2>&1
    _rc=$?
    if [ $_rc -ne 0 ]; then
        fail "rust: rustup exit $_rc (see $LOG_DIR/rustup.log)"
        return 1
    fi
    rustup default "$_want" >/dev/null 2>&1
    say "rust: $(rustc --version)"
}

# ----------------------------------------------------------------------- git
# Each commit is the operator's (docs/decisions.md, "Commits are attributed
# to the operator only"). A cloud session's global identity is its own, so
# the repository gets the identity of its newest commit by a person, once,
# in its own configuration; an identity already set there is kept.
step_git() {
    cd "$REPO_ROOT" || return 1
    if [ -n "$(git config --local user.email 2>/dev/null)" ]; then
        say "git: the repository's identity is $(git config --local user.name) <$(git config --local user.email)>"
        return 0
    fi
    _who=$(git log -n 200 --format='%an%x09%ae' 2>/dev/null |
        grep -v -i -e '\[bot\]' -e 'noreply@anthropic.com' -e 'noreply@github.com' | head -n 1)
    if [ -z "$_who" ]; then
        warn "git: no commit by a person to take the identity from"
        return 0
    fi
    _name=$(printf '%s' "$_who" | cut -f1)
    _mail=$(printf '%s' "$_who" | cut -f2)
    if [ "$CHECK_ONLY" = 1 ]; then
        warn "git: the repository has no identity of its own; the commits would be '$(git config user.name)'"
        return 0
    fi
    git config --local user.name "$_name" && git config --local user.email "$_mail"
    say "git: the repository's identity is now $_name <$_mail>, the author of its newest commit"
}

# --------------------------------------------------------------- the session
# A Claude Code cloud session has a disk allowance of about 40 GB, which
# clippy and the tests of the workspace with full debug information filled
# on 2026-10-30. Its own settings file, which git ignores, gives cargo less to
# keep; a file that is already there is the session's, and is kept.
SESSION_SETTINGS="$REPO_ROOT/.claude/settings.local.json"
step_session() {
    if [ "${CLAUDE_CODE_REMOTE:-}" != true ]; then
        say "session: not a Claude Code cloud session; nothing to set"
        return 0
    fi
    if [ -f "$SESSION_SETTINGS" ]; then
        if grep -q CARGO_PROFILE_DEV_DEBUG "$SESSION_SETTINGS"; then
            say "session: $SESSION_SETTINGS sets cargo's debug information"
        else
            warn "session: $SESSION_SETTINGS is the session's own; add the env of docs/development.md to it"
        fi
        return 0
    fi
    if [ "$CHECK_ONLY" = 1 ]; then
        warn "session: no $SESSION_SETTINGS; builds keep full debug information"
        return 0
    fi
    mkdir -p "$REPO_ROOT/.claude" && cat >"$SESSION_SETTINGS" <<'EOF'
{
  "env": {
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "line-tables-only",
    "CARGO_PROFILE_TEST_DEBUG": "line-tables-only"
  }
}
EOF
    say "session: wrote $SESSION_SETTINGS (cargo keeps less, for the disk allowance)"
}

# -------------------------------------------------------------------- report
report() {
    _v() { "$@" 2>&1 | head -n 1; }
    printf '\n== the host\n'
    printf '%-14s %s\n' cpus "$(nproc 2>/dev/null)"
    printf '%-14s %s\n' memory "$(awk '/^MemTotal:/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
    printf '%-14s %s\n' disk "$(df -h "$REPO_ROOT" 2>/dev/null | awk 'NR==2 {print $4 " free"}')"
    printf '%-14s %s\n' init "$(cat /proc/1/comm 2>/dev/null)"
    printf '%-14s %s\n' jobs "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-unset (set it: AGENTS.md, section 4)}"
    # The proxy's address only: a user and password in its URL stay unprinted.
    printf '%-14s %s\n' proxy "$(printf '%s' "${HTTPS_PROXY:-none}" | sed 's#://[^@/]*@#://#')"
    printf '%-14s %s\n' ca "${SSL_CERT_FILE:-the system store}"
    for _t in docker podman ssh sshd dropbear groff mandoc tmux rustc; do
        if command -v "$_t" >/dev/null 2>&1; then
            case $_t in
                ssh) _ver=$(_v ssh -V) ;;
                sshd) _ver=$(_v sshd -V) ;;
                dropbear) _ver=$(_v dropbear -V) ;;
                tmux) _ver=$(_v tmux -V) ;;
                mandoc) _ver=present ;;
                *) _ver=$(_v "$_t" --version) ;;
            esac
        else
            _ver=-
        fi
        printf '%-14s %s\n' "$_t" "$_ver"
    done
    printf '\nNext: sh scripts/dev.sh check (the gate), or cargo test --no-fail-fast.\n'
}

step_packages
step_docker
step_podman
step_images
step_rust
step_git
step_session
report
if [ $failed -ne 0 ]; then
    echo "setup: FAILED: a step above did not finish." >&2
    exit 1
fi
echo "setup: ready."
exit 0
