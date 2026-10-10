#!/bin/sh
# What podssh does on this host, for the record in docs/STATUS.md: run it in
# the sandbox podssh is meant for and keep the output. It prints no secret:
# proxy credentials are masked, and the relay token is never shown.
#
#   sh scripts/sandbox-check.sh [PATH_TO_PODSSH]
#
# Without a path it builds podssh from this checkout (cargo, 4 jobs; the
# binary needs a C compiler for aws-lc), and finds the binary where cargo put
# it. Each step prints ok or FAIL against its expected result, or skip with
# the reason when it cannot run on this host; a skip does not fail the run.
# The script exits 1 when a step failed, else 0. Every network step is
# bounded, and every exit code is read from the command itself, never
# through a pipe.

set -u
B=${1:-}
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-sandbox-check-$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT
failed=0 oks=0 fails=0 skips=0
say() { printf '\n== %s\n' "$*"; }
verdict() { # verdict NAME yes|no|skip DETAIL
    case $2 in
        yes) printf 'ok    %s: %s\n' "$1" "$3"; oks=$((oks + 1)) ;;
        skip) printf 'skip  %s: %s\n' "$1" "$3"; skips=$((skips + 1)) ;;
        *) printf 'FAIL  %s: %s\n' "$1" "$3"; fails=$((fails + 1)); failed=1 ;;
    esac
}
has() { grep -q -- "$1" "$2"; } # has TEXT FILE
finish() {
    printf '\nsandbox-check: %s ok, %s FAIL, %s skip\n' "$oks" "$fails" "$skips"
    exit "$failed"
}

say "host"
uname -srm
id
if [ -r /etc/os-release ]; then . /etc/os-release && echo "${PRETTY_NAME:-}"; fi
for v in https_proxy HTTPS_PROXY all_proxy ALL_PROXY http_proxy HTTP_PROXY no_proxy NO_PROXY; do
    eval "val=\${$v:-}"
    # shellcheck disable=SC2154  # set by the eval above
    [ -n "$val" ] && printf '%s=%s\n' "$v" "$(printf '%s' "$val" | sed 's#//[^@/]*@#//***@#; s#^[^/@]*@#***@#')"
done
for tool in ssh ssh-keygen curl cc cargo timeout setsid; do
    printf '%s: %s\n' "$tool" "$(command -v "$tool" || echo none)"
done
command -v timeout >/dev/null || { echo "timeout is missing: every wait here needs a bound"; exit 1; }

# The binary that cargo built, wherever its settings put it: CARGO_TARGET_DIR
# (relative to the checkout), the target_directory of `cargo metadata` (which
# also reads .cargo/config.toml), then target/; in the directory of
# CARGO_BUILD_TARGET when it is set.
built() {
    meta=$(cd "$REPO" && timeout 120 cargo metadata --format-version 1 --no-deps 2>/dev/null |
        sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | sed 's#\\\\#/#g')
    for dir in "${CARGO_TARGET_DIR:-}" "$meta" target; do
        [ -n "$dir" ] || continue
        case $dir in /* | [A-Za-z]:*) ;; *) dir=$REPO/$dir ;; esac
        sub=release
        [ -z "${CARGO_BUILD_TARGET:-}" ] || sub=$CARGO_BUILD_TARGET/release
        for exe in "$dir/$sub/podssh" "$dir/$sub/podssh.exe"; do
            [ -f "$exe" ] && { printf '%s\n' "$exe"; return 0; }
        done
    done
    return 1
}

if [ -z "$B" ]; then
    say "build"
    CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
    export CARGO_BUILD_JOBS
    (cd "$REPO" && timeout 3600 cargo build --release -p podssh-cli) >"$T/build.log" 2>&1
    rc=$?
    echo "cargo build exit=$rc"
    if [ "$rc" != 0 ]; then tail -40 "$T/build.log"; exit 1; fi
    B=$(built) || {
        verdict build no "cargo built podssh, but it is not in CARGO_TARGET_DIR, the target_directory of cargo metadata or target/"
        finish
    }
    echo "built: $B"
fi

say "podssh --version (the binary runs here)"
timeout 30 "$B" --version
rc=$?
if [ "$rc" != 0 ]; then
    verdict "the binary" no "$B --version exits $rc: it does not run here, so no step can (a noexec mount gives 126)"
    finish
fi

say "podssh doctor --full"
# --full adds the check login: GitHub refuses a key made for the check, which
# shows that the handshake, the host key and the authentication path work.
timeout 300 "$B" doctor --full
rc=$?
if [ "$rc" = 0 ]; then ok=yes; else ok=no; fi
verdict doctor "$ok" "exit $rc (want 0: no check failed)"

say "podssh proxy github.com 22 (GitHub's SSH banner, then exit 0)"
# After its banner the server waits for key exchange, and podssh rightly
# keeps the connection open while the server does; eight zero bytes (a
# packet of length 0) make the server hang up, so the exit is podssh's own.
(printf 'SSH-2.0-podssh-sandbox-check\r\n'; sleep 2; printf '\000\000\000\000\000\000\000\000'; sleep 3) |
    timeout 60 "$B" proxy github.com 22 >"$T/banner" 2>"$T/banner.err"
rc=$?
first=$(head -c 64 "$T/banner" | head -n 1 | tr -d '\r')
cat "$T/banner.err"
case $rc/$first in 0/SSH-2.0-*) ok=yes ;; *) ok=no ;; esac
verdict "proxy github.com 22" "$ok" "exit $rc, first line '$first' (want 0 and SSH-2.0-...)"

say "podssh keygen, then podssh ssh to github.com with that key"
echo "(GitHub does not know the key: exit 255 and 'Permission denied (publickey)' mean the"
echo " handshake and the host-key check through the relay worked)"
"$B" keygen -t ed25519 -N '' -q -C sandbox-check -f "$T/key"
rc=$?
if [ "$rc" = 0 ] && [ -s "$T/key" ] && [ -s "$T/key.pub" ]; then ok=yes; else ok=no; fi
verdict keygen "$ok" "exit $rc (want 0, and the key and its .pub written)"
"$B" keygen -l -f "$T/key.pub"
denied() { # denied NAME ERR RC: GitHub refused the unknown key, after the handshake and the host-key check
    if [ "$3" = 255 ] && has 'Permission denied (publickey)' "$2"; then ok=yes; else ok=no; fi
    verdict "$1" "$ok" "exit $3 (want 255 and 'Permission denied (publickey)')"
}
HOME="$T" timeout 90 "$B" ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "$T/key" -T git@github.com \
    </dev/null 2>"$T/ssh.err"
rc=$?
cat "$T/ssh.err"
denied "ssh -T" "$T/ssh.err" "$rc"
HOME="$T" timeout 90 "$B" ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "$T/key" -tt git@github.com \
    </dev/null 2>"$T/sshtt.err"
rc=$?
cat "$T/sshtt.err"
denied "ssh -tt with no terminal" "$T/sshtt.err" "$rc"

say "a prompt with nobody to answer it (GitHub #15): podssh stops at once and names the remedy"
# podssh asks only on a terminal that the kernel names as its own, or through
# SSH_ASKPASS. setsid drops a terminal of the caller, so each host gives the
# same answer. In the target sandbox /dev/tty opens and never answers; a
# podssh that trusted the open waited there for ever. On Windows podssh asks
# on the console, which nothing here can take away.
SETSID=$(command -v setsid || true)
[ -n "$SETSID" ] || echo "(no setsid here: the steps run in this session)"
asked() { # asked OUT ERR COMMAND...: run it with nobody to answer; sets rc and secs
    out=$1 err=$2
    shift 2
    start=$(date +%s)
    # shellcheck disable=SC2086  # SETSID is empty or one path
    env -u SSH_ASKPASS -u SSH_ASKPASS_REQUIRE -u DISPLAY -u WAYLAND_DISPLAY \
        timeout 90 $SETSID "$@" </dev/null >"$out" 2>"$err"
    rc=$?
    secs=$(($(date +%s) - start))
}
case $(uname -s) in
    MINGW* | MSYS* | CYGWIN*)
        verdict "keygen with no -N" skip "Windows: podssh asks on the console"
        verdict "an unknown host key" skip "Windows: podssh asks on the console"
        ;;
    *)
        asked "$T/kp.out" "$T/kp.err" "$B" keygen -t ed25519 -q -f "$T/kprompt"
        ok=no
        [ "$rc" = 1 ] && [ "$secs" -lt 30 ] && has "-N ''" "$T/kp.err" && [ ! -e "$T/kprompt" ] && ok=yes
        verdict "keygen with no -N" "$ok" "exit $rc after ${secs} s (want 1 within 30 s, -N '' named, no key written)"
        head -n 3 "$T/kp.err"
        mkdir -p "$T/fresh"
        asked "$T/hp.out" "$T/hp.err" env HOME="$T/fresh" "$B" ssh -o StrictHostKeyChecking=ask -i "$T/key" -T git@github.com true
        ok=no
        [ "$rc" = 255 ] && [ "$secs" -lt 60 ] && has 'SHA256:' "$T/hp.err" && has 'accept-new' "$T/hp.err" && ok=yes
        verdict "an unknown host key" "$ok" "exit $rc after ${secs} s (want 255 within 60 s, the fingerprint and accept-new named)"
        head -n 4 "$T/hp.err"
        ;;
esac

say "a listener of podssh pipe (unix-listen:), within 5 s"
# The target sandbox allows an AF_UNIX bind, and the box refuses each bind:
# the step records which. A refusal is 77 and leaves no file; a listener
# that SIGTERM ends removes its file.
lsock="$T/listen.sock"
timeout 5 "$B" pipe "unix-listen:$lsock" stdio </dev/null >"$T/listen.out" 2>"$T/listen.err"
rc=$?
echo "unix-listen exit=$rc"
head -n 2 "$T/listen.err"
ok=no
case $rc in
    77)
        [ ! -e "$lsock" ] && has 'need no listener' "$T/listen.err" && ok=yes
        verdict "a listener" "$ok" "refused: exit 77, the error named, and no file left"
        ;;
    124 | 143)
        has 'listening on' "$T/listen.err" && [ ! -e "$lsock" ] && ok=yes
        verdict "a listener" "$ok" "listened until SIGTERM, which removed its file"
        ;;
    *) verdict "a listener" no "exit $rc (want 77 where the host refuses the bind, else a listener that SIGTERM ends)" ;;
esac

say "OpenSSH with podssh as its ProxyCommand"
if ! command -v ssh >/dev/null; then
    verdict OpenSSH skip "no ssh on this host"
else
    timeout 90 ssh -o ProxyCommand="$B proxy %h %p" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
        -o UserKnownHostsFile="$T/known_hosts_openssh" -i "$T/key" -T git@github.com </dev/null 2>"$T/openssh.err"
    rc=$?
    cat "$T/openssh.err"
    if has 'No user exists for uid' "$T/openssh.err"; then
        verdict OpenSSH skip "OpenSSH needs a user database entry, and uid $(id -u) has none here"
    else
        denied OpenSSH "$T/openssh.err" "$rc"
    fi
fi
finish
