#!/bin/sh
# What podssh does on this host, for the record in docs/STATUS.md: run it in
# the sandbox podssh is meant for and keep the output. It prints no secret:
# proxy credentials are masked, and the relay token is never shown.
#
#   sh scripts/sandbox-check.sh [PATH_TO_PODSSH]
#
# Without a path it builds podssh from this checkout (cargo, 4 jobs; the
# binary needs a C compiler for aws-lc). Every network step is bounded, and
# every exit code is read from the command itself, never through a pipe.

set -u
B=${1:-}
T=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-sandbox-check-$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT
say() { printf '\n== %s\n' "$*"; }

say "host"
uname -srm
id
if [ -r /etc/os-release ]; then . /etc/os-release && echo "${PRETTY_NAME:-}"; fi
for v in https_proxy HTTPS_PROXY all_proxy ALL_PROXY http_proxy HTTP_PROXY no_proxy NO_PROXY; do
    eval "val=\${$v:-}"
    # shellcheck disable=SC2154  # set by the eval above
    [ -n "$val" ] && printf '%s=%s\n' "$v" "$(printf '%s' "$val" | sed 's#//[^@/]*@#//***@#; s#^[^/@]*@#***@#')"
done
for tool in ssh ssh-keygen curl cc cargo timeout; do
    printf '%s: %s\n' "$tool" "$(command -v "$tool" || echo none)"
done
command -v timeout >/dev/null || { echo "timeout is missing: every wait here needs a bound"; exit 1; }

if [ -z "$B" ]; then
    say "build"
    CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
    export CARGO_BUILD_JOBS
    timeout 3600 cargo build --release -p podssh-cli >"$T/build.log" 2>&1
    rc=$?
    echo "cargo build exit=$rc"
    if [ "$rc" != 0 ]; then tail -40 "$T/build.log"; exit 1; fi
    B=target/release/podssh
fi
"$B" --version

say "podssh doctor"
timeout 300 "$B" doctor
echo "exit=$?"

say "podssh proxy github.com 22 (GitHub's SSH banner, then exit 0)"
# After its banner the server waits for key exchange, and podssh rightly
# keeps the connection open while the server does; eight zero bytes (a
# packet of length 0) make the server hang up, so the exit is podssh's own.
(printf 'SSH-2.0-podssh-sandbox-check\r\n'; sleep 2; printf '\000\000\000\000\000\000\000\000'; sleep 3) |
    timeout 60 "$B" proxy github.com 22 >"$T/banner" 2>"$T/banner.err"
echo "exit=$?"
head -c 64 "$T/banner" | head -n 1
cat "$T/banner.err"

say "podssh keygen, then podssh ssh to github.com with that key"
echo "(GitHub does not know the key: exit 255 and 'Permission denied (publickey)' mean the"
echo " handshake and the host-key check through the relay worked)"
"$B" keygen -t ed25519 -N '' -q -C sandbox-check -f "$T/key"
echo "keygen exit=$?"
"$B" keygen -l -f "$T/key.pub"
HOME="$T" timeout 90 "$B" ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "$T/key" -T git@github.com </dev/null
echo "exit=$?"
HOME="$T" timeout 90 "$B" ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -i "$T/key" -tt git@github.com </dev/null
echo "-tt with no terminal: exit=$?"

if command -v ssh >/dev/null; then
    say "OpenSSH with podssh as its ProxyCommand"
    timeout 90 ssh -o ProxyCommand="$B proxy %h %p" -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
        -o UserKnownHostsFile="$T/known_hosts_openssh" -i "$T/key" -T git@github.com </dev/null
    echo "exit=$?"
fi
