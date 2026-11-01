#!/bin/sh
# scripts/ts-headscale.sh - the live runs of `podssh ts` against a stand-in
# tailnet (T-334), in place of the operator's (docs/decisions.md,
# 2026-10-31): headscale with its embedded DERP server and a CA made for the
# run, a node of tailscaled with Tailscale SSH as the target, and a second
# one in user space as the peer, for OpenSSH's path and as a SOCKS5 proxy
# that podssh did not write; each in Podman, else Docker, on this host's
# network (scripts/ts-headscale-lib.sh).
#
#   sh scripts/ts-headscale.sh [PODSSH_BINARY]
#   TS_HS_PLANT=unknown-key sh scripts/ts-headscale.sh [PODSSH_BINARY]
#
# PODSSH_BINARY is a build with the feature ts; with none, the harness builds
# one natively (cargo build -p podssh-cli --features ts), with
# CARGO_BUILD_JOBS=4 unless it is set. podssh runs from a copy beside a
# podssh-ca.pem of the run's CA, which its checks before the start trust;
# its node trusts the same CA from PODSSH_TS_TEST_CA_FILE (the fork's patch
# 0027). Each pre-auth key stays in a file and goes to podssh and to
# tailscale by its path alone: no key reaches a terminal, a log or an
# argument, and ts.key checks podssh's outputs for both.
#
# The runs: the status and its JSON (T-100, T-102, T-240); a request and its
# reply through -W (T-101); 1 MiB each way between two nodes, through
# OpenSSH over -W in tcp mode and in relay mode, whose DERP over a WebSocket
# headscale's DERP server carries (T-106's runs with two nodes); a DERP link
# that never comes up, which the bound of --timeout ends with 78 (T-100,
# T-104); an ephemeral node that leaves the node list after its run (T-102);
# the exit status of an interactive login shell, `exit 7`, through
# `podssh ssh --direct -tt` and OpenSSH's `ssh -v -tt` (T-026); the relay's
# refusal of a fresh key through scripts/fake-proxy.py and through the
# peer's SOCKS5 (T-103, T-105, T-281: the live relay, the operator's own); a
# DERP link dropped and back while a session goes on (T-104); and no key in
# any output (T-241).
#
# Each check prints a line of scripts/interop-lib.sh. The exit code is 0 when
# each passed, 1 when one failed, and 3 when none failed but a run could not
# reach the live relay from this host (`env`). TS_HS_PLANT=unknown-key gives
# podssh a pre-auth key that headscale does not know: the registration
# fails, the status run fails, the harness says so and exits 1.
#
# Needs podman or docker, openssl, curl, python3, OpenSSH's ssh, timeout and
# sha256sum; the ports PODSSH_HS_PORT (45380) to PODSSH_HS_PORT+5 of the
# loopback free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"
# shellcheck source=scripts/ts-headscale-lib.sh
. "$HERE/ts-headscale-lib.sh"

PORT=${PODSSH_HS_PORT:-45380}
SOCKS=$((PORT + 4))
SPORT=$((PORT + 5))
URL=https://127.0.0.1:$PORT
HS_NAME=podssh-hs
TARGET_NAME=podssh-hs-target
PEER_NAME=podssh-hs-peer
PLANT=${TS_HS_PLANT:-}
: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

die() {
    echo "ts-headscale: $*" >&2
    exit 1
}
case $PLANT in "" | unknown-key) ;; *) die "TS_HS_PLANT is unknown-key or empty, not $PLANT" ;; esac
for tool in timeout openssl curl python3 ssh sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done
ENGINE=$(hs_engine) || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"

W=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-hs-$$")
mkdir -p "$W/hs" "$W/keys" "$W/state" "$W/in" "$W/out" "$W/bin" || die "cannot use the work directory $W"
SSERVER=
FPROXY=
cleanup() {
    [ -n "$SSERVER" ] && kill "$SSERVER" 2>/dev/null
    [ -n "$FPROXY" ] && kill "$FPROXY" 2>/dev/null
    timeout 60 "$ENGINE" rm -f "$HS_NAME" "$TARGET_NAME" "$PEER_NAME" >/dev/null 2>&1
    # TS_HS_KEEP=1 keeps the outputs to read; the keys go in any case.
    if [ -n "${TS_HS_KEEP:-}" ]; then
        rm -rf "$W/keys"
        echo "ts-headscale: the outputs are kept in $W"
    else
        rm -rf "$W"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
timeout 60 "$ENGINE" rm -f "$HS_NAME" "$TARGET_NAME" "$PEER_NAME" >/dev/null 2>&1

echo "== podssh with the feature ts"
if [ -n "${1:-}" ]; then
    cp "$1" "$W/bin/podssh" || die "no podssh binary at $1"
else
    (cd "$REPO" && timeout 1800 cargo build -q -p podssh-cli --features ts) >"$W/cargo.log" 2>&1 ||
        { tail -40 "$W/cargo.log"; die "podssh did not build with the feature ts"; }
    # Where cargo put it: CARGO_TARGET_DIR when the caller set one.
    cp "${CARGO_TARGET_DIR:-$REPO/target}/debug/podssh" "$W/bin/podssh" || die "no debug/podssh after the build"
fi
BIN=$W/bin/podssh
timeout 30 "$BIN" ts --timeout 5s </dev/null >/dev/null 2>"$W/feature.err"
rc=$?
# With no key a build with the feature says 77; one without, 70.
[ "$rc" = 77 ] || die "$BIN is not a build with the feature ts (podssh ts gave $rc, not 77)"

echo "== a CA of the run; headscale on 127.0.0.1:$PORT with its DERP server"
hs_ca || { cat "$W/openssl.log"; die "openssl made no CA"; }
cp "$W/ca.pem" "$W/bin/podssh-ca.pem" || die "cannot put the CA beside the binary"
hs_config
HS_IMAGE=$(hs_pull "$REPO/images/headscale/Dockerfile") || die "headscale's image did not pull"
TS_IMAGE=$(hs_pull "$REPO/images/tailscale/Dockerfile") || die "Tailscale's image did not pull"
hs_start || { "$ENGINE" logs "$HS_NAME" 2>&1 | tail -20; die "headscale did not answer within 60 s"; }
hs_keys || { cat "$W/hs-cli.log"; die "headscale made no user or no pre-auth key"; }
PKEY=$W/keys/a.key
EKEY=$W/keys/e.key
if [ "$PLANT" = unknown-key ]; then
    PKEY=$W/keys/unknown.key
    hs_unknown_key "$PKEY" || die "no unknown key was made"
    echo "planted: podssh's pre-auth key is one that headscale does not know"
fi

echo "== the target (Tailscale SSH) and the peer (SOCKS5 on 127.0.0.1:$SOCKS)"
ts_node "$TARGET_NAME" target --ssh || { tail -20 "$W/$TARGET_NAME-up.log"; die "the target did not log in"; }
ts_node "$PEER_NAME" peer --ssh=false --socks5-server="127.0.0.1:$SOCKS" ||
    { tail -20 "$W/$PEER_NAME-up.log"; die "the peer did not log in"; }
TARGET_IP=$(ts_cli "$TARGET_NAME" ip -4) || die "the target has no tailnet address"
wait_port "$SOCKS"

# noproxy CMD...: CMD with no proxy, agent or home of this host, and the
# run's CA for the node of podssh.
noproxy() {
    env -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u http_proxy -u HTTP_PROXY -u no_proxy \
        -u NO_PROXY -u SSH_AUTH_SOCK PODSSH_TS_TEST_CA_FILE="$W/ca.pem" HOME="$W" "$@"
}

# pts RUN KEY STATE ARGS...: podssh ts against the stand-in, at most 180 s,
# with the pre-auth key file KEY and the state $W/state/STATE.json; stdin is
# $W/in/RUN.in when there is one; stdout and stderr in $W/out/RUN.out and
# .err; the exit in $rc.
pts() {
    _run=$1
    _key=$2
    _state=$3
    shift 3
    _in=/dev/null
    [ -f "$W/in/$_run.in" ] && _in=$W/in/$_run.in
    noproxy timeout 180 "$BIN" ts --ts-control-url "$URL" --ts-auth-key-file "$_key" \
        --ts-state "$W/state/$_state.json" "$@" <"$_in" >"$W/out/$_run.out" 2>"$W/out/$_run.err"
    rc=$?
}

# prefix RUN: the node-key prefix of the status line of RUN, with home 999.
prefix() {
    LC_ALL=C sed -n 's/^node \([0-9a-f]\{8\}\)[^ ]* ip 100\.[0-9.]* home 999$/\1/p' "$W/out/$1.out"
}

# ossh RUN MODE REMOTE: OpenSSH's ssh to root on the target through
# `podssh ts -W` in MODE (tcp or relay, pinned to headscale's DERP server),
# at most 300 s; stdin $W/in/RUN.in or nothing; podssh's lines in .err.
ossh() {
    _mode="--ts-mode tcp"
    [ "$2" = relay ] && _mode="--ts-mode relay --ts-relay 127.0.0.1:$PORT"
    _in=/dev/null
    [ -f "$W/in/$1.in" ] && _in=$W/in/$1.in
    _pc="$BIN ts --ts-control-url $URL --ts-auth-key-file $PKEY --ts-state $W/state/pipe-$2.json"
    _pc="$_pc --timeout 300s $_mode -W %h:%p"
    noproxy timeout 300 ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o UserKnownHostsFile="$W/known_hosts" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=120 \
        -o ProxyCommand="$_pc" root@"$TARGET_IP" "$3" <"$_in" >"$W/out/$1.out" 2>"$W/out/$1.err"
}

# digest FILE: its SHA-256, read from a file, not a pipe.
digest() {
    sha256sum "$1" >"$W/digest" && read -r _sum _ <"$W/digest" && printf '%s' "$_sum"
}
head -c 1048576 /dev/urandom >"$W/in/up.bin" || die "no random input"
head -c 1048576 /dev/zero >"$W/zeros.bin" || die "no zeros"
UP=$(digest "$W/in/up.bin")
ZEROS=$(digest "$W/zeros.bin")

# both RUN MODE: 1 MiB up, read back as its digest, and 1 MiB of zeros
# down; 0 when both crossed whole.
both() {
    cp "$W/in/up.bin" "$W/in/$1-up.in"
    ossh "$1-up" "$2" sha256sum || return 1
    read -r _got _ <"$W/out/$1-up.out" || return 1
    [ "$_got" = "$UP" ] || return 1
    ossh "$1-down" "$2" 'head -c 1048576 /dev/zero' || return 1
    [ "$(digest "$W/out/$1-down.out")" = "$ZEROS" ]
}

echo "== tcp mode: the check asks headscale for its key"
pts tcp-status "$PKEY" a --ts-mode auto --timeout 60s
NODE_A=$(prefix tcp-status)
if [ "$rc" = 0 ] && [ -n "$NODE_A" ]; then
    ok ts.tcp.status "auto took tcp; a status line with home 999 (node $NODE_A)"
else
    bad ts.tcp.status "exit $rc, no status line of the stand-in" "$W/out/tcp-status.err"
fi
if [ -n "$PLANT" ]; then
    # The registration fails, and podssh says so: 77 with the control server's refusal. Another
    # failure is 2, which the plant's caller tells apart from the 1 it wants.
    # No panic either: a thread of the fork's actors panicked as it shut down (T-384).
    if [ "$rc" = 77 ] && grep -q 'the control server refused this node' "$W/out/tcp-status.err" &&
        ! grep -q 'panicked' "$W/out/tcp-status.err"; then
        echo "planted: the registration was refused (exit 77, said): ts.tcp.status failed, as it must"
    else
        echo "planted: podssh exited $rc, not 77 with the control server's refusal and no panic"
        exit 2
    fi
    echo "ts-headscale: $pass passed, $fail failed (planted)"
    [ "$fail" -eq 0 ] || exit 1
    exit 0
fi
pts tcp-jsonl "$PKEY" a --ts-mode tcp --jsonl --timeout 60s
python3 -I -c 'import json, sys
d = json.loads(open(sys.argv[1]).read())
assert sorted(d) == ["event", "home_region", "nodekey_prefix", "tailnet_ip"] and d["event"] == "status"
assert d["home_region"] == 999 and d["tailnet_ip"].startswith("100.")' "$W/out/tcp-jsonl.out" 2>"$W/jsonl.err"
json_rc=$?
if [ "$rc" = 0 ] && [ "$json_rc" = 0 ]; then
    ok ts.tcp.jsonl "one JSON object of the status, home 999"
else
    bad ts.tcp.jsonl "exit $rc, the object read with exit $json_rc" "$W/out/tcp-jsonl.err"
fi
printf 'SSH-2.0-podssh_ts_headscale\r\n' >"$W/in/tcp-banner.in"
pts tcp-banner "$PKEY" banner --ts-mode tcp --timeout 60s -W "$TARGET_IP:22"
if [ "$rc" = 0 ] && [ "$(head -c 8 "$W/out/tcp-banner.out")" = SSH-2.0- ] &&
    grep -q 'pipe closed: up=29, ' "$W/out/tcp-banner.err"; then
    ok ts.tcp.banner "-W $TARGET_IP:22: 29 bytes up, the server's version line down, after the end of input"
else
    bad ts.tcp.banner "exit $rc" "$W/out/tcp-banner.err"
fi
if both tcp-ssh tcp; then
    ok ts.tcp.ssh "OpenSSH over -W in tcp mode: 1 MiB each way, equal digests"
else
    bad ts.tcp.ssh "the digests or an exit of ssh" "$W/out/tcp-ssh-up.err"
fi

echo "== relay mode: DERP over a WebSocket, pinned to headscale's DERP server"
pts relay-status "$PKEY" relay --ts-mode relay --ts-relay "127.0.0.1:$PORT" --timeout 60s
if [ "$rc" = 0 ] && [ -n "$(prefix relay-status)" ]; then
    ok ts.relay.status "the relay's DERP link up, a status line with home 999"
else
    bad ts.relay.status "exit $rc" "$W/out/relay-status.err"
fi
if both relay-ssh relay; then
    ok ts.relay.ssh "OpenSSH over -W in relay mode: 1 MiB each way through DERP over a WebSocket"
else
    bad ts.relay.ssh "the digests or an exit of ssh" "$W/out/relay-ssh-up.err"
fi

echo "== the bound: a DERP server that speaks no WebSocket, on 127.0.0.1:$SPORT"
openssl s_server -quiet -www -accept "127.0.0.1:$SPORT" -cert "$W/hs/tls.crt" -key "$W/hs/tls.key" \
    >"$W/s_server.log" 2>&1 &
SSERVER=$!
wait_port "$SPORT"
started=$(date +%s)
pts bound "$PKEY" bound --ts-mode relay --ts-relay "127.0.0.1:$SPORT" --timeout 20s
took=$(($(date +%s) - started))
if [ "$rc" = 78 ] && [ "$took" -le 30 ] && grep -q 'did not come up within the wait' "$W/out/bound.err" &&
    grep -q 'dropped (' "$W/out/bound.err"; then
    ok ts.bound "registered, no DERP link: 78 in $took s of a bound of 20 s, each failed attempt said"
else
    bad ts.bound "exit $rc in $took s" "$W/out/bound.err"
fi
kill "$SSERVER" 2>/dev/null
SSERVER=

echo "== an ephemeral node leaves the list after its run"
pts ephemeral "$EKEY" ephemeral --ts-mode tcp --ts-ephemeral --timeout 60s
NODE_E=$(prefix ephemeral)
gone=no
if [ "$rc" = 0 ] && [ -n "$NODE_E" ] && [ -n "$NODE_A" ]; then
    tries=0
    while [ "$tries" -lt 30 ]; do
        hs_has_node "$NODE_E"
        case $? in 1) gone=yes && break ;; 2) break ;; esac
        tries=$((tries + 1))
        sleep 2
    done
fi
# The control: the node of ts.tcp.status, which is not ephemeral, stays.
if [ "$gone" = yes ] && hs_has_node "$NODE_A"; then
    ok ts.ephemeral "node $NODE_E gone from headscale's list within 60 s; node $NODE_A stays"
else
    bad ts.ephemeral "exit $rc, node '$NODE_E' gone: $gone" "$W/out/ephemeral.err"
fi

echo "== exit 7 of an interactive login shell (T-026)"
# typed: `exit 7` once the shell is up, as a person types it. Input that
# comes before the shell sets up its line editing is flushed (its echo comes
# before the MOTD), and a pty passes no end of input to a shell, so a file
# on stdin would leave it waiting. The shell's line editing asks where the
# cursor is (ESC [ 6 n), and the answer is a terminal's, row 1, column 1.
typed() {
    sleep 8
    printf '\033[1;1R'
    sleep 1
    printf 'exit 7\n'
    # Then nothing more, until the session ends or the bound passes.
    sleep 30
}
typed | noproxy timeout 120 ssh -v -tt -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o UserKnownHostsFile="$W/known_hosts.openssh" -o StrictHostKeyChecking=accept-new \
    -o ProxyCommand="$ENGINE exec -i $PEER_NAME tailscale --socket=/run/podssh/ts.sock nc %h %p" \
    root@"$TARGET_IP" >"$W/out/exit7-openssh.out" 2>"$W/out/exit7-openssh.err"
o_rc=$?
typed | noproxy env HTTPS_PROXY="socks5h://127.0.0.1:$SOCKS" timeout 120 "$BIN" ssh --direct -tt -F none \
    -o BatchMode=yes -o UserKnownHostsFile="$W/known_hosts.podssh" -o StrictHostKeyChecking=accept-new \
    root@"$TARGET_IP" >"$W/out/exit7-podssh.out" 2>"$W/out/exit7-podssh.err"
p_rc=$?
sent=none
grep -q 'rtype exit-status' "$W/out/exit7-openssh.err" &&
    sent=$(sed -n '/^debug1: Exit status /{s/^debug1: Exit status \([-0-9]*\).*/\1/;h;};${x;p;}' \
        "$W/out/exit7-openssh.err")
want=255
[ "$sent" = none ] || want=$sent
if ! grep -q -e '^Authenticated to' -e 'debug1: Authenticated to' "$W/out/exit7-openssh.err"; then
    bad ts.exit7 "OpenSSH did not log in (exit $o_rc)" "$W/out/exit7-openssh.err"
elif [ "$p_rc" = "$want" ] && [ "$o_rc" = "$want" ]; then
    ok ts.exit7 "exit 7 typed: OpenSSH $o_rc, exit-status request $sent; podssh --direct -tt $p_rc"
else
    bad ts.exit7 "OpenSSH $o_rc, exit-status request $sent; podssh $p_rc, wanted $want" \
        "$W/out/exit7-podssh.err"
fi

echo "== the live relay refuses a fresh key, through a proxy (T-103, T-105, T-281)"
python3 "$HERE/fake-proxy.py" --port-file "$W/fp.port" --log "$W/out/fake-proxy.log" \
    --map tcp.ts.relay.ajam.dev=tcp.ts.relay.ajam.dev:443 >"$W/fp.out" 2>&1 &
FPROXY=$!
tries=0
until [ -s "$W/fp.port" ] || [ "$tries" -ge 50 ]; do
    tries=$((tries + 1))
    sleep 0.2
done
# Port 1 when the proxy wrote none: nothing listens there, and the run says so.
FPORT=$(cat "$W/fp.port" 2>/dev/null)
[ -n "$FPORT" ] || FPORT=1
# foreign_issuer ERR: the run failed as the fork refused the relay's
# certificate, and the relay's address shows one of an issuer that the
# fork's roots (webpki-roots) do not hold: this host's egress re-terminates
# TLS. FOREIGN says so, with that issuer. A certificate of the relay's own
# issuer that the fork refused is no such case: the run fails.
foreign_issuer() {
    grep -q 'invalid peer certificate: UnknownIssuer' "$1" || return 1
    _issuer=$(echo | timeout 20 openssl s_client -connect tcp.ts.relay.ajam.dev:443 \
        -servername tcp.ts.relay.ajam.dev 2>/dev/null | sed -n 's/^issuer=//p' | head -1)
    case "$_issuer" in
        "" | *"Let's Encrypt"* | *"Google Trust Services"* | *"DigiCert"* | *"Sectigo"* | *"GlobalSign"*)
            return 1 ;;
    esac
    FOREIGN="this host's egress shows the relay with a certificate of $_issuer, which the fork's roots do not hold"
    return 0
}

# live RUN PROXY: a fresh ephemeral node in relay mode, to the live relay,
# through PROXY for each host but headscale's loopback.
live() {
    noproxy env HTTPS_PROXY="$2" NO_PROXY=127.0.0.1 timeout 120 "$BIN" ts --ts-control-url "$URL" \
        --ts-auth-key-file "$EKEY" --ts-state "$W/state/$1.json" --ts-mode relay --ts-ephemeral --timeout 60s \
        </dev/null >"$W/out/$1.out" 2>"$W/out/$1.err"
    rc=$?
}
live live-http "http://127.0.0.1:$FPORT"
connects=$(grep -c '^200 CONNECT tcp.ts.relay.ajam.dev:443' "$W/out/fake-proxy.log" 2>/dev/null)
if [ "$rc" = 77 ] && grep -q 1008 "$W/out/live-http.err"; then
    ok ts.live.refused "registered with headscale, refused by the relay with 1008: exit 77"
    if [ "${connects:-0}" -ge 2 ]; then
        ok ts.live.proxy "the check and the node's own DERP dial each a CONNECT ($connects)"
    else
        bad ts.live.proxy "$connects CONNECT to the relay" "$W/out/fake-proxy.log"
    fi
elif [ "$rc" = 78 ] && grep -q 'mode relay tcp.ts.relay.ajam.dev:443: ' "$W/out/live-http.err"; then
    unmet ts.live.refused "the live relay is not reachable from this host"
    unmet ts.live.proxy "the live relay is not reachable from this host"
elif foreign_issuer "$W/out/live-http.err"; then
    unmet ts.live.refused "$FOREIGN"
    unmet ts.live.proxy "$FOREIGN"
else
    bad ts.live.refused "exit $rc" "$W/out/live-http.err"
    bad ts.live.proxy "exit $rc" "$W/out/live-http.err"
fi
live live-socks5 "socks5h://127.0.0.1:$SOCKS"
if [ "$rc" = 77 ] && grep -q 1008 "$W/out/live-socks5.err"; then
    ok ts.live.socks5 "through tailscaled's SOCKS5: refused by the relay with 1008, exit 77"
elif [ "$rc" = 78 ] && grep -q 'mode relay tcp.ts.relay.ajam.dev:443: ' "$W/out/live-socks5.err"; then
    unmet ts.live.socks5 "the live relay is not reachable from this host"
elif foreign_issuer "$W/out/live-socks5.err"; then
    unmet ts.live.socks5 "$FOREIGN"
else
    bad ts.live.socks5 "exit $rc" "$W/out/live-socks5.err"
fi
kill "$FPROXY" 2>/dev/null
FPROXY=

echo "== a DERP link dropped and back while a session goes on (T-104)"
# headscale stops for 45 s, 25 s into a session whose command answers after
# 40 s: the DERP link has answered pings by then, and three go unanswered.
ossh relay-drop relay 'sleep 40; head -c 1048576 /dev/zero' &
session=$!
sleep 25
timeout 30 "$ENGINE" kill --signal STOP "$HS_NAME" >/dev/null 2>&1
sleep 45
timeout 30 "$ENGINE" kill --signal CONT "$HS_NAME" >/dev/null 2>&1
# ossh ends within its own bound of 300 s.
wait "$session"
rc=$?
if [ "$rc" = 0 ] && [ "$(digest "$W/out/relay-drop.out")" = "$ZEROS" ] &&
    grep -q 'dropped (' "$W/out/relay-drop.err" && grep -q 'is up again' "$W/out/relay-drop.err"; then
    ok ts.relay.drop "headscale stopped 45 s: the link dropped and came back, 1 MiB whole"
else
    bad ts.relay.drop "exit $rc" "$W/out/relay-drop.err"
fi

echo "== no pre-auth key in any output (T-241)"
leaked=
for f in "$W"/out/*; do
    if grep -F -q -f "$PKEY" "$f" || grep -F -q -f "$EKEY" "$f"; then
        leaked="$leaked ${f##*/}"
    fi
done
if [ -z "$leaked" ]; then
    ok ts.key "neither key in podssh's outputs, ssh's or the proxy's log"
else
    bad ts.key "a key in:$leaked"
fi

echo "ts-headscale: $pass passed, $fail failed, $unmet not run here"
[ "$fail" -eq 0 ] || exit 1
[ "$unmet" -eq 0 ] || exit 3
exit 0
