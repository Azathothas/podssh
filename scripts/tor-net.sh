#!/bin/sh
# A private Tor network of C tor on this host, for the tests of the Tor
# road (T-353): chutney's network `basic` (four authorities, five exits,
# two clients), and arti-client's configuration of it, which the tests read
# from PODSSH_TEST_TOR_NETWORK. Its relays know no other network, so
# nothing of it reaches Tor's own.
#
# start-bridges (T-385) makes a network of podssh's own in its place: four
# authorities, a bridge authority, four exits, and one bridge whose
# pluggable transports are Tor's own servers, meek-server 0.38.0 and the
# WebTunnel server 0.0.7, built here with Go from their modules (through
# Go's module proxy) and started by the bridge's tor. It prints the path of
# a file of the bridge's lines, one for each transport, beside the
# network's arti.toml; the tests read it from PODSSH_TEST_TOR_BRIDGES.
#
#   sh scripts/tor-net.sh start DIR [ADDRESS]           # prints the path of arti.toml
#   sh scripts/tor-net.sh start-bridges DIR [ADDRESS]   # prints the path of the bridge lines
#   sh scripts/tor-net.sh stop DIR
#
# The relays listen on ADDRESS, 127.0.0.1 by default. podssh sends no
# loopback address through a proxy, so a test of the proxy's road gives
# another address of this host. Both forms take the same ports: stop one
# network before the other starts.
#
# chutney comes from the Tor Project at a pinned commit, into DIR, with its
# Python packages in a virtual environment there. It needs tor and
# tor-gencert, git, and python3 with venv; start-bridges needs go too.
set -u

CHUTNEY_URL=https://gitlab.torproject.org/tpo/core/chutney.git
CHUTNEY_COMMIT=c6b2c5faa67a34354fd1bbb9d7d50c11f8aafb4d
MEEK_SERVER=git.torproject.org/pluggable-transports/meek.git/meek-server@v0.38.0
WEBTUNNEL_SERVER=gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/main/server@v0.0.7
# The transports' ports on ADDRESS: above each of chutney's (5100 to 10000
# and the node's number).
MEEK_PORT=11780
WEBTUNNEL_PORT=11781

what=${1:-}
dir=${2:-}
address=${3:-127.0.0.1}
case $what in
    start | start-bridges | stop) ;;
    *) what= ;;
esac
if [ -z "$dir" ] || [ -z "$what" ]; then
    echo "usage: tor-net.sh start DIR [ADDRESS] | start-bridges DIR [ADDRESS] | stop DIR (got '$*')" >&2
    exit 64
fi
mkdir -p "$dir" || exit 73
dir=$(cd "$dir" && pwd)
chutney="$dir/venv/bin/chutney"
data="$dir/data"

if [ "$what" = stop ]; then
    if [ -x "$chutney" ] && [ -d "$data/nodes" ]; then
        timeout 60 "$chutney" --data-dir "$data" stop > "$dir/stop.log" 2>&1
        echo "tor-net: stopped ($?)" >&2
    fi
    exit 0
fi

tor=$(command -v tor) || { echo "tor-net: no tor in PATH" >&2; exit 69; }
gencert=$(command -v tor-gencert) || { echo "tor-net: no tor-gencert in PATH" >&2; exit 69; }

if [ ! -x "$chutney" ]; then
    # Three tries, as the gate's downloads have.
    for try in 1 2 3; do
        rm -rf "$dir/chutney"
        if timeout 300 git clone -q "$CHUTNEY_URL" "$dir/chutney" > "$dir/clone.log" 2>&1; then
            break
        fi
        echo "tor-net: the clone failed (try $try)" >&2
        [ "$try" = 3 ] && exit 69
        sleep 10
    done
    if ! git -C "$dir/chutney" -c advice.detachedHead=false checkout -q "$CHUTNEY_COMMIT"; then
        echo "tor-net: chutney has no commit $CHUTNEY_COMMIT" >&2
        exit 69
    fi
    python3 -m venv "$dir/venv" || exit 69
    if ! timeout 600 "$dir/venv/bin/pip" install -q "$dir/chutney" > "$dir/pip.log" 2>&1; then
        echo "tor-net: chutney's packages did not install:" >&2
        tail -5 "$dir/pip.log" >&2
        exit 69
    fi
fi

# Build MODULE@VERSION into $bin, static: three tries, as the clone has,
# then one with the linker's check of go:linkname off, which Go 1.23 added
# and which a dependency of 2022 can fail.
go_install() {
    for try in 1 2 3 4; do
        flags=
        [ "$try" = 4 ] && flags=-ldflags=-checklinkname=0
        # $flags is one word or none.
        # shellcheck disable=SC2086
        if GOBIN="$bin" CGO_ENABLED=0 timeout 600 "$go" install $flags "$1" > "$dir/go.log" 2>&1; then
            return 0
        fi
        echo "tor-net: go install $1 failed (try $try)" >&2
        [ "$try" -lt 3 ] && sleep 10
    done
    tail -5 "$dir/go.log" >&2
    return 1
}

net="--net basic"
if [ "$what" = start-bridges ]; then
    go=$(command -v go) || { echo "tor-net: no go in PATH" >&2; exit 69; }
    bin="$dir/bin"
    mkdir -p "$bin" || exit 73
    go_install "$MEEK_SERVER" || exit 69
    go_install "$WEBTUNNEL_SERVER" || exit 69
    # The WebTunnel server's package is main/server, which go names server.
    mv -f "$bin/server" "$bin/webtunnel-server" || exit 70
    # WebTunnel's path is the bridge's secret: a new one for each network.
    tunnel_path=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
    # The lines that the bridge's tor ends its torrc with: the extended OR
    # port that a transport's server hands each client to, and the two
    # servers, each on its port of ADDRESS. A WebTunnel server needs its
    # URL, which its line announces.
    torrc="$dir/bridge.torrc"
    cat > "$torrc" <<EOF
ExtORPort auto
ServerTransportPlugin meek exec $bin/meek-server --disable-tls --log $dir/meek-server.log
ServerTransportListenAddr meek $address:$MEEK_PORT
ServerTransportPlugin webtunnel exec $bin/webtunnel-server
ServerTransportListenAddr webtunnel $address:$WEBTUNNEL_PORT
ServerTransportOptions webtunnel url=http://$address:$WEBTUNNEL_PORT/$tunnel_path
EOF
    # chutney's network script, which it runs with Node and ConfigureNodes
    # given (--net-from-script-path); the nodes as its bridges-min has them,
    # with the bridge's own lines (extra_raw_torrc) and no sandbox, which
    # forbids tor to start a transport's server.
    script="$dir/bridges.net"
    cat > "$script" <<EOF
Authority = Node(tag="a", authority=1, relay=1)
BridgeAuthority = Node(tag="ba", authority=1, bridgeauthority=1, relay=1)
ExitRelay = Node(tag="r", relay=1, exit=1)
with open("$torrc") as transports:
    TRANSPORTS = transports.read()
Bridge = Node(tag="br", bridge=1, relay=1, sandbox=0, launch_phase=2, extra_raw_torrc=TRANSPORTS)
ConfigureNodes(Authority.getN(4) + BridgeAuthority.getN(1) + ExitRelay.getN(4) + Bridge.getN(1))
EOF
    net="--net-from-script-path $script"
fi

rm -rf "$data"
mkdir -p "$data"
# $net is a flag and its value, split on purpose.
# shellcheck disable=SC2086
if ! timeout 120 "$chutney" --data-dir "$data" init $net --tor "$tor" --tor-gencert "$gencert" \
    --listen-address "$address" --disable-ipv6 true > "$dir/init.log" 2>&1; then
    echo "tor-net: chutney init failed:" >&2
    tail -5 "$dir/init.log" >&2
    exit 70
fi
# The authorities vote, then each relay publishes: a few minutes at most.
if ! timeout 600 "$chutney" --data-dir "$data" bootstrap > "$dir/bootstrap.log" 2>&1; then
    echo "tor-net: the network did not bootstrap:" >&2
    tail -20 "$dir/bootstrap.log" >&2
    timeout 60 "$chutney" --data-dir "$data" stop > /dev/null 2>&1
    exit 70
fi
toml="$data/nodes/arti.toml"
if [ ! -f "$toml" ]; then
    echo "tor-net: chutney wrote no $toml" >&2
    exit 70
fi
if [ "$what" = start ]; then
    echo "$toml"
    exit 0
fi

# The bridge's fingerprint, from its node's file (NICKNAME FINGERPRINT).
fingerprint=$(cat "$data"/nodes/*br/fingerprint 2>/dev/null | awk 'NR == 1 {print $2}')
case $fingerprint in
    "" | *[!0-9A-F]*) fingerprint= ;;
esac
if [ "${#fingerprint}" -ne 40 ]; then
    echo "tor-net: no fingerprint of the bridge under $data/nodes" >&2
    timeout 60 "$chutney" --data-dir "$data" stop > /dev/null 2>&1
    exit 70
fi
# tor says when a transport's server took its port; a server that did not
# fails the tests later, so its absence is said here, and the tests go on.
for name in meek webtunnel; do
    if ! grep -qs "Registered server transport '$name'" "$data"/nodes/*br/*.log; then
        echo "tor-net: the bridge's tor logged no server transport $name" >&2
    fi
done
# The addresses of the lines are dummies, as real bridges' are: a
# transport's server is its url=.
lines="$data/nodes/bridges"
{
    echo "meek_lite 192.0.2.1:1 $fingerprint url=http://$address:$MEEK_PORT/"
    echo "webtunnel [2001:db8::1]:443 $fingerprint url=http://$address:$WEBTUNNEL_PORT/$tunnel_path"
} > "$lines"
echo "$lines"
