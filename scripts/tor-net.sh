#!/bin/sh
# A private Tor network of C tor on this host, for the tests of the Tor
# road (T-353): chutney's network `basic` (four authorities, five exits,
# two clients), and arti-client's configuration of it, which the tests read
# from PODSSH_TEST_TOR_NETWORK. Its relays know no other network, so
# nothing of it reaches Tor's own.
#
#   sh scripts/tor-net.sh start DIR [ADDRESS]   # prints the path of arti.toml
#   sh scripts/tor-net.sh stop DIR
#
# The relays listen on ADDRESS, 127.0.0.1 by default. podssh sends no
# loopback address through a proxy, so a test of the proxy's road gives
# another address of this host.
#
# chutney comes from the Tor Project at a pinned commit, into DIR, with its
# Python packages in a virtual environment there. It needs tor and
# tor-gencert, git, and python3 with venv.
set -u

CHUTNEY_URL=https://gitlab.torproject.org/tpo/core/chutney.git
CHUTNEY_COMMIT=c6b2c5faa67a34354fd1bbb9d7d50c11f8aafb4d

what=${1:-}
dir=${2:-}
address=${3:-127.0.0.1}
if [ -z "$dir" ] || { [ "$what" != start ] && [ "$what" != stop ]; }; then
    echo "usage: tor-net.sh start DIR [ADDRESS] | stop DIR (got '$*')" >&2
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

rm -rf "$data"
mkdir -p "$data"
if ! timeout 120 "$chutney" --data-dir "$data" init --net basic --tor "$tor" --tor-gencert "$gencert" \
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
echo "$toml"
