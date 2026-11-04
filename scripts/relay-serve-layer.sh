# The live run of the relay role's forward road in the resumable layer
# (T-173), which scripts/relay-serve-live.sh sources with `layer`: its
# $PODSSH, $FK, $HERE and $PORT, the role at relay-a.test:$PORT with the CA
# of $FK/ca.pem, and the runner's sshd at PODSSH_LAYER_SSHD (127.0.0.1:PORT),
# for this user with the key of PODSSH_LAYER_KEY. Each client's link goes
# through scripts/fake-proxy.py as its HTTPS_PROXY, which ends each open
# tunnel with RST every $CUT_EVERY seconds; $MIB MiB go each way through the
# server's cat, a MiB each second, so that each session meets several cuts.
# OpenSSH's ssh with podssh proxy as its ProxyCommand, then podssh ssh: each
# must end 0 with each byte back in order and say its resumes, and the role
# must say that it resumed. No token or key is printed.

SSHD=${PODSSH_LAYER_SSHD:?PODSSH_LAYER_SSHD names the runner sshd, 127.0.0.1:PORT}
KEY=${PODSSH_LAYER_KEY:?PODSSH_LAYER_KEY names the key that the sshd takes}
SSHD_PORT=${SSHD##*:}
LOGIN=$(id -un)
# The MiB of each way, one each second, and the seconds between two cuts.
MIB=48
CUT_EVERY=8

python3 "$HERE/fake-proxy.py" --port-file "$FK/proxy-port" --log "$FK/proxy.log" \
    --map "relay-a.test=127.0.0.1:$PORT" --cut-every "$CUT_EVERY" &
PROXY=$!
i=0
while [ ! -s "$FK/proxy-port" ]; do
    i=$((i + 1))
    [ "$i" -le 100 ] || { echo "relay-serve-layer: the stand-in proxy did not start" >&2; exit 1; }
    sleep 0.1
done
PROXY_PORT=$(cat "$FK/proxy-port")
head -c $((MIB * 1048576)) /dev/urandom >"$FK/data"
mkdir -p "$FK/home/cache"

# The data, a MiB each second.
slowly() {
    n=0
    while [ "$n" -lt "$MIB" ]; do
        dd if="$FK/data" bs=1048576 skip="$n" count=1 2>/dev/null
        sleep 1
        n=$((n + 1))
    done
}

# One session: $1 its name, the rest its command, whose exit code is read
# from itself, the last command of its pipe.
session() {
    name=$1
    shift
    rc=0
    slowly | timeout 300 env HOME="$FK/home" XDG_CACHE_HOME="$FK/home/cache" PODSSH_SSH_CONFIG=none \
        HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT" PODSSH_RELAY_LAYER=yes SSL_CERT_FILE="$FK/ca.pem" \
        "$@" >"$FK/$name.back" 2>"$FK/$name.err" || rc=$?
    resumes=$(grep -c 'the session resumed after' "$FK/$name.err" || true)
    if [ "$rc" != 0 ] || ! cmp -s "$FK/data" "$FK/$name.back" || [ "$resumes" -lt 2 ]; then
        echo "relay-serve-layer: $name: exit $rc, $(wc -c <"$FK/$name.back") of $((MIB * 1048576)) bytes back," \
            "$resumes resumes" >&2
        sed 's/^/  /' "$FK/$name.err" >&2
        echo "relay-serve-layer: the stand-in proxy: $(tr '\n' ' ' <"$FK/proxy.log")" >&2
        echo "relay-serve-layer: the role: $(tail -n 40 "$FK/events" | tr '\n' ' ')" >&2
        exit 1
    fi
    echo "relay-serve-layer: ok   $name: $MIB MiB each way, back in order, through $resumes resumes"
}

session openssh ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$KEY" \
    -o "ProxyCommand=$PODSSH proxy --relay-host relay-a.test:$PORT %h %p" -p "$SSHD_PORT" "$LOGIN@127.0.0.1" cat
session podssh "$PODSSH" ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$FK/known_hosts" --relay-host "relay-a.test:$PORT" -p "$SSHD_PORT" \
    "$LOGIN@127.0.0.1" cat
resumed=$(grep -c 'layer resumed' "$FK/events" || true)
cuts=$(grep -c '^cut ' "$FK/proxy.log" || true)
[ "$resumed" -ge 4 ] || { echo "relay-serve-layer: the role resumed $resumed sessions' links, 4 at least" >&2; exit 1; }
echo "relay-serve-layer: the role resumed $resumed links, and the stand-in proxy cut the open tunnels $cuts times"
echo "relay-serve-live: ok"
