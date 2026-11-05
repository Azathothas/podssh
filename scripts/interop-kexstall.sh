# A server that stalls after the key exchange (T-236): the stand-in passes
# OpenSSH's bytes up to its NEWKEYS, then drops them. On --direct nothing
# else ends the wait: each answer during the login has the ConnectTimeout
# limit. `timeout 90` ends a podssh that has none. Twice (T-675): with no
# cache, the first request to log in is `none`; with the key that this host
# took kept (T-664), it is that key's signature, with a name of its own.
# Sourced by scripts/interop-faults.sh; uses its ok, bad, port, $FK, $W, $T,
# $K, $KH, $HERE and $BIN.

python3 "$HERE/fake-stall.py" --target 127.0.0.1:2201 --port-file "$FK/kexstall.port" \
    >"$FK/kexstall.log" 2>&1 &
echo $! >"$FK/kexstall.pid"
tries=0
while [ ! -s "$FK/kexstall.port" ] && [ "$tries" -lt 30 ]; do sleep 1; tries=$((tries + 1)); done

# kexstall CACHE PORT: podssh ssh --direct to PORT with the cache directory
# CACHE (none: no cache); sets rc and took.
kexstall() {
    start=$(date +%s)
    # shellcheck disable=SC2086
    timeout 90 env -u SSH_AUTH_SOCK HOME="$W" PODSSH_CACHE_DIR="$1" "$BIN" ssh --direct -p "$2" \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new -o IdentityAgent=none \
        -o IdentitiesOnly=yes $K -o BatchMode=yes -o ConnectTimeout=10 "$T" true >"$FK/out" 2>"$FK/err" </dev/null
    rc=$?
    took=$(( $(date +%s) - start ))
}

kexstall none "$(port kexstall)"
[ "$rc" = 255 ] && [ "$took" -lt 60 ] && grep -q "did not answer the first request to log in within 10 s" "$FK/err" \
    && ok kexstall.first \
        "a server that stalls after the key exchange: exit 255 after ${took}s, and the wait is named" \
    || bad kexstall.first "a server that stalls after the key exchange: exit $rc after ${took}s" "$FK/err"

# A login to OpenSSH itself keeps the key that it took; the stand-in shows
# the same host key, so the next login signs that key in its first request.
mkdir -p "$FK/kexcache"
kexstall "$FK/kexcache" 2201
kept=$rc
kexstall "$FK/kexcache" "$(port kexstall)"
[ "$kept" = 0 ] && [ "$rc" = 255 ] && [ "$took" -lt 60 ] \
    && grep -q "did not answer the signed publickey request within 10 s" "$FK/err" \
    && ok kexstall.signed \
        "the key that the host took signed at once, to a server that stalls: exit 255 after ${took}s, and the wait is named" \
    || bad kexstall.signed \
        "the key that the host took signed at once: the login that keeps it exit $kept; the stall exit $rc after ${took}s" \
        "$FK/err"
