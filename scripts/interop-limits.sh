# The memory of a session whose output nobody reads (T-201): the server
# writes 50 MB, and the reader takes nothing for 30 s. podssh's peak, VmHWM
# of /proc/PID/status, must stay under a ceiling of half of what the server
# writes, so a podssh that held the output would pass it. Two bounds keep it
# down: the SSH window (WINDOW in crates/podssh-ssh/src/run.rs) and russh's
# queue of a channel, 100 messages; measured on 2026-10-11, without either
# of them the peak was 62708 KiB, and with the window alone at 64 MiB 8948 KiB.
# Sourced by scripts/interop.sh once its servers run; uses ok, bad, $W,
# $BIN, $KH, $K and $T.

echo
echo "== the memory of a session whose output nobody reads"

LM="$W/limits"
mkdir -p "$LM"
LM_BYTES=50000000
# In KiB: half of LM_BYTES. podssh's own peak was about 7 MiB (2026-10-11).
LM_CEILING=24414

# lm_peak PID: the largest VmHWM, in KiB, that /proc showed while PID ran.
# It runs in a subshell, which cannot reap PID: an ended PID stays a zombie,
# which `kill -0` still finds, so the end is its state Z.
lm_peak() {
    _peak=0
    while [ -r "/proc/$1/status" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; do
        _now=$(sed -n 's/^VmHWM:[[:space:]]*\([0-9]*\) kB$/\1/p' "/proc/$1/status" 2>/dev/null)
        [ -n "$_now" ] && [ "$_now" -gt "$_peak" ] && _peak=$_now
        sleep 0.2
    done
    echo "$_peak"
}

# A reader that takes each byte: podssh's own process, as env execs it, so
# that $! is its PID.
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
    "$T" "head -c $LM_BYTES /dev/zero" >"$LM/fast.out" 2>"$LM/fast.err" </dev/null &
lm_pid=$!
fast_peak=$(lm_peak "$lm_pid")
wait "$lm_pid"
fast_rc=$?
fast_got=$(wc -c <"$LM/fast.out")
rm -f "$LM/fast.out"
[ "$fast_rc" = 0 ] && [ "$fast_got" = "$LM_BYTES" ] && [ "$fast_peak" -gt 0 ] && [ "$fast_peak" -le "$LM_CEILING" ] \
    && ok limits.fast_reader "a reader that takes each byte: $fast_got bytes, podssh's peak ${fast_peak} KiB" \
    || bad limits.fast_reader \
        "a fast reader: exit $fast_rc, $fast_got bytes, peak ${fast_peak} KiB of ${LM_CEILING} at most" "$LM/fast.err"

# The slow reader opens the pipe at once, so that podssh starts, and reads
# nothing for 30 s.
mkfifo "$LM/out"
(
    exec 3<"$LM/out"
    sleep 30
    wc -c <&3 >"$LM/slow.count"
) &
lm_reader=$!
# shellcheck disable=SC2086
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
    "$T" "head -c $LM_BYTES /dev/zero" >"$LM/out" 2>"$LM/slow.err" </dev/null &
lm_pid=$!
slow_peak=$(lm_peak "$lm_pid")
wait "$lm_pid"
slow_rc=$?
wait "$lm_reader"
slow_got=$(cat "$LM/slow.count" 2>/dev/null)
[ "$slow_rc" = 0 ] && [ "$slow_got" = "$LM_BYTES" ] && [ "$slow_peak" -gt 0 ] && [ "$slow_peak" -le "$LM_CEILING" ] \
    && ok limits.slow_reader \
        "a reader that takes nothing for 30 s: podssh's peak ${slow_peak} KiB, against ${fast_peak} with a fast one" \
    || bad limits.slow_reader \
        "a slow reader: exit $slow_rc, ${slow_got:-0} bytes, peak ${slow_peak} KiB of ${LM_CEILING} at most" \
        "$LM/slow.err"
