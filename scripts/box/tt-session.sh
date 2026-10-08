#!/bin/sh
# An interactive session over -tt from the box (T-004): vi, less, top, Ctrl-C
# and the exit status, written to podssh through a pipe with pauses, as an
# agent drives it in the sandbox: no /dev/ptmx, no controlling terminal, a
# /dev/tty that never answers. The server is OpenSSH next to the box, named
# tt.box, which the box's proxy lets through (scripts/test_in_box.sh,
# BOX_RUN=tt); podssh reaches it with --direct through HTTPS_PROXY.
#
#   sh scripts/box/tt-session.sh PODSSH
#
# Prints one line per marker and exits 1 if one is missing.

set -u
BIN=${1:?usage: tt-session.sh PODSSH}
W=/state/home/tt
mkdir -p "$W"
install -m 600 /tt/key "$W/key" || { echo "tt: FAIL  no key at /tt/key"; exit 1; }
failed=0
mark() { # mark NAME yes|no DETAIL
    if [ "$2" = yes ]; then echo "tt: ok    $1: $3"; else echo "tt: FAIL  $1: $3"; failed=1; fi
}

echo "== an interactive session over -tt, through a pipe"
start=$(date +%s)
(
    # A pause after ESC: vi reads ESC and the next byte at once as the start of
    # an escape sequence, and stays in insert mode.
    sleep 4; printf 'vi /tmp/podssh-tt\r'; sleep 2; printf 'ihello\033'; sleep 1; printf ':wq\r'; sleep 2
    printf 'less /etc/services\r'; sleep 2; printf 'q'; sleep 1; printf 'top\r'; sleep 3; printf 'q'
    sleep 1; printf 'cat /tmp/podssh-tt; sleep 30\r'; sleep 3; printf '\003'; sleep 1; printf 'exit 7\r'
) | timeout 120 "$BIN" ssh --direct -tt -p 22 -i "$W/key" -o StrictHostKeyChecking=accept-new \
    -o BatchMode=yes -o UserKnownHostsFile="$W/known_hosts" -o LogLevel=DEBUG3 -E "$W/log" tt@tt.box \
    >"$W/out" 2>"$W/err"
rc=$?
took=$(( $(date +%s) - start ))
tr -d '\r' <"$W/out" >"$W/text"

[ "$rc" = 7 ] && mark "exit status" yes "7, the status of the remote shell" \
    || mark "exit status" no "wanted 7, got $rc"
saved=$(grep -cx hello "$W/text")
[ "$saved" -ge 1 ] && mark vi yes "the file holds hello (cat printed it)" \
    || mark vi no "cat printed no line hello"
grep -q 'tcpmux' "$W/text" && mark less yes "/etc/services was shown (its first entry, tcpmux)" \
    || mark less no "no line of /etc/services"
grep -qi 'load average' "$W/text" && mark top yes "its header was drawn" \
    || mark top no "no header of top"
# The script's own pauses take 20 s; a sleep 30 that Ctrl-C did not stop
# would end the session after more than 40 s.
[ "$took" -lt 35 ] && mark "Ctrl-C" yes "sleep 30 stopped; the session took ${took}s" \
    || mark "Ctrl-C" no "the session took ${took}s"
if [ "$failed" != 0 ]; then
    echo "tt: stderr of podssh:"
    sed 's/^/tt:   | /' "$W/err" | head -20
    echo "tt: the debug log of podssh, last 40 lines:"
    tail -n 40 "$W/log" | sed 's/^/tt:   | /'
    echo "tt: the session's output ($(wc -c <"$W/out") bytes), control bytes as escapes:"
    od -c "$W/out" | head -n 90 | sed 's/^/tt:   | /'
fi
exit "$failed"
