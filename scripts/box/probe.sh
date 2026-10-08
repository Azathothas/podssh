#!/bin/sh
# Inside the test box: measure the properties that define the target sandbox
# and compare each with the verdict the operator's sandprobe report recorded
# there (sandprobe 1.0.0, 2026-10-04; docs/target-environment.md). Prints
# `match` or `DIFFERS` per property and exits 1 when a required one differs,
# so podssh is never measured in a box that is not the cage it stands for.
#
# TCP is tested with curl, never busybox nc: Alpine's nc binds its socket
# before it connects, and the box refuses bind, so nc fails every TCP test
# for a reason that is not the one under test (measured: the first version
# reported the proxy silent while it had received nothing). nc stays for UDP
# and for the listener, where the refusal is the thing measured.

set -u
failed=0
match() { printf 'match    %-22s %s\n' "$1" "$2"; }
differs() { printf 'DIFFERS  %-22s box: %s; sandbox: %s\n' "$1" "$2" "$3"; failed=1; }
note() { printf 'note     %-22s %s\n' "$1" "$2"; }

# Identity: uid 0, with no name in the user database.
uid=$(id -u)
if whoami >/dev/null 2>&1; then
    differs identity "uid $uid is named $(whoami)" "uid 0 with no name (whoami: cannot find name for user ID 0)"
elif [ "$uid" = 0 ]; then
    match identity "uid 0 with no name in the user database"
else
    differs identity "uid $uid" "uid 0"
fi

# Capabilities, no_new_privs and seccomp, from the kernel's own record.
eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)
nnp=$(awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status)
sec=$(awk '/^Seccomp:/ { print $2 }' /proc/self/status)
if [ "$eff" = 0000000000000000 ] && [ "$nnp" = 1 ] && [ "$sec" = 2 ]; then
    match privileges "no capabilities, NoNewPrivs=1, a seccomp filter"
else
    differs privileges "CapEff=$eff NoNewPrivs=$nnp Seccomp=$sec" "CapEff=0000000000000000 NoNewPrivs=1 Seccomp=2"
fi

# No pty device.
if [ -e /dev/ptmx ]; then
    differs /dev/ptmx "present" "absent"
else
    match /dev/ptmx "absent"
fi

# /dev/tty opens and never answers, and the process has no controlling
# terminal (sandprobe: "opened but no byte available within 10s; it blocked
# rather than refused"). A prompt that trusted the open waited for ever
# there (GitHub #15). busybox timeout exits 143, GNU timeout 124.
ctty=$(awk '{ print $7 }' /proc/self/stat)
tty=$(timeout 5 dd if=/dev/tty of=/dev/null bs=1 count=1 2>&1)
rc=$?
case $rc in
    124 | 143)
        if [ "$ctty" = 0 ]; then
            match /dev/tty "opens, no byte within 5 s, no controlling terminal"
        else
            differs /dev/tty "the controlling terminal (tty_nr $ctty)" "no controlling terminal"
        fi
        ;;
    *) differs /dev/tty "$(printf '%s' "${tty:-exit $rc}" | head -n 1)" "opens, and no byte within 10 s" ;;
esac

# No DNS: the resolver is listed but nothing answers.
if timeout 10 nslookup github.com >/dev/null 2>&1; then
    differs DNS "github.com resolves" "unresolved (Temporary failure in name resolution)"
else
    match DNS "github.com does not resolve"
fi

# No direct egress, even to an IP literal on 443.
direct=$(timeout 15 curl -sS --noproxy '*' --connect-timeout 10 -o /dev/null http://1.1.1.1:443/ 2>&1)
case $? in
    7 | 28) match "direct TCP" "1.1.1.1:443 does not connect ($(echo "$direct" | tail -n 1 | cut -c1-70))" ;;
    *) differs "direct TCP" "1.1.1.1:443 connected or answered" "dropped (no answer within 10 s)" ;;
esac

# UDP refused at the socket: EPERM.
udp=$(timeout 5 nc -u -w 1 1.1.1.1 53 </dev/null 2>&1)
case $udp in
    *"not permitted"*) match UDP "socket refused: Operation not permitted" ;;
    *) differs UDP "${udp:-no error}" "Operation not permitted (EPERM)" ;;
esac

# No listener: bind refused. (The report has no bind probe; the operator
# reports that binding is not allowed there.)
bind=$(timeout 3 nc -l -p 18080 </dev/null 2>&1)
case $bind in
    *"ermission denied"*) match bind "refused: Permission denied" ;;
    *) differs bind "${bind:-no error within 3 s}" "refused" ;;
esac

# Loopback: the sandbox refuses connect() with EACCES; here nothing listens.
note loopback "the sandbox refuses connect() to loopback with EACCES; this box only has no listener there"

# The proxy and its policy, asked directly.
proxy=${HTTPS_PROXY:-${https_proxy:-}}
if [ -z "$proxy" ]; then
    differs proxy "HTTPS_PROXY is not set" "HTTPS_PROXY names one link-local CONNECT proxy"
else
    hostport=${proxy#*://}
    hostport=${hostport%%/*}
    phost=${hostport%:*}
    pport=${hostport##*:}
    match proxy "HTTPS_PROXY names $hostport"
    ask() { # ask TARGET EXPECTED-STATUS-LINE: the proxy's answer to CONNECT TARGET
        got=$(timeout 15 curl -sv -p -x "http://$phost:$pport" --noproxy '' --connect-timeout 8 -m 12 \
            -o /dev/null "http://$1/" 2>&1 | grep -m 1 '^< HTTP/' | tr -d '\r' | sed 's/^< //')
        if [ "$got" = "$2" ]; then match "CONNECT $1" "$got"; else differs "CONNECT $1" "${got:-no answer}" "$2"; fi
    }
    ask example.com:443 "HTTP/1.1 200 Connection Established"
    ask example.com:80 "HTTP/1.1 200 Connection Established"
    ask example.com:8443 "HTTP/1.1 200 Connection Established"
    ask example.com:22 "HTTP/1.1 403 not on the egress allowlist"
    ask example.com:25 "HTTP/1.1 403 not on the egress allowlist"
    ask 127.0.0.1:22 "HTTP/1.1 403 not on the egress allowlist"
    ask 169.254.169.254:80 "HTTP/1.1 403 not a public host"
    ask 10.255.255.1:80 "HTTP/1.1 403 not a public host"
fi

if [ "$failed" = 0 ]; then
    echo "the box matches the sandbox on every required property"
else
    echo "the box does not match the sandbox: podssh is not measured in it"
fi
exit "$failed"
