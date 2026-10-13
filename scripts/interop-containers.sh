# podssh containers (T-190) against OpenSSH on port 2201 and Dropbear on
# port 2203: stand-ins of docker and kubectl on the far PATH print the lists
# of the unit tests (crates/podssh-cli/tests/fixtures/containers/) and log
# each exec; the list, the command that a line shows, and --exec reach
# them. The planted defect, no check of the names, fails containers.bad_name.
# No real runtime runs here: a rootless podman inside the gate's container
# stopped the distribution that runs the build image (2026-10-13), so a
# real runtime is measured on a host that has one.
# Sourced by scripts/interop-each.sh; uses ok, bad, expect_rc, unmet, p,
# $BIN, $HERE, $W, $K, $T and $KH.

echo
echo "== podssh containers (T-190): stand-ins of docker and kubectl, then podman"
CW="$W/containers"
mkdir -p "$CW"
cp "$HERE"/../crates/podssh-cli/tests/fixtures/containers/*.txt "$CW/"
chmod 644 "$CW"/*.txt
: >"$CW/exec.log"
chmod 666 "$CW/exec.log"
# c [podssh containers arguments...]: podssh containers as p() runs ssh.
c() {
    # shellcheck disable=SC2086
    timeout 120 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" containers --direct -o UserKnownHostsFile="$KH" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K "$@" </dev/null
}
# stand_in DIR TOOL LIST: a stand-in of TOOL in DIR. Its list (docker ps,
# kubectl get) is LIST; with $CW/deny, docker's refusal of its socket; with
# $CW/bad, a docker list that holds a;b. Its exec says what it got, and logs it.
stand_in() {
    cat >"$1/$2" <<EOF
#!/bin/sh
case "\$1" in
ps|get)
    [ "$2" = docker ] && [ -e "$CW/deny" ] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
    if [ "$2" = docker ] && [ -e "$CW/bad" ]; then cat "$CW/docker-bad.txt"; else cat "$3"; fi ;;
exec)
    echo "$2 \$*" >>"$CW/exec.log"
    echo "entered: $2 \$*" ;;
*)
    echo "$2: \$1: not in the stand-in" >&2
    exit 2 ;;
esac
EOF
    chmod 755 "$1/$2"
}
# The first directory of the PATH of a command on each server.
: >"$CW/dirs"
for port in 2201 2203; do
    # shellcheck disable=SC2016,SC2086
    d=$(p "$port" $K -o BatchMode=yes "$T" 'printf %s "${PATH%%:*}"' </dev/null 2>/dev/null)
    case $d in /*) ;; *) d=/usr/bin ;; esac
    mkdir -p "$d"
    stand_in "$d" docker "$CW/docker-ps.txt"
    stand_in "$d" kubectl "$CW/kubectl-pods.txt"
    echo "$d" >>"$CW/dirs"
done

c "$T:2201" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(wc -l <"$CW/out")" -eq 5 ] \
    && grep -q '^docker  *web  *podssh ssh -t .* -- docker exec -it web sh$' "$CW/out" \
    && grep -q '^kubectl  *pod/worker-0  *podssh ssh -t .* -- kubectl exec -it pod/worker-0 -- sh$' "$CW/out" \
    && ok containers.list "OpenSSH: a line for each container of docker and kubectl, with the command that enters it" \
    || bad containers.list "exit $rc" "$CW/err"
# The command of web's line, as a shell reads it, run as it is: with no
# terminal there is no pty, and the stand-in says what it got.
line=$(sed -n 's/^docker  *web  *podssh //p' "$CW/out")
eval "set -- $line"
timeout 120 env -u SSH_AUTH_SOCK HOME="$W" "$BIN" "$@" </dev/null >"$CW/out2" 2>"$CW/err2"
rc=$?
[ "$rc" = 0 ] && grep -qx 'entered: docker exec -it web sh' "$CW/out2" \
    && ok containers.shown "the command of a line, run as it is, reaches docker exec of that container" \
    || bad containers.shown "exit $rc: $line" "$CW/err2"
c "$T:2203" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && [ "$(wc -l <"$CW/out")" -eq 5 ] && grep -q '^kubectl  *pod/api-' "$CW/out" \
    && ok containers.dropbear "Dropbear: the same list" \
    || bad containers.dropbear "exit $rc" "$CW/err"
c --exec web "$T:2201" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && grep -qx 'entered: docker exec -i web sh' "$CW/out" && grep -qx 'docker exec -i web sh' "$CW/exec.log" \
    && ok containers.exec "--exec web with no terminal: docker exec -i web sh, on the connection of the list" \
    || bad containers.exec "exit $rc" "$CW/err"
c -tt --exec worker-0 --shell /bin/bash "$T:2201" >"$CW/out" 2>"$CW/err"
rc=$?
[ "$rc" = 0 ] && grep -q 'entered: kubectl exec -it pod/worker-0 -- /bin/bash' "$CW/out" \
    && ok containers.exec_tty "-tt --exec worker-0: a pty, and kubectl exec -it pod/worker-0 -- /bin/bash" \
    || bad containers.exec_tty "exit $rc" "$CW/err"
touch "$CW/deny"
c "$T:2201" >"$CW/out" 2>"$CW/err"
rc=$?
rm -f "$CW/deny"
[ "$rc" = 69 ] && grep -q '^podssh: docker: permission denied' "$CW/err" && ! grep -q '^docker' "$CW/out" \
    && [ "$(wc -l <"$CW/out")" -eq 2 ] \
    && ok containers.denied "a docker that is refused its socket: its line, the lines of kubectl, exit 69" \
    || bad containers.denied "exit $rc" "$CW/err"
touch "$CW/bad"
c "$T:2201" >"$CW/out" 2>"$CW/err"
rc=$?
rm -f "$CW/bad"
[ "$rc" = 65 ] && ! grep -q 'a;b' "$CW/out" && grep -q 'docker lists "a;b"' "$CW/err" \
    && ok containers.bad_name "a listed name that a shell would read is left out, and named: exit 65" \
    || bad containers.bad_name "exit $rc" "$CW/out"
c --tool podman "$T:2201" >"$CW/out" 2>"$CW/err"
expect_rc containers.none "--tool podman on a host with no podman" 69 $? "$CW/err"
while read -r d; do rm -f "$d/docker" "$d/kubectl"; done <"$CW/dirs"

