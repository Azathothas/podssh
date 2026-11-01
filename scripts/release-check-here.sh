# The checks of the release check (T-251) that run on this host, in a fresh
# container, or in the build image; sourced by scripts/release-check.sh. The
# network: the live relay, GitHub's SSH endpoint, railway.new, n0's iroh
# relays and the IRC networks of Q39 (AGENTS.md, section 4).

# c_short LABEL: the short form of each release job, here.
c_short() {
    if [ "$MODE" = tag ]; then
        timed 300 "$LOGS/short.$1.log" $PENV PODSSH_BUILD_COMMIT="$COMMIT" sh "$HERE/release-short.sh" "$W/bin/$1" --net
    else
        timed 300 "$LOGS/short.$1.log" $PENV sh "$HERE/release-short.sh" "$W/bin/$1" --net
    fi
    by_rc short "$1" 0 "$LOGS/short.$1.log" "$(grep -c '^ok' "$LOGS/short.$1.log") ok lines"
}

# c_sandbox LABEL: the record of a sandbox (T-006), here.
c_sandbox() {
    timed 900 "$LOGS/sandbox.$1.log" $PENV sh "$HERE/sandbox-check.sh" "$W/bin/$1"
    by_rc sandbox "$1" 0 "$LOGS/sandbox.$1.log" "$(tail -n 1 "$LOGS/sandbox.$1.log")"
}

# c_readme LABEL: the commands of README's first steps that a check can run
# here; its download and its proofs are the sources of a tag.
c_readme() {
    _d=$W/readme.$1 _b=$W/bin/$1 _bad= _secs=0
    mkdir -p "$_d"
    timed 60 "$_d/man.txt" $PENV "$_b" man ssh
    _secs=$((_secs + SECS))
    _lines=$(($(wc -l <"$_d/man.txt")))
    [ "$RC" = 0 ] && [ "$_lines" -gt 20 ] || _bad="$_bad man ssh ($(why), $_lines lines);"
    timed 60 "$_d/keygen.log" $PENV "$_b" keygen -t ed25519 -N '' -f "$_d/id_ed25519"
    _secs=$((_secs + SECS))
    [ "$RC" = 0 ] && [ -s "$_d/id_ed25519.pub" ] || _bad="$_bad keygen ($(why));"
    timed 60 "$_d/fingerprint.txt" $PENV "$_b" keygen -l -f "$_d/id_ed25519.pub"
    _secs=$((_secs + SECS))
    [ "$RC" = 0 ] && grep -q 'SHA256:' "$_d/fingerprint.txt" || _bad="$_bad keygen -l ($(why));"
    timed 60 "$_d/status.json" $PENV "$_b" status
    _secs=$((_secs + SECS))
    [ "$RC" = 0 ] && [ "$(head -c 1 "$_d/status.json")" = "{" ] || _bad="$_bad status ($(why));"
    cat "$_d/keygen.log" "$_d/fingerprint.txt" >"$LOGS/readme.$1.log" 2>/dev/null
    if [ -z "$_bad" ]; then
        row PASS readme "$1" "$_secs" "man ssh $_lines lines; $(cut -d' ' -f1,2 "$_d/fingerprint.txt"); status JSON"
    else
        row FAIL readme "$1" "$_secs" "$_bad"
    fi
}

# c_pipe: 5,000,000 bytes through exec:cat, and through a Unix socket whose
# server is Python's, not podssh's (AGENTS.md, rule 2 of section 6).
c_pipe() {
    _d=$W/pipe _b=$W/bin/$PRIMARY _bad=
    mkdir -p "$_d"
    head -c 5000000 /dev/urandom >"$_d/in"
    _want=$(digest "$_d/in")
    timed_io 120 "$_d/in" "$_d/out.exec" "$LOGS/pipe.exec.log" $PENV "$_b" pipe stdio exec:cat
    _s1=$SECS
    [ "$RC" = 0 ] && [ "$(digest "$_d/out.exec")" = "$_want" ] || _bad="$_bad exec:cat ($(why), the digest $(digest "$_d/out.exec"));"
    cat >"$_d/echo.py" <<'EOF'
import os, socket, sys
path = sys.argv[1]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
server.settimeout(60)
client, _ = server.accept()
client.settimeout(60)
while True:
    data = client.recv(65536)
    if not data:
        break
    client.sendall(data)
client.shutdown(socket.SHUT_WR)
client.close()
server.close()
os.unlink(path)
EOF
    timeout -k 5 120 python3 -I "$_d/echo.py" "$_d/echo.sock" >"$LOGS/pipe.server.log" 2>&1 &
    _srv=$!
    echo "$_srv" >>"$W/pids"
    _n=0
    while [ ! -S "$_d/echo.sock" ] && [ "$_n" -lt 50 ]; do sleep 0.2; _n=$((_n + 1)); done
    timed_io 120 "$_d/in" "$_d/out.unix" "$LOGS/pipe.unix.log" $PENV "$_b" pipe stdio "unix-connect:$_d/echo.sock"
    wait "$_srv"
    [ "$RC" = 0 ] && [ "$(digest "$_d/out.unix")" = "$_want" ] || _bad="$_bad unix-connect: ($(why), the digest $(digest "$_d/out.unix"));"
    if [ -z "$_bad" ]; then
        row PASS pipe "$PRIMARY" "$((_s1 + SECS))" "exec:cat and unix-connect: each gave 5,000,000 bytes back, sha256 equal"
    else
        row FAIL pipe "$PRIMARY" "$((_s1 + SECS))" "$_bad"
        show "$LOGS/pipe.exec.log"
        show "$LOGS/pipe.unix.log"
    fi
}

# c_railway: a pty and an exec through the relay to railway.new. Its words
# hold a claim URL, which no line may print (AGENTS.md, section 4), so its
# output stays in the scratch directory, is never shown, and goes with it.
c_railway() {
    _d=$W/railway _b=$W/bin/$PRIMARY _got= _secs=0 _refused= _missed=
    mkdir -p "$_d"
    timeout -k 5 60 $PENV "$_b" keygen -q -t ed25519 -N '' -C release-check -f "$_d/key" </dev/null >/dev/null 2>&1
    for _m in tt T; do
        timed 120 "$_d/$_m.log" $PENV "$_b" ssh "-$_m" -i "$_d/key" -o IdentitiesOnly=yes \
            -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$_d/known_hosts" -o BatchMode=yes \
            release-check@railway.new 'exit 3'
        _secs=$((_secs + SECS))
        _got="$_got -$_m: $(why);"
        [ "$RC" = 3 ] && continue
        _missed=1
        # Its limit for an anonymous visitor, in the words that it used.
        grep -qiE 'limit|temporarily (disabled|unavailable)|"status": *"(refused|error)"' "$_d/$_m.log" && _refused=1
    done
    if [ -n "$_refused" ]; then
        # Its own limit for an anonymous visitor, not podssh's (T-422): the
        # exit status through the relay is the rows reverse.two and
        # actions.node, against OpenSSH. Any other failure stays a FAIL.
        row SKIP railway "$PRIMARY" "$_secs" "railway.new refused this anonymous visitor, its limit (its words withheld):$_got an outside refusal (T-422); the exit status through the relay is reverse.two's and actions.node's"
    elif [ -n "$_missed" ]; then
        row FAIL railway "$PRIMARY" "$_secs" "wanted exit 3 each:$_got its output withheld"
    else
        row PASS railway "$PRIMARY" "$_secs" "exit 3 with a pty, and exit 3 with none"
    fi
}

# The engine of the containers: PODSSH_ENGINE, else Podman, else Docker.
engine() {
    case ${PODSSH_ENGINE:-} in
        podman | docker) echo "$PODSSH_ENGINE"; return ;;
    esac
    for _e in podman docker; do
        command -v "$_e" >/dev/null 2>&1 && { echo "$_e"; return; }
    done
    echo none
}

# c_containers: the static binary in a fresh container of the box's pinned
# Alpine, on this host's network and proxy, with nothing of this host's but
# the binary, the scripts and the proxy's CA.
c_containers() {
    _e=$(engine)
    if [ "$_e" = none ]; then
        for _id in container.short container.sandbox; do
            wanted "$_id" && row FAIL "$_id" "$PRIMARY" 0 "no podman or docker on PATH"
        done
        return
    fi
    _ref=$(tr -d '\r' <"$REPO/images/box/Dockerfile" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    _img=$(PULL_ENGINE=$_e timeout 1200 sh "$HERE/pull-image.sh" "$_ref" 2>"$LOGS/container.pull.log")
    _rc=$?
    if [ "$_rc" != 0 ] || [ -z "$_img" ]; then
        for _id in container.short container.sandbox; do
            wanted "$_id" && row FAIL "$_id" "$PRIMARY" 0 "the box's image did not pull into $_e (exit $_rc)"
        done
        return
    fi
    _env=
    for _v in HTTPS_PROXY https_proxy NO_PROXY no_proxy; do
        eval "_val=\${$_v:-}"
        [ -z "$_val" ] || _env="$_env -e $_v"
    done
    _ca=
    if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "$SSL_CERT_FILE" ]; then
        _ca="-v $SSL_CERT_FILE:/rc/ca.pem:ro -e SSL_CERT_FILE=/rc/ca.pem"
    fi
    _commit=
    [ "$MODE" != tag ] || _commit="-e PODSSH_BUILD_COMMIT=$COMMIT"
    # ID:SCRIPT:LIMIT:ARGUMENT, one for each container.
    for _c in short:release-short.sh:600:--net sandbox:sandbox-check.sh:900:; do
        _id=container.${_c%%:*}
        _rest=${_c#*:}
        _script=${_rest%%:*}
        _rest=${_rest#*:}
        _lim=${_rest%%:*}
        _arg=${_rest#*:}
        wanted "$_id" || continue
        # shellcheck disable=SC2086  # lists of flags, with no space in a value
        timed "$_lim" "$LOGS/$_id.log" "$_e" run --rm --network host $_env $_ca $_commit \
            -v "$W/bin/$PRIMARY:/rc/podssh:ro" -v "$HERE:/rc/scripts:ro" -v "$REPO/Cargo.toml:/rc/tree/Cargo.toml:ro" \
            -w /rc/tree "$_img" sh "/rc/scripts/$_script" /rc/podssh $_arg
        by_rc "$_id" "$PRIMARY" 0 "$LOGS/$_id.log" "$_e, $(tail -n 1 "$LOGS/$_id.log")"
    done
}

# c_irc_live: one short run on a public network through the relay (Q39),
# a throwaway nick and channel; the first network that takes it passes.
# Which networks take the relay's address is theirs to say (docs/irc.md).
c_irc_live() {
    _h=$(rand_hex 3) _tried= _secs=0
    # OFTC three times: its name gives one server of several each time, and
    # one of them ended TLS with no word where another took the run (T-422);
    # libera and undernet bar the relay's address (docs/irc.md).
    for _net in irc.oftc.net:6697 irc.oftc.net:6697 irc.oftc.net:6697 irc.libera.chat:6697 irc.undernet.org:6667; do
        _plain=
        case $_net in *:6667) _plain=--irc-plaintext ;; esac
        # shellcheck disable=SC2086  # one flag or none
        # A nick of 8 characters: undernet takes 12 at most.
        timed 120 "$LOGS/irc.${_net%%:*}.log" $PENV "$W/bin/$PRIMARY" chat --irc "$_net" $_plain --nick "rc$_h" \
            --send "the release check $_h" --timeout 90s "#podssh-rc-$_h"
        _secs=$((_secs + SECS))
        if [ "$RC" = 0 ]; then
            row PASS irc.live "$PRIMARY" "$_secs" "$_net took a message of #podssh-rc-$_h${_tried:+ (before it:$_tried)}"
            return
        fi
        _tried="$_tried $_net $(why);"
    done
    row FAIL irc.live "$PRIMARY" "$_secs" "no network took the run:$_tried"
}

# c_throughput: T-157's method at 100 MiB a run (Q38), with n0's relay; the
# cell through the relay's loop is a row of its own.
c_throughput() {
    timed 7200 "$LOGS/throughput.log" env CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" PODSSH_THROUGHPUT_MIB=100 \
        PODSSH_THROUGHPUT_IROH_RELAY=https://use1-1.relay.n0.iroh.link. \
        cargo test --locked -p podssh-cli --features iroh-test --test throughput_live -- --ignored --nocapture \
        throughput_on_each_road
    by_rc throughput build 0 "$LOGS/throughput.log" "the cells and their MiB/s are in its log"
    # The loop's cell must have figures: its name alone is in the log of a
    # cell that was skipped too.
    _loop=$(awk '/^cell: /{ inloop = /relay.s own loop/ } inloop && /^  (up: min|skipped:)/{ print; exit }' \
        "$LOGS/throughput.log")
    case $_loop in
        "  up: min"*) row PASS throughput.loop build 0 "the cell through the relay's loop:${_loop#  up:}" ;;
        "  skipped:"*) row FAIL throughput.loop build 0 "the cell through the relay's loop did not run:${_loop#  skipped:}" ;;
        *) row FAIL throughput.loop build 0 "no cell through the relay's loop in the run's log" ;;
    esac
}

checks_here() {
    for _l in $HERE_BINS; do
        [ -f "$W/bin/$_l" ] || continue
        wanted short && c_short "$_l"
        wanted sandbox && c_sandbox "$_l"
        wanted readme && c_readme "$_l"
    done
    wanted pipe && c_pipe
    wanted railway && c_railway
    { wanted container.short || wanted container.sandbox; } && c_containers
    if [ "$MODE" = tag ] && wanted update.check; then
        timed 300 "$LOGS/update.log" $PENV "$W/bin/$PRIMARY" update --check --version "$TAG"
        by_rc update.check "$PRIMARY" 0 "$LOGS/update.log" "$(tail -n 1 "$LOGS/update.log")"
    fi
    wanted irc.live && c_irc_live
    if wanted irc.image; then
        timed 3600 "$LOGS/irc.image.log" sh "$HERE/dev.sh" run -- 'sh /work/scripts/irc-in-image.sh'
        by_rc irc.image build 0 "$LOGS/irc.image.log" "ngircd: plain text and TLS"
    fi
    if wanted headscale; then
        timed 5400 "$LOGS/headscale.log" env CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" sh "$HERE/ts-headscale.sh"
        if [ "$RC" = 3 ]; then
            row PASS headscale "build (ts)" "$SECS" "each run here passed; the live relay's three are actions.headscale's (exit 3)"
        else
            by_rc headscale "build (ts)" 0 "$LOGS/headscale.log" "$(grep -c '^ok' "$LOGS/headscale.log") ok lines"
        fi
    fi
    wanted throughput && c_throughput
}

# checks_skipped: each SKIP of the catalog, with the reason that it names.
checks_skipped() {
    catalog | while IFS='|' read -r _id _modes _entry _where _limit _pass; do
        case $_pass in "SKIP: "*) ;; *) continue ;; esac
        case $_modes in both | "$MODE") ;; *) continue ;; esac
        wanted "$_id" && row SKIP "$_id" - 0 "${_pass#SKIP: }"
    done
}
