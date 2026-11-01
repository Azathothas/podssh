# Sourced by interop.sh: an interactive terminal, a local pty driven by
# scripts/interop-pty.py, its ok and FAIL lines counted with interop.sh's.
echo
echo "== an interactive terminal (a local pty, driven by scripts/interop-pty.py)"
env -u SSH_AUTH_SOCK HOME="$W" python3 "$HERE/interop-pty.py" "$BIN" "$KH" "$W/id_ed25519" >"$W/pty.log" 2>&1
rc=$?
cat "$W/pty.log"
pass=$((pass + $(grep -c '^ok ' "$W/pty.log")))
fail=$((fail + $(grep -c '^FAIL' "$W/pty.log")))
{ [ "$rc" -eq 0 ] || [ "$(grep -c '^FAIL' "$W/pty.log")" -gt 0 ]; } && ok ssh.pty.driver "the pty driver ran (exit $rc)" \
    || bad ssh.pty.driver "the pty driver exited $rc with no result line"
