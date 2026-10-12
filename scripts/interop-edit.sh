# podssh edit against OpenSSH (T-149). Sourced by scripts/interop-cp.sh
# while its servers run (2201: OpenSSH with its sftp-server; 2207: OpenSSH
# with no Subsystem line, for the copy by exec). Uses ok, bad, expect_rc,
# sum, $W, $T, $K, $KH, $BIN, $CW and $RD. Each run gets a terminal from
# Python's pty module, as a person's would be, and an EDITOR that is a
# script; the planted defect, the check before the send skipped, must fail
# edit.far_changed.

echo
echo "== edit"
EW="$CW/edit"
mkdir -p "$EW"

# e EDITOR PORT [edit arguments...]: podssh edit in a new pty, with EDITOR
# and no VISUAL; what the terminal shows, stderr too, goes to $EW/out, and
# the exit code is podssh's.
e() {
    _editor=$1
    _port=$2
    shift 2
    # shellcheck disable=SC2086
    python3 -c 'import pty, sys; sys.exit(pty.spawn(sys.argv[1:]) >> 8)' \
        env -u SSH_AUTH_SOCK -u VISUAL HOME="$W" EDITOR="$_editor" PODSSH_CACHE_DIR="$EW/cache" \
        "$BIN" edit --direct -P "$_port" -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K "$@" </dev/null >"$EW/out" 2>&1
}
# kept: the path of the copy that podssh named as kept, from $EW/out.
kept() { sed -n 's/.*your copy stays at \(.*\)$/\1/p' "$EW/out" | tr -d '\r' | head -n 1; }
# far NAME: a far file of one line, the login's own.
far() {
    printf 'the far file\n' >"$RD/$1"
    chown podtest:podtest "$RD/$1"
}

# The editors: each is a script that gets the path of the copy as $1. The
# third changes the far file through podssh ssh first, as another person
# would while the editor is open.
# shellcheck disable=SC2016  # $1 is the script's own
printf '#!/bin/sh\necho "a line from the editor" >>"$1"\n' >"$EW/add-line"
# shellcheck disable=SC2016
printf '#!/bin/sh\necho "a line from the editor" >>"$1"\nexit 3\n' >"$EW/add-and-fail"
cat >"$EW/far-first" <<EOF
#!/bin/sh
env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o UserKnownHostsFile="$KH" \\
    -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes $K \\
    "$T" 'echo "a line from podssh ssh" >>cp/edit-far' </dev/null >/dev/null 2>&1
echo "a line from the editor" >>"\$1"
EOF
chmod 755 "$EW/add-line" "$EW/add-and-fail" "$EW/far-first"
printf 'the far file\na line from the editor\n' >"$EW/want"

# The line goes, the digests agree, and the far mode stays, on each road.
far edit-sftp
chmod 640 "$RD/edit-sftp"
e "$EW/add-line" 2201 "$T:cp/edit-sftp"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$EW/want")" = "$(sum "$RD/edit-sftp")" ] && [ "$(stat -c %a "$RD/edit-sftp")" = 640 ] \
    && ok edit.sftp.add_line "edit over SFTP: the editor's line went, the digests agree, the mode stays 640" \
    || bad edit.sftp.add_line "edit over SFTP: exit $rc" "$EW/out"
far edit-exec
chmod 640 "$RD/edit-exec"
e "$EW/add-line" 2207 "$T:cp/edit-exec"
rc=$?
[ "$rc" = 0 ] && [ "$(sum "$EW/want")" = "$(sum "$RD/edit-exec")" ] && [ "$(stat -c %a "$RD/edit-exec")" = 640 ] \
    && grep -q "by exec" "$EW/out" \
    && ok edit.exec.add_line "edit by exec: the editor's line went, the digests agree, the mode stays 640" \
    || bad edit.exec.add_line "edit by exec: exit $rc" "$EW/out"
[ -z "$(find "$EW/cache" -name 'edit-*' 2>/dev/null)" ] \
    && ok edit.no_copy_left "after each edit that went, no copy stays here" \
    || bad edit.no_copy_left "a copy stayed here: $(find "$EW/cache" -name 'edit-*' | head -n 1)"

# An editor that changes nothing: nothing goes, and the far file keeps its
# time of change.
before=$(stat -c %Y "$RD/edit-sftp")
e true 2201 "$T:cp/edit-sftp"
rc=$?
[ "$rc" = 0 ] && grep -q "no change, so nothing was sent" "$EW/out" && [ "$(stat -c %Y "$RD/edit-sftp")" = "$before" ] \
    && [ "$(sum "$EW/want")" = "$(sum "$RD/edit-sftp")" ] \
    && ok edit.unchanged "an edit with no change sends nothing (exit 0)" \
    || bad edit.unchanged "an edit with no change: exit $rc" "$EW/out"

# The far file changes while the editor is open: nothing goes, the far
# change stays, and the copy here stays, named.
far edit-far
e "$EW/far-first" 2201 "$T:cp/edit-far"
rc=$?
copy=$(kept)
[ "$rc" = 73 ] && grep -q "a line from podssh ssh" "$RD/edit-far" && ! grep -q "a line from the editor" "$RD/edit-far" \
    && [ -n "$copy" ] && grep -q "a line from the editor" "$copy" \
    && ok edit.far_changed "a far file that podssh ssh changed meanwhile: exit 73, nothing sent, the copy kept and named" \
    || bad edit.far_changed "a far file changed meanwhile: exit $rc" "$EW/out"

# An editor that fails: nothing goes, podssh exits with its status, and
# the copy, which holds a change, stays, named.
far edit-fail
e "$EW/add-and-fail" 2201 "$T:cp/edit-fail"
rc=$?
copy=$(kept)
[ "$rc" = 3 ] && [ "$(cat "$RD/edit-fail")" = "the far file" ] && [ -n "$copy" ] && grep -q "a line from the editor" "$copy" \
    && ok edit.editor_failed "an editor that ends with 3: exit 3, nothing sent, the copy kept and named" \
    || bad edit.editor_failed "an editor that fails: exit $rc" "$EW/out"

# A symbolic link stays a link, and the file that it names gets the line.
far edit-target
ln -sf edit-target "$RD/edit-link"
chown -h podtest:podtest "$RD/edit-link"
e "$EW/add-line" 2201 "$T:cp/edit-link"
rc=$?
[ "$rc" = 0 ] && [ -L "$RD/edit-link" ] && [ "$(sum "$EW/want")" = "$(sum "$RD/edit-target")" ] \
    && ok edit.link "edit of a link over SFTP: the link stays a link, and its file gets the line" \
    || bad edit.link "edit of a link over SFTP: exit $rc" "$EW/out"

# With no terminal: 64, before anything connects.
env -u SSH_AUTH_SOCK -u VISUAL HOME="$W" EDITOR="$EW/add-line" "$BIN" edit --direct -P 2201 "$T:cp/edit-sftp" \
    </dev/null >"$EW/out" 2>&1
expect_rc edit.no_terminal "edit with no terminal" 64 $? "$EW/out"
