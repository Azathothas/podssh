# Match in ssh_config (T-045): each fixture through OpenSSH's ssh -G and
# podssh's, and the lines that show which blocks applied must be the same.
# Each block adds an IdentityFile /m/NAME, so that the lines show the blocks
# in their order. Sourced by scripts/interop.sh; uses ok, bad, $W and $BIN.

echo
echo "== Match in ssh_config, against OpenSSH's ssh -G (T-045)"
MW="$W/match"
mkdir -p "$MW"
ME=$(id -un)
MHOME=$(awk -F: -v u="$ME" '$1 == u {print $6}' /etc/passwd)
cat >"$MW/basics" <<'EOF'
Match host h
  IdentityFile /m/host_h
Match host H
  IdentityFile /m/host_H
Match originalhost H
  IdentityFile /m/orig_H
Match host x,h
  IdentityFile /m/list
Match host *,!h
  IdentityFile /m/neglist
Match !host x
  IdentityFile /m/not_x
Match host h # a comment
  IdentityFile /m/comment
Match host=h
  IdentityFile /m/eq
Match host h host x
  IdentityFile /m/twice
EOF
cat >"$MW/hostname" <<'EOF'
Match host real.example
  IdentityFile /m/before
Host h
  HostName real.example
Match host h
  IdentityFile /m/host_h
Match host real.example
  IdentityFile /m/host_real
Match originalhost h
  IdentityFile /m/orig_h
EOF
{
    printf 'Match user alice\n  IdentityFile /m/user_alice\nMatch user %s\n  IdentityFile /m/user_me\n' "$ME"
    printf 'Match localuser %s\n  IdentityFile /m/localuser_me\nHost h\n  User alice\n' "$ME"
    printf 'Match user alice\n  IdentityFile /m/user_alice_after\nMatch user bob\n  IdentityFile /m/user_bob\n'
} >"$MW/users"
cat >"$MW/tagged" <<'EOF'
Match tagged t1
  IdentityFile /m/tagged_t1
Match tagged ""
  IdentityFile /m/tagged_empty
Host h
  Tag t1
Match tagged t1
  IdentityFile /m/tagged_t1_after
Match !tagged t1
  IdentityFile /m/not_tagged_t1
EOF
cat >"$MW/sessions" <<'EOF'
Match sessiontype shell
  IdentityFile /m/st_shell
Match sessiontype exec
  IdentityFile /m/st_exec
Match sessiontype subsystem
  IdentityFile /m/st_subsystem
Match sessiontype none
  IdentityFile /m/st_none
Match command "ls*"
  IdentityFile /m/cmd_ls
Match command ""
  IdentityFile /m/cmd_empty
Match version OpenSSH_10*
  IdentityFile /m/version
EOF
cat >"$MW/final" <<'EOF'
Match canonical
  IdentityFile /m/canonical
Match !final
  IdentityFile /m/not_final
Host h
  HostName real.example
Match final host real.example
  IdentityFile /m/final_host_real
Host real.example
  IdentityFile /m/hostblock_real
Host H
  SendEnv HB
Host h
  SendEnv LB
Match final all
  HostName final.example
  Port 2399
EOF
cat >"$MW/accumulate" <<'EOF'
Host *
  SendEnv FOO
  SetEnv A=1
  LocalForward 8080 db:80
  RemoteForward 9090 web:80
  DynamicForward 1080
  IdentityFile /m/star
Host h
  SetEnv A=2 B=3
Match final all
  IdentityFile /m/final
EOF
# match_shown FILE: the lines of -G that show which blocks applied.
match_shown() {
    grep -E '^(user|hostname|port|sessiontype|remotecommand|tag|dynamicforward|localforward|remoteforward|sendenv|setenv) |^identityfile /m/' "$1" \
        | grep -vxE 'port 22|sessiontype default' | tr '\n' ';'
}
for spec in "basics:basics:h" "basics_upper:basics:H" "hostname:hostname:h" "users:users:h" "users_l:users:-l bob h" \
        "users_at:users:bob@h" "tagged:tagged:h" "tagged_p:tagged:-P t1 h" "tagged_p2:tagged:-P t2 h" \
        "shell:sessions:h" "exec:sessions:h ls -l" "none:sessions:-N h" "subsystem:sessions:-s h sftp" \
        "final:final:h" "final_upper:final:H" "accumulate:accumulate:h"; do
    rest=${spec#*:}
    file=$MW/${rest%%:*}
    words=${rest#*:}
    # shellcheck disable=SC2086
    ssh -F "$file" -G $words </dev/null >"$MW/ssh-G" 2>"$MW/ssh-err"
    # shellcheck disable=SC2086
    env USER="$ME" HOME="$MHOME" PODSSH_OFFLINE=1 "$BIN" ssh -F "$file" -G $words </dev/null >"$MW/podssh-G" 2>"$MW/err"
    rc=$?
    theirs=$(match_shown "$MW/ssh-G")
    ours=$(match_shown "$MW/podssh-G")
    [ "$rc" = 0 ] && [ -n "$theirs" ] && [ "$ours" = "$theirs" ] \
        && ok "match.${spec%%:*}" "Match: podssh applies the blocks that OpenSSH applies ($words)" \
        || bad "match.${spec%%:*}" "Match ($words): exit $rc; OpenSSH: $theirs; podssh: $ours" "$MW/err"
done
# Match exec runs nothing and is refused with its place (78), where OpenSSH
# would run it.
printf 'Host other\n  Port 2200\nMatch exec "touch %s/ran"\n  Port 2222\n' "$MW" >"$MW/exec"
env USER="$ME" HOME="$MHOME" PODSSH_OFFLINE=1 "$BIN" ssh -F "$MW/exec" -G h </dev/null >"$MW/podssh-G" 2>"$MW/err"
rc=$?
[ "$rc" = 78 ] && grep -q "/exec:3: Match exec" "$MW/err" && [ ! -e "$MW/ran" ] \
    && ok match.exec_refused "Match exec: refused with its file and line (78), and nothing ran" \
    || bad match.exec_refused "Match exec: exit $rc" "$MW/err"
