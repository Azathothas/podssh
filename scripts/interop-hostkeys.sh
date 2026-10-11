# The name that each host key is filed under (T-030): each hop of -J its own,
# and HostKeyAlias with no port, as OpenSSH files it. Sourced by
# scripts/interop.sh after its check of -J; uses ok, bad, $W, $BIN, $K and $T,
# and its servers on ports 2201 (OpenSSH) and 2203 (Dropbear).

# Each hop files its key under its own name (T-030): from an empty file under
# accept-new, the jump's key is [127.0.0.1]:2201 and the destination's
# [127.0.0.1]:2203; a changed key of the jump alone is then refused, by the
# jump's name.
jump_known() { # FILE: -J through OpenSSH to Dropbear, with FILE as known_hosts
    # shellcheck disable=SC2086
    env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2203 -o UserKnownHostsFile="$1" \
        -o StrictHostKeyChecking=accept-new -o IdentityAgent=none -o IdentitiesOnly=yes $K -o BatchMode=yes \
        -J "$T:2201" "$T" 'exit 5' </dev/null >"$W/out" 2>"$W/err"
}
: >"$W/kh_jump"
jump_known "$W/kh_jump"
rc=$?
names=$(cut -d' ' -f1 "$W/kh_jump" | sort -u | tr '\n' ' ')
[ "$rc" = 5 ] && [ "$names" = "[127.0.0.1]:2201 [127.0.0.1]:2203 " ] \
    && ok hostkeys.jump_names "-J: each hop's key is filed under its own name and port" \
    || bad hostkeys.jump_names "-J: exit $rc; the names filed: $names" "$W/err"
fake=$(cut -d' ' -f1,2 "$W/id_ed25519.pub")
awk -v fake="$fake" '$1 == "[127.0.0.1]:2201" { print $1, fake; next } { print }' "$W/kh_jump" >"$W/kh_jump.new"
mv "$W/kh_jump.new" "$W/kh_jump"
jump_known "$W/kh_jump"
rc=$?
[ "$rc" = 255 ] && grep -qF "for '[127.0.0.1]:2201' has changed" "$W/err" \
    && ok hostkeys.jump_changed "-J: a changed key of the jump alone is refused, by the jump's name" \
    || bad hostkeys.jump_changed "-J with the jump's key changed: exit $rc" "$W/err"
# HostKeyAlias files the destination's key under the alias as it is, with no
# port, as OpenSSH files it (T-030), and each tool reads the other's file.
alias_login() { # TOOL FILE STRICT: a login to port 2201 as alias-t030
    if [ "$1" = openssh ]; then
        ssh -F /dev/null -p 2201 -i "$W/id_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes \
            -o HostKeyAlias=alias-t030 -o StrictHostKeyChecking="$3" -o UserKnownHostsFile="$2" "$T" true \
            </dev/null >"$W/out" 2>"$W/err"
    else
        # shellcheck disable=SC2086
        env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p 2201 -o HostKeyAlias=alias-t030 \
            -o StrictHostKeyChecking="$3" -o UserKnownHostsFile="$2" -o IdentityAgent=none \
            -o IdentitiesOnly=yes $K -o BatchMode=yes "$T" true </dev/null >"$W/out" 2>"$W/err"
    fi
}
: >"$W/kh_alias_openssh"
: >"$W/kh_alias_podssh"
alias_login openssh "$W/kh_alias_openssh" accept-new
alias_login podssh "$W/kh_alias_podssh" accept-new
rc=$?
names="$(cut -d' ' -f1 "$W/kh_alias_openssh" | sort -u) / $(cut -d' ' -f1 "$W/kh_alias_podssh" | sort -u)"
[ "$rc" = 0 ] && [ "$names" = "alias-t030 / alias-t030" ] \
    && ok hostkeys.alias_no_port "HostKeyAlias with -p 2201: the key is filed under the alias, as OpenSSH files it" \
    || bad hostkeys.alias_no_port "HostKeyAlias: exit $rc; OpenSSH / podssh filed: $names" "$W/err"
alias_login podssh "$W/kh_alias_openssh" yes && by_podssh=read || by_podssh=refused
alias_login openssh "$W/kh_alias_podssh" yes && by_openssh=read || by_openssh=refused
[ "$by_podssh" = read ] && [ "$by_openssh" = read ] \
    && ok hostkeys.alias_read "HostKeyAlias: each tool reads the key that the other filed" \
    || bad hostkeys.alias_read "HostKeyAlias: OpenSSH's file $by_podssh by podssh, podssh's $by_openssh by OpenSSH" "$W/err"
