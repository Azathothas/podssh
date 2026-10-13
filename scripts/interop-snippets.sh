# Snippets (T-187) against OpenSSH on port 2201 and Dropbear on port 2203:
# a value with a quote, and a value with a command in it, each reach the
# server's shell as one word and come back unchanged, and the command never
# runs (the planted defect, the values with no quotes, fails both); the
# question answered by an askpass program, y and n; and podssh each, with
# the user, host and port of each host. Sourced by scripts/interop-each.sh;
# uses ok, bad, p, e, $W, $K and $T.

echo
echo "== snippets (T-187, OpenSSH and Dropbear)"
SN="$W/snippets"
mkdir -p "$SN"
cat >"$SN/settings" <<'EOF'
[snippets]
say printf %s {{1}}
mark touch {{1}}
where printf '%s@%s:%s\n' {{user}} {{host}} {{port}}
EOF
chmod 600 "$SN/settings"
printf '#!/bin/sh\nprintf "%%s" "$1" >"%s"\necho y\n' "$SN/asked" >"$SN/askpass-yes"
printf '#!/bin/sh\necho n\n' >"$SN/askpass-no"
chmod 700 "$SN"/askpass-*
export PODSSH_SETTINGS="$SN/settings"
INJ=/tmp/podssh-snippet-inj

for srv in openssh:2201 dropbear:2203; do
    port=${srv#*:}
    # shellcheck disable=SC2086
    p "$port" $K --yes --snippet say "$T" "a'b" </dev/null >"$SN/out" 2>"$SN/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(cat "$SN/out")" = "a'b" ] \
        && ok "snippets.quote.${srv%%:*}" "port $port: the value a'b came back as one word, unchanged" \
        || bad "snippets.quote.${srv%%:*}" "port $port: exit $rc, out $(cat "$SN/out")" "$SN/err"
    rm -f "$INJ"
    # shellcheck disable=SC2086
    p "$port" $K --yes --snippet say "$T" "x; touch $INJ" </dev/null >"$SN/out" 2>"$SN/err"
    rc=$?
    [ "$rc" = 0 ] && [ "$(cat "$SN/out")" = "x; touch $INJ" ] && [ ! -e "$INJ" ] \
        && ok "snippets.injection.${srv%%:*}" "port $port: a command in a value came back unchanged, and did not run" \
        || bad "snippets.injection.${srv%%:*}" "port $port: exit $rc, out $(cat "$SN/out")" "$SN/err"
done

rm -f "$INJ" "$SN/asked"
# shellcheck disable=SC2086
SSH_ASKPASS="$SN/askpass-yes" SSH_ASKPASS_REQUIRE=force \
    p 2201 $K --snippet mark "$T" "$INJ" </dev/null >"$SN/out" 2>"$SN/err"
rc=$?
[ "$rc" = 0 ] && [ -e "$INJ" ] && grep -q "touch $INJ" "$SN/asked" && grep -q 'Run it? \[y/N\]' "$SN/asked" \
    && ok snippets.asked "SSH_ASKPASS answered y to a question that showed the command, and it ran" \
    || bad snippets.asked "exit $rc" "$SN/err"
rm -f "$INJ"
# shellcheck disable=SC2086
SSH_ASKPASS="$SN/askpass-no" SSH_ASKPASS_REQUIRE=force \
    p 2201 $K --snippet mark "$T" "$INJ" </dev/null >"$SN/out" 2>"$SN/err"
rc=$?
[ "$rc" = 64 ] && [ ! -e "$INJ" ] && grep -q "not run" "$SN/err" \
    && ok snippets.declined "SSH_ASKPASS answered n: exit 64, and nothing ran" \
    || bad snippets.declined "exit $rc" "$SN/err"

e --yes --snippet where "$T:2201,$T:2203" >"$SN/out" 2>"$SN/err"
rc=$?
[ "$rc" = 0 ] && grep -qx "$T:2201: $T:2201" "$SN/out" && grep -qx "$T:2203: $T:2203" "$SN/out" \
    && [ "$(grep -c "^podssh each:   $T:220[13]: printf" "$SN/err")" = 2 ] \
    && ok snippets.each "each --snippet: the user, host and port of each host, each command shown before it ran" \
    || bad snippets.each "exit $rc" "$SN/err"
unset PODSSH_SETTINGS
