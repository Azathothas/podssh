#!/bin/sh
# scripts/interop-man.sh - podssh's man page against two man(7) renderers
# that podssh did not write: groff and mandoc. The gate runs it in its
# throwaway container, where it installs both with apk.
#
#   sh scripts/interop-man.sh path/to/podssh
#
# The flags come from `podssh COMMAND --help` of each working command, so
# the check reads the binary, not the manual's own tables. Each check prints
# ok or FAIL; the exit code is 1 when one failed. A planted page, with the
# term of one flag removed, must fail the same check, or the check is
# vacuous. (An `Fl` macro that used `\$*` once printed each flag name blank,
# under groff and mandoc alike.)

set -u
B=${1:?usage: sh scripts/interop-man.sh path/to/podssh}
# shellcheck source=scripts/interop-lib.sh
. "$(dirname "$0")/interop-lib.sh"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

apk add --no-cache groff mandoc >"$W/apk.log" 2>&1 || { cat "$W/apk.log"; exit 1; }

"$B" man --roff >"$W/podssh.1"
rc=$?
if [ "$rc" -ne 0 ]; then
    bad man.roff "podssh man --roff exited $rc"
    exit 1
fi
ok man.roff "podssh man --roff exited 0"

# The flags that --help shows for each command that works: one spelling per
# line, "-x, --long" or "--long".
"$B" --help >"$W/help.txt"
verbs=$(sed -n '/^SUBCOMMANDS:/,/^$/p' "$W/help.txt" | grep -v '(not ' |
    awk 'NF > 1 && $1 != "SUBCOMMANDS:" && $1 != "aliases:" { print $1 }')
: >"$W/flags.raw"
# The verbs come from the binary, not a literal list, so no id names one; a
# failed --help counts against man.flags.
broken=
for v in $verbs; do
    if ! "$B" "$v" --help >"$W/verb.txt"; then
        broken="$broken $v"
        continue
    fi
    sed -n '/^OPTIONS:/,/^$/p' "$W/verb.txt" |
        grep -oE '^ +(-[A-Za-z0-9], )?--[A-Za-z0-9][A-Za-z0-9-]*' |
        sed 's/^ *//' >>"$W/flags.raw"
done
sort -u "$W/flags.raw" >"$W/flags.txt"
count=$(wc -l <"$W/flags.txt")
if [ -n "$broken" ]; then
    bad man.flags "podssh VERB --help failed for:$broken"
elif [ "$count" -ge 20 ]; then
    ok man.flags "$count flag spellings from the --help of: $(printf '%s' "$verbs" | tr '\n' ' ')"
else
    bad man.flags "only $count flag spellings from --help"
fi

bs=$(printf '\b')

# render PAGE: PAGE.groff and PAGE.mandoc, as plain text.
render() {
    groff -man -Tascii -P-cbu -rLL=300n -ww "$1" >"$1.groff" 2>"$1.groff.err" || return 1
    mandoc -Tascii -Owidth=300 "$1" >"$1.mandoc.raw" || return 1
    sed "s/.$bs//g" "$1.mandoc.raw" >"$1.mandoc"
}

# missing PAGE: write each flag spelling that a rendering lacks to
# PAGE.missing, one line each.
missing() {
    : >"$1.missing"
    for r in groff mandoc; do
        while IFS= read -r f; do
            grep -qF -- "$f" "$1.$r" || echo "$r lacks: $f" >>"$1.missing"
        done <"$W/flags.txt"
    done
}

if render "$W/podssh.1"; then
    missing "$W/podssh.1"
    n=$(wc -l <"$W/podssh.1.missing")
    if [ "$n" -eq 0 ]; then
        ok man.render.flags "groff and mandoc show each of the $count flag spellings"
    else
        bad man.render.flags "$n flag spellings are missing from a rendering:"
        cat "$W/podssh.1.missing"
    fi
    if [ -s "$W/podssh.1.groff.err" ]; then
        bad man.render.groff_warnings "groff -ww warns:" "$W/podssh.1.groff.err"
    else
        ok man.render.groff_warnings "groff -ww: no warnings"
    fi
    if grep -q '^ *podssh - ' "$W/podssh.1.groff" && grep -q '^ *podssh - ' "$W/podssh.1.mandoc"; then
        ok man.render.name "both show the NAME line"
    else
        bad man.render.name "a rendering has no NAME line 'podssh - ...'"
    fi
else
    # A page that does not render shows no flag spelling.
    bad man.render.flags "groff or mandoc could not render the page"
fi

mandoc -Tlint -W error "$W/podssh.1" >"$W/lint.txt" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    ok man.lint "mandoc -Tlint: no errors"
else
    bad man.lint "mandoc -Tlint exited $rc:" "$W/lint.txt"
fi

# The plant: the same page without the term of --port. The check must fail.
grep -vF '\fB\-\-port\fR' "$W/podssh.1" >"$W/planted.1"
if render "$W/planted.1"; then
    missing "$W/planted.1"
    if grep -qF -- '--port' "$W/planted.1.missing"; then
        ok man.plant "the planted page fails: $(wc -l <"$W/planted.1.missing") spellings missing"
    else
        bad man.plant "the planted page passed: the check is vacuous"
    fi
else
    bad man.plant "the planted page did not render"
fi

[ "$fail" -eq 0 ] || exit 1
