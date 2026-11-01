# The checks of the release check (T-251) that GitHub's runners make: the
# Windows and macOS hosts, the box and the live runs that this host's
# network does not carry. Sourced by scripts/release-check.sh. The script
# starts no run; a row without --actions-run NAME=ID says how to start one,
# and a row with it reads the run and its jobs through GitHub's public API
# (scripts/release-check-api.py), and passes only for a run of its workflow,
# completed, at the commit under check, whose jobs each passed.

# run_of NAME: the run that --actions-run gave NAME, or nothing.
run_of() {
    for _ro in $RUNS; do
        [ "${_ro%%=*}" = "$1" ] && { echo "${_ro#*=}"; return; }
    done
}

# jobs_of FILE SPECS: the problems of the jobs of a read run against SPECS
# (GLOB:N;...); nothing when each passed.
jobs_of() {
    _jf=$1
    _probs=
    _old_ifs=$IFS
    IFS=';'
    # The specs, split at each ; and not matched against file names.
    set -f
    # shellcheck disable=SC2086
    set -- $2
    set +f
    IFS=$_old_ifs
    for _spec in "$@"; do
        _glob=${_spec%:*} _min=${_spec##*:}
        [ "$_min" = all ] && _glob='*'
        _n=0 _badj=
        while IFS="$TAB" read -r _kind _name _status _conc; do
            [ "$_kind" = job ] || continue
            # shellcheck disable=SC2254  # the glob of the spec is a pattern
            case $_name in
                $_glob)
                    _n=$((_n + 1))
                    [ "$_conc" = success ] || _badj="$_badj $_name ($_status, ${_conc:-none})"
                    ;;
            esac
        done <"$_jf"
        [ "$_min" = all ] && _min=1
        [ "$_n" -ge "$_min" ] || _probs="$_probs $_n jobs of '$_glob', not $_min;"
        [ -z "$_badj" ] || _probs="$_probs not passed:$_badj;"
    done
    printf '%s' "$_probs"
}

checks_actions() {
    actions_spec >"$W/actions.spec"
    while IFS='|' read -r _id _name _wf _jobs _rule _how; do
        wanted "$_id" || continue
        _modes=$(catalog | awk -F'|' -v id="$_id" '$1 == id { print $2 }')
        case $_modes in both | "$MODE") ;; *) continue ;; esac
        _ref=main
        [ "$MODE" != tag ] || _ref=$TAG
        _run=$(run_of "$_name")
        if [ -z "$_run" ]; then
            _hint=$(printf '%s' "$_how" | sed "s/REF/$_ref/g; s/TAG/${TAG:-TAG}/g; s/COMMIT/$COMMIT/g")
            row ACTIONS "$_id" - 0 "$_wf, not read: $_hint; then --actions-run $_name=RUN"
            continue
        fi
        _f=$W/api.run.$_run
        if [ ! -f "$_f" ]; then
            timed 180 "$_f" python3 -I "$HERE/release-check-api.py" run "$SLUG" "$_run"
            echo "$RC" >"$_f.rc"
            cp "$_f" "$LOGS/api.run.$_run.log"
        fi
        if [ "$(cat "$_f.rc")" != 0 ]; then
            row FAIL "$_id" - 0 "run $_run of $_wf could not be read: $(tail -n 1 "$_f")"
            continue
        fi
        _line=$(grep "^run$TAB" "$_f")
        _path=$(printf '%s' "$_line" | cut -f2)
        _sha=$(printf '%s' "$_line" | cut -f3)
        _status=$(printf '%s' "$_line" | cut -f4)
        _created=$(printf '%s' "$_line" | cut -f6)
        _p=
        [ "$_path" = ".github/workflows/$_wf" ] || _p="$_p run $_run is of $_path, not $_wf;"
        [ "$_status" = completed ] || _p="$_p it is $_status;"
        if [ "$_sha" != "$COMMIT" ]; then
            # A run of a tag's checks that started on main reads the tag's
            # files; it counts once the release was published.
            if [ "$_rule" = after ] && [ "$MODE" = tag ] && [ -n "${PUBLISHED:-}" ] &&
                awk -v a="$_created" -v b="$PUBLISHED" 'BEGIN { exit !(a >= b) }'; then
                :
            else
                _p="$_p it ran at $(printf '%.7s' "$_sha"), not $(printf '%.7s' "$COMMIT");"
            fi
        fi
        _p="$_p$(jobs_of "$_f" "$_jobs")"
        if [ -z "$_p" ]; then
            row PASS "$_id" - 0 "run $_run of $_wf at $(printf '%.7s' "$_sha"): $(printf '%s' "$_jobs" | tr ';' ' ') passed"
        else
            row FAIL "$_id" - 0 "$_p"
        fi
    done <"$W/actions.spec"

    # Each ACTIONS row of the catalog has its spec, and each spec its row.
    catalog | awk -F'|' '$1 ~ /^actions\./ { print $1 }' | sort >"$W/actions.ids"
    cut -d'|' -f1 "$W/actions.spec" | sort >"$W/actions.specs"
    if ! cmp -s "$W/actions.ids" "$W/actions.specs"; then
        row FAIL actions.gate - 0 "the catalog and actions_spec disagree: $(comm -3 "$W/actions.ids" "$W/actions.specs" | tr -d '\t' | tr '\n' ' ')"
    fi
}
