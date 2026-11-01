#!/bin/sh
# The planted defects of the checks (T-251): each check that the record trusts
# must fail on a defect planted for it (AGENTS.md, section 6, rule 3), and the
# entries since 2026-10-09 left that planted run to the release check.
#
#   sh scripts/plant-each.sh --list            the plants, with their groups
#   sh scripts/plant-each.sh [--group G] [ID...]
#
# Each plant is scripts/plants/ID.plant, a file of shell assignments:
#
#   ENTRY=T-NNN          the entry whose check it proves
#   GROUP=name           the workflow job that runs it (plants.yml)
#   EXPECT='regex'       what the failed run must print (grep -E), so that a
#                        run that fails for another reason is not a catch
#   RUN='command'        the check; it must exit nonzero on the plant
#   SETUP='command'      optional: run first, with the plant in place (apk add)
#   LIMIT=seconds        optional: the time limit of RUN (default 1800)
#   ENV='NAME=value'     optional: a plant that a harness takes as a switch
#
# and, unless the plant is a switch of its harness (ENV), scripts/plants/ID.patch,
# a diff against the tree that `git apply` takes. The patch is applied, RUN
# runs with its limit, and the patch is reverted on each path out. A plant is
# caught when RUN exits nonzero and printed EXPECT; it is MISSED when RUN
# passed or failed without EXPECT, and STALE when its patch no longer applies:
# each of the two is a failure of this script.
#
# It runs in the build image with the tree at /work (plants.yml), or on a host
# with --here. POSIX sh, and each exit code is read from its own process.

set -u

here=0
group=
list=0
while [ $# -gt 0 ]; do
    case "$1" in
        --here) here=1 ;;
        --group) shift; group=${1:-} ;;
        --list) list=1 ;;
        --) shift; break ;;
        -*) echo "plant-each: unknown option $1" >&2; exit 64 ;;
        *) break ;;
    esac
    shift
done

if [ "$here" -eq 0 ]; then
    cd /work || { echo "plant-each: no tree at /work (use --here on a host)" >&2; exit 71; }
fi
dir=scripts/plants
[ -d "$dir" ] || { echo "plant-each: $dir is missing" >&2; exit 71; }

: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS
TARGET=${PODSSH_TARGET:-x86_64-unknown-linux-musl}
export TARGET
# The release binary that a RUN builds with `cargo build --release`, by name.
BIN="target/$TARGET/release/podssh"
export BIN

# Read one plant's file in a subshell's scope: its variables, and nothing else.
read_plant() {
    ENTRY='' GROUP='' EXPECT='' RUN='' SETUP='' LIMIT=1800 ENV=''
    # shellcheck disable=SC1090  # each plant file is the repository's own
    . "$dir/$1.plant"
}

ids=
if [ $# -gt 0 ]; then
    ids=$*
else
    for f in "$dir"/*.plant; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .plant)
        if [ -n "$group" ]; then
            g=$(read_plant "$id"; printf '%s' "$GROUP")
            [ "$g" = "$group" ] || continue
        fi
        ids="$ids $id"
    done
fi

if [ "$list" -eq 1 ]; then
    for id in $ids; do
        (read_plant "$id"; printf '%s\t%s\t%s\n' "$GROUP" "$id" "$ENTRY")
    done
    exit 0
fi

[ -n "$ids" ] || { echo "plant-each: no plant chosen" >&2; exit 64; }

caught=0
missed=0
stale=0
for id in $ids; do
    [ -f "$dir/$id.plant" ] || { echo "MISSED $id: no $dir/$id.plant"; missed=$((missed + 1)); continue; }
    (
        read_plant "$id"
        patch="$dir/$id.patch"
        log="/tmp/plant-$id.log"
        printf '\n=== plant %s (%s)\n' "$id" "$ENTRY"
        if [ -z "$EXPECT" ] || [ -z "$RUN" ]; then
            echo "MISSED $id: EXPECT and RUN are required"
            exit 1
        fi
        applied=0
        if [ -f "$patch" ]; then
            if ! git apply --check "$patch" 2>"$log"; then
                cat "$log"
                echo "STALE $id: its patch no longer applies"
                exit 2
            fi
            git apply "$patch" || { echo "STALE $id: git apply failed"; exit 2; }
            applied=1
        elif [ -z "$ENV" ]; then
            echo "MISSED $id: neither $patch nor ENV"
            exit 1
        fi
        # shellcheck disable=SC2317  # called by the EXIT trap
        revert() {
            if [ "$applied" -eq 1 ]; then
                git apply -R "$patch" || echo "plant-each: the patch of $id did not revert" >&2
                applied=0
            fi
        }
        trap revert EXIT
        trap 'exit 130' INT TERM
        if [ -n "$SETUP" ]; then
            sh -c "$SETUP" >"$log.setup" 2>&1 || { tail -20 "$log.setup"; echo "MISSED $id: SETUP failed"; exit 1; }
        fi
        # shellcheck disable=SC2086  # ENV is a list of NAME=value words
        env $ENV timeout "$LIMIT" sh -c "$RUN" >"$log" 2>&1
        rc=$?
        tail -15 "$log"
        if [ "$rc" -eq 0 ]; then
            echo "MISSED $id: the check passed with the plant"
            exit 1
        fi
        if [ "$rc" -eq 124 ]; then
            echo "MISSED $id: the check ran out of its $LIMIT s"
            exit 1
        fi
        if ! grep -Eq "$EXPECT" "$log"; then
            echo "MISSED $id: exit $rc, but no line matched: $EXPECT"
            exit 1
        fi
        echo "caught $id: exit $rc, and: $(grep -E -m1 "$EXPECT" "$log")"
        exit 0
    )
    rc=$?
    case "$rc" in
        0) caught=$((caught + 1)) ;;
        2) stale=$((stale + 1)) ;;
        *) missed=$((missed + 1)) ;;
    esac
    # A plant that did not revert would plant the next one too: its patch
    # must apply again to what is left.
    if [ -f "$dir/$id.patch" ] && [ "$rc" -ne 2 ] && ! git apply --check "$dir/$id.patch" 2>/dev/null; then
        echo "plant-each: the patch of $id is still in the tree; stopping"
        exit 1
    fi
done

printf '\nplant-each: %s caught, %s missed, %s stale\n' "$caught" "$missed" "$stale"
[ "$missed" -eq 0 ] && [ "$stale" -eq 0 ]
