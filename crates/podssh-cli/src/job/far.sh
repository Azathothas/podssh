# The far side of `podssh job` (T-193, T-197). podssh sends this POSIX sh
# script with each call and keeps it as ~/.podssh/jobs/jobs.sh, where tmux
# runs it for each job and for the runner of the queue: nothing of podssh
# runs on the host but this file, under sh, with tmux and the tools that it
# probes. Each job is a directory beside it, named MILLIS-ID (the time of
# its start or its submit in milliseconds, then 8 hex digits), so that the
# names sort in that order: its command (cmd), its state (state: queued,
# running, done), its output and its errors (out), and its exit status
# (status) once it ended. The file slots holds the number of jobs that the
# runner lets run at once. A job with no tmux (T-481) is far_notmux.sh's,
# which comes before this file in the script.
#
# sh jobs.sh MARKER ACTION ARG...: MARKER on a line, then the answer, which
# crates/podssh-cli/src/job/far.rs reads. A MARKER of - prints none: tmux
# runs `jobs.sh - job NAME` for a job, and `jobs.sh - runner` for the queue;
# nohup runs `jobs.sh - plain NAME lead|alone` and `jobs.sh - runner plain`.

m=$1
a=$2
shift 2 || exit 64
case $0 in
*/*) cd "${0%/*}" || exit 1 ;;
esac
q=$(pwd)
[ "$m" = - ] || printf '%s\n' "$m"

say() {
    printf '%s\n' "$*"
}

# Each tool that the call needs; else the first one missing is said.
need() {
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || {
            say "missing $t"
            exit 0
        }
    done
}

# Whether this directory can go in single quotes to tmux's shell, which is
# the login's: a ' or a ! cannot.
quotable() {
    case $q in
    *\'* | *!*) return 1 ;;
    esac
    return 0
}

# The tmux session of the job of directory $1.
sess() {
    printf 'podssh-job-%s' "${1#*-}"
}

# The directory of the job whose ID is $1; a status of 1 when there is none.
dir_of() {
    for d in *-"$1"; do
        [ -d "$d" ] && {
            printf '%s' "$d"
            return 0
        }
    done
    return 1
}

# The names of tmux's sessions, one a line, in $live: none without tmux or
# without its server.
sessions() {
    live=$(tmux list-sessions -F '#{session_name}' 2>/dev/null)
}

# Whether the session named $1 is in $live: its exact name, never a part.
alive() {
    case "
$live
" in
    *"
$1
"*) return 0 ;;
    esac
    return 1
}

# The state of the job of directory $1: done (its status is there), queued,
# running (its session is, or with no tmux its runner), or lost (none of
# these: the host or tmux's server stopped).
state_of() {
    if [ -f "$1/status" ]; then
        printf done
    elif [ "$(cat "$1/state" 2>/dev/null)" = queued ]; then
        printf queued
    elif runs "$1"; then
        printf running
    else
        printf lost
    fi
}

# Start the job of directory $1 in tmux. Its command runs in sh, in the home
# directory.
intmux() {
    if ! quotable || ! command -v tmux >/dev/null 2>&1; then
        return 1
    fi
    printf 'running\n' >"$1/state" &&
        tmux new-session -d -s "$(sess "$1")" "exec sh '$q/jobs.sh' - job '$1'" </dev/null
}

# Start the job of directory $1 as its kind asks: in tmux, or with no tmux.
launch() {
    if [ "$(kind_of "$1")" = plain ]; then
        loose "$1"
    else
        intmux "$1"
    fi
}

# A job of the queue that did not start ends at once with 255.
unstarted() {
    if [ "$(kind_of "$1")" = plain ]; then
        printf 'podssh: the runner of this job did not start\n' >"$1/out"
    else
        printf 'podssh: tmux did not start this job\n' >"$1/out"
    fi
    printf '255\n' >"$1/status"
    printf 'done\n' >"$1/state"
}

# The runner of the queue, unless one runs, of either kind: in tmux, whose
# session's name is its lock, so a second one does not start; or with no
# tmux ($1 is plain), whose lock is runner.lock.
runner_up() {
    sessions
    alive podssh-runner && return 0
    held && return 0
    if [ "$1" = plain ]; then
        away sh "$q/jobs.sh" - runner plain
    else
        quotable && command -v tmux >/dev/null 2>&1 &&
            tmux new-session -d -s podssh-runner "exec sh '$q/jobs.sh' - runner" </dev/null 2>/dev/null
    fi
    return 0
}

# The oldest queued job in $next, the jobs that run in $busy, and in $k the
# slots: the number of the file slots, else 1.
scan() {
    sessions
    k=$(cat slots 2>/dev/null)
    case $k in
    '' | *[!0-9]* | 0*) k=1 ;;
    esac
    busy=0
    next=
    for d in *-*; do
        [ -f "$d/cmd" ] && [ ! -f "$d/status" ] || continue
        case $(cat "$d/state" 2>/dev/null) in
        queued) [ -n "$next" ] || next=$d ;;
        running) runs "$d" && busy=$((busy + 1)) ;;
        esac
    done
}

# The size of the file $1 in bytes, 0 when it cannot be read: some wc pad
# their count with blanks.
size() {
    # shellcheck disable=SC2046 # the count, out of its blanks
    set -- $(wc -c 2>/dev/null <"$1")
    case $1 in
    '' | *[!0-9]*) printf 0 ;;
    *) printf '%s' "$1" ;;
    esac
}

case $a in
start | submit)
    # $4: plain for a job with no tmux (T-481), which the user asked for;
    # else tmux runs it, and its lack is said with what can install it.
    kind=${4:-tmux}
    if [ "$kind" = plain ]; then
        need mkdir cat mv rm nohup sleep
    else
        need mkdir cat mv rm sleep
        command -v tmux >/dev/null 2>&1 || {
            say "missing tmux $(hint)"
            exit 0
        }
        quotable || {
            say "odd-path $q"
            exit 0
        }
    fi
    mkdir "$1" || {
        say "failed to make $q/$1"
        exit 0
    }
    printf '%s\n' "$3" >"$1/cmd" || {
        rm -rf "$1"
        say "failed to write $q/$1/cmd"
        exit 0
    }
    [ "$kind" = tmux ] || printf 'plain\n' >"$1/kind"
    if [ "$a" = submit ]; then
        printf 'queued\n' >"$1/state"
        [ "$2" = - ] || printf '%s\n' "$2" >slots
        runner_up "$kind"
        say "queued ${1#*-}"
    elif launch "$1"; then
        say "started ${1#*-}"
    elif [ "$kind" = plain ]; then
        rm -rf "$1"
        say "failed the runner of the job did not start"
    else
        rm -rf "$1"
        say "failed tmux did not start the job"
    fi
    ;;
job)
    # In tmux: the command, then its status, under a new name first so that
    # a reader never sees half of it.
    d=$q/$1
    c=$(cat "$d/cmd") || exit 1
    cd || exit 1
    sh -c "$c" </dev/null >"$d/out" 2>&1
    s=$?
    printf '%s\n' "$s" >"$d/status.part" && mv -f "$d/status.part" "$d/status"
    printf 'done\n' >"$d/state"
    ;;
plain)
    # Under nohup, with no tmux (T-481): far_notmux.sh's runner.
    runplain "$1" "$2"
    ;;
runner)
    # In tmux, or with no tmux ($1 is plain) as a process of its own whose
    # lock is runner.lock: start the oldest queued job while fewer jobs run
    # than the slots; end when nothing is queued and nothing runs.
    r=${1:-tmux}
    [ "$r" = tmux ] || lock || exit 0
    while :; do
        scan
        if [ -n "$next" ] && [ "$busy" -lt "$k" ]; then
            launch "$next" || unstarted "$next"
            continue
        fi
        if [ -z "$next" ] && [ "$busy" -eq 0 ]; then
            # Give the lock up first, so that a submit from now on starts a
            # runner of its own; then look once more, and take it back.
            release "$r" || exit 0
            scan
            [ -n "$next" ] || exit 0
            retake "$r" || exit 0
            continue
        fi
        sleep 1
    done
    ;;
list)
    sessions
    waits=
    for d in *-*; do
        [ -f "$d/cmd" ] || continue
        s=-
        [ -f "$d/status" ] && s=$(cat "$d/status")
        st=$(state_of "$d")
        [ "$st" = queued ] && [ -z "$waits" ] && waits=$(kind_of "$d")
        printf 'job\t%s\t%s\t%s\t%s\n' "$d" "$st" "$s" "$(cat "$d/cmd")"
    done
    # A queue with no runner, after a restart of tmux's server or of the
    # host, gets one, of the kind of its oldest job.
    [ -z "$waits" ] || runner_up "$waits"
    say end
    ;;
state)
    d=$(dir_of "$1") || {
        say "no-job $1"
        exit 0
    }
    sessions
    st=$(state_of "$d")
    s=-
    [ -f "$d/status" ] && s=$(cat "$d/status")
    [ "$st" = queued ] && runner_up "$(kind_of "$d")"
    say "state $st $s"
    ;;
log)
    d=$(dir_of "$1") || {
        say "no-job $1"
        exit 0
    }
    if [ -f "$d/out" ]; then
        say out
        cat "$d/out"
    else
        sessions
        say "no-out $(state_of "$d")"
    fi
    ;;
follow)
    # The output from the byte $2, or from its end now ($2 is end) (T-485):
    # `out N`, N the offset where the bytes start, then each byte that
    # comes, read each second with tail into a file of the job's directory
    # and counted with wc, so that each byte goes once. The call ends once
    # the status is there and nothing more came, once the job is lost, or
    # after 20 s, so that the client's wait for each piece of an answer
    # never ends a call on a link that lives.
    d=$(dir_of "$1") || {
        say "no-job $1"
        exit 0
    }
    need tail wc sleep cat rm
    n=$2
    if [ "$n" = end ]; then
        n=0
        [ -f "$d/out" ] && n=$(size "$d/out")
    fi
    case $n in
    '' | *[!0-9]*)
        say "unknown follow $2"
        exit 0
        ;;
    esac
    say "out $n"
    p=$d/follow.$$
    t=0
    while [ "$t" -lt 20 ]; do
        ended=
        [ -f "$d/status" ] && ended=yes
        g=0
        if [ -f "$d/out" ]; then
            tail -c "+$((n + 1))" "$d/out" >"$p" 2>/dev/null
            g=$(size "$p")
            [ "$g" -eq 0 ] || cat "$p"
            n=$((n + g))
        fi
        if [ "$g" -gt 0 ]; then
            # The output is whole once the status is there: read on at once.
            [ -z "$ended" ] || continue
        else
            [ -z "$ended" ] || break
            sessions
            [ "$(state_of "$d")" != lost ] || break
        fi
        t=$((t + 1))
        sleep 1
    done
    rm -f "$p"
    ;;
files)
    # The job's directory and state, then each file that the pattern $2
    # names in the home directory: a word of it with no match stays as it
    # is, and is no file.
    d=$(dir_of "$1") || {
        say "no-job $1"
        exit 0
    }
    sessions
    say "dir $d $(state_of "$d")"
    if [ "$2" != - ] && cd; then
        # shellcheck disable=SC2086 # the pattern's words and globs
        for f in $2; do
            [ -f "$f" ] && say "file $f"
        done
    fi
    say end
    ;;
stop)
    d=$(dir_of "$1") || {
        say "no-job $1"
        exit 0
    }
    # The session of this job only: = asks tmux for that exact name, where
    # a bare name would also match a longer one.
    w=removed
    if [ "$(kind_of "$d")" = plain ]; then
        # With no tmux (T-481), no signal from here: the file stop asks the
        # runner, which alone signals the command, and the status is waited
        # for. A job that still runs then keeps its directory.
        if [ ! -f "$d/status" ]; then
            : >"$d/stop"
            if [ "$(cat "$d/state" 2>/dev/null)" != queued ]; then
                halt "$d" || {
                    say "stuck $1"
                    exit 0
                }
                w=lost
                [ -f "$d/status" ] && w=stopped
            fi
        fi
    elif command -v tmux >/dev/null 2>&1 && tmux kill-session -t "=$(sess "$d")" 2>/dev/null; then
        w=stopped
    fi
    rm -rf "$d" || {
        say "failed to remove $q/$d"
        exit 0
    }
    say "$w $1"
    ;;
*)
    say "unknown $a"
    ;;
esac
