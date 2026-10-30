# The far side of `podssh job` (T-193). podssh sends this POSIX sh script
# with each call and keeps it as ~/.podssh/jobs/jobs.sh, where tmux runs it
# for each job: nothing of podssh runs on the host but this file, under sh,
# with tmux and the tools that it probes. Each job is a directory beside it,
# named MILLIS-ID (the time of the start in milliseconds, then 8 hex
# digits): its command (cmd), its state (state), its output and its errors
# (out), and its exit status (status) once it ended.
#
# sh jobs.sh MARKER ACTION ARG...: MARKER on a line, then the answer, which
# crates/podssh-cli/src/job/far.rs reads. A MARKER of - prints none: tmux
# runs `jobs.sh - job NAME` for a job.

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

# The state of the job of directory $1: done (its status is there), running
# (its session is), or lost (neither: the host or tmux's server stopped).
state_of() {
    if [ -f "$1/status" ]; then
        printf done
    elif alive "$(sess "$1")"; then
        printf running
    else
        printf lost
    fi
}

# Start the job of directory $1 in tmux. Its command runs in sh, in the home
# directory; the path goes in single quotes to tmux's shell, the login's.
launch() {
    printf 'running\n' >"$1/state" &&
        tmux new-session -d -s "$(sess "$1")" "exec sh '$q/jobs.sh' - job '$1'" </dev/null
}

case $a in
start)
    need mkdir cat mv rm tmux
    case $q in
    *\'* | *!*)
        say "odd-path $q"
        exit 0
        ;;
    esac
    mkdir "$1" || {
        say "failed to make $q/$1"
        exit 0
    }
    if printf '%s\n' "$2" >"$1/cmd" && launch "$1"; then
        say "started ${1#*-}"
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
list)
    sessions
    for d in *-*; do
        [ -f "$d/cmd" ] || continue
        s=-
        [ -f "$d/status" ] && s=$(cat "$d/status")
        printf 'job\t%s\t%s\t%s\t%s\n' "$d" "$(state_of "$d")" "$s" "$(cat "$d/cmd")"
    done
    say end
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
stop)
    d=$(dir_of "$1") || {
        say "no-job $1"
        exit 0
    }
    # The session of this job only: = asks tmux for that exact name, where
    # a bare name would also match a longer one.
    w=removed
    if command -v tmux >/dev/null 2>&1 && tmux kill-session -t "=$(sess "$d")" 2>/dev/null; then
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
