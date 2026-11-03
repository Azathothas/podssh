# The far side of `podssh job`, first part (T-481): what can install a
# missing tmux, and the jobs with no tmux that `--no-tmux` asks for. podssh
# sends this file, then far.sh, as one script, which the host keeps as
# ~/.podssh/jobs/jobs.sh; here are functions only, which the actions of
# far.sh call.
#
# A job with no tmux has the file kind (plain) in its directory. Its runner
# (`jobs.sh - plain NAME lead|alone`) runs under nohup, in a session of its
# own where setsid is there, and is the parent of the job's command: it
# alone signals it. It writes its PID to pid; the PID of $! stands in
# pid.start until it has. A stop is the file stop, which the runner reads;
# no call signals a PID that it read from a file, as the system may have
# given that PID to another process since.

# What can install a missing tool: the first package manager on PATH, the
# ID= of /etc/os-release, and who may install (root; own, a login that owns
# the manager's file; sudo, one that is not root and has sudo; or user),
# each - when unknown. podssh names the command of them and runs none
# (crates/podssh-cli/src/install_hint.rs, whose table of the managers is
# this list, in this order).
hint() {
    pm=-
    for p in apk apt-get dnf yum zypper pacman brew pkg; do
        if command -v "$p" >/dev/null 2>&1; then
            pm=$p
            break
        fi
    done
    os=-
    if [ -r /etc/os-release ]; then
        while IFS= read -r l; do
            case $l in
            ID=*) os=${l#ID=} ;;
            esac
        done </etc/os-release
    fi
    u=
    command -v id >/dev/null 2>&1 && u=$(id -u 2>/dev/null)
    # With no id, the effective UID that the kernel gives the shell itself.
    if [ -z "$u" ] && [ -r /proc/self/status ]; then
        while read -r f _ y _; do
            [ "$f" = Uid: ] && u=$y
        done </proc/self/status
    fi
    w=user
    if [ "$u" = 0 ]; then
        w=root
    elif [ "$pm" != - ] && [ -O "$(command -v "$pm")" ] 2>/dev/null; then
        w=own
    elif command -v sudo >/dev/null 2>&1; then
        w=sudo
    fi
    printf '%s %s %s' "$pm" "$os" "$w"
}

# The kind of the job of directory $1: plain, with no tmux, or tmux.
kind_of() {
    if [ "$(cat "$1/kind" 2>/dev/null)" = plain ]; then
        printf plain
    else
        printf tmux
    fi
}

# Write the value $3 to the file $2 of directory $1 under a new name first,
# so that a reader never sees half of it.
put() {
    printf '%s\n' "$3" >"$1/$2.part" && mv -f "$1/$2.part" "$1/$2"
}

# Whether PID $1 runs, and where /proc shows its command line, runs this
# script: a PID that the system gave to another process since is no
# runner of a job. NUL bytes of the command line are dropped, and bash's
# word of them goes nowhere.
mine() {
    case $1 in
    '' | *[!0-9]*) return 1 ;;
    esac
    kill -0 "$1" 2>/dev/null || return 1
    [ -r "/proc/$1/cmdline" ] || return 0
    { cl=$(cat "/proc/$1/cmdline"); } 2>/dev/null
    case $cl in
    *jobs.sh*) return 0 ;;
    esac
    return 1
}

# Whether the job of directory $1 runs: with no tmux while its runner does;
# else while its tmux session is in $live.
runs() {
    if [ "$(kind_of "$1")" = plain ]; then
        p=$(cat "$1/pid" 2>/dev/null) || p=$(cat "$1/pid.start" 2>/dev/null)
        mine "$p"
    else
        alive "$(sess "$1")"
    fi
}

# Run the words in the background under nohup, away from the call's
# channel: no input, the output to the null device, and a session of their
# own where setsid is there, so that a server which ends the call's process
# group at its end ends none of them.
away() {
    if command -v setsid >/dev/null 2>&1; then
        nohup setsid "$@" </dev/null >/dev/null 2>&1 &
    else
        nohup "$@" </dev/null >/dev/null 2>&1 &
    fi
}

# Start the job of directory $1 with no tmux: its runner, told whether
# setsid made it the leader of its process group.
loose() {
    printf 'plain\n' >"$1/kind" || return 1
    printf 'running\n' >"$1/state" || return 1
    lw=alone
    command -v setsid >/dev/null 2>&1 && lw=lead
    away sh "$q/jobs.sh" - plain "$1" "$lw"
    put "$1" pid.start "$!"
}

# Whether this shell leads its process group, as /proc shows it: the group
# is the third field of stat after the name in parentheses.
leads() {
    [ -r "/proc/$$/stat" ] || return 1
    read -r st <"/proc/$$/stat" || return 1
    st=${st##*") "}
    # shellcheck disable=SC2086 # the fields of stat
    set -- $st
    [ "$3" = "$$" ]
}

# The runner of the job of directory $1 with no tmux ($2: lead when setsid
# started it). It starts the command in sh, in the home directory, keeps
# its PID, and waits; each second a watcher of its own asks it (USR1) to
# look for the file stop. Then TERM goes to its process group where it
# leads it, its own TERM ignored, else to the command alone; KILL to the
# command 10 s later. The command is its child, which it has not waited
# for, so no other process can have its PID. The status goes to the file
# status at the end, under a new name first.
runplain() {
    d=$q/$1
    c=$(cat "$d/cmd") || exit 1
    put "$d" pid "$$"
    g=
    [ "$2" = lead ] && leads && g=yes
    # A stop that came before the start: nothing runs.
    [ -f "$d/stop" ] && exit 0
    cd || exit 1
    asked=
    trap 'asked=1' USR1
    sh -c "$c" </dev/null >"$d/out" 2>&1 &
    kid=$!
    r=$$
    # The watcher ends with the runner, or with the job's directory, as a
    # runner killed from outside may stay a zombie where nothing reaps it.
    (
        trap '' TERM
        while kill -0 "$r" 2>/dev/null && [ -d "$d" ]; do
            sleep 1
            [ -f "$d/stop" ] && kill -USR1 "$r" 2>/dev/null
        done
    ) </dev/null >/dev/null 2>&1 &
    tick=$!
    n=-1
    while :; do
        asked=
        wait "$kid"
        s=$?
        [ -n "$asked" ] || break
        # A command that ended as the stop came gets no signal.
        kill -0 "$kid" 2>/dev/null || break
        if [ "$n" -lt 0 ]; then
            if [ -n "$g" ]; then
                trap '' TERM
                kill -TERM 0 2>/dev/null
            else
                kill -TERM "$kid" 2>/dev/null
            fi
        elif [ "$n" -ge 10 ]; then
            kill -KILL "$kid" 2>/dev/null
        fi
        n=$((n + 1))
    done
    kill -KILL "$tick" 2>/dev/null
    put "$d" status "$s"
    printf 'done\n' >"$d/state"
}

# Wait for the status of the job of directory $1 with no tmux, once its
# stop is asked: 15 s while its runner runs, 5 s while none does (it is
# lost, and nothing can end its command); 1 when it still runs at the end.
halt() {
    n=0
    while [ ! -f "$1/status" ]; do
        if runs "$1"; then
            [ "$n" -lt 15 ] || return 1
        elif [ "$n" -ge 5 ]; then
            return 0
        fi
        sleep 1
        n=$((n + 1))
    done
    return 0
}

# Whether a runner of the queue with no tmux holds its lock, the directory
# runner.lock with the runner's PID; one whose PID is not written yet is
# held, as mkdir made it a moment ago.
held() {
    [ -d runner.lock ] || return 1
    p=$(cat runner.lock/pid 2>/dev/null)
    [ -z "$p" ] || mine "$p"
}

# Take the lock of the runner with no tmux: mkdir makes the directory at
# once or not at all; a lock whose runner is gone is taken over.
lock() {
    if ! mkdir runner.lock 2>/dev/null; then
        held && return 1
        rm -rf runner.lock
        mkdir runner.lock 2>/dev/null || return 1
    fi
    printf '%s\n' "$$" >runner.lock/pid
}

# The runner of the queue gives its lock up ($1 its kind), so that a submit
# from now on starts a runner of its own; retake takes it back.
release() {
    if [ "$1" = plain ]; then
        rm -rf runner.lock
    else
        tmux rename-session -t =podssh-runner "podssh-runner-$$" 2>/dev/null
    fi
}

retake() {
    if [ "$1" = plain ]; then
        lock
    else
        tmux rename-session -t "=podssh-runner-$$" podssh-runner 2>/dev/null
    fi
}
