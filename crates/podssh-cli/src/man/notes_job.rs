//! The notes of `podssh job` (T-193), apart from the others so that each
//! file stays short.

pub const JOB: &[&str] = &[
    "podssh job start HOST -- COMMAND starts the command on the host in a tmux session of its own, \
     podssh-job-ID, and prints the ID on stdout: 8 hex digits. The job runs on after the connection ends. \
     The command runs in sh, in the home directory, with no input; its output and its errors go to a file. \
     The host is reached as podssh ssh reaches it, with its connection flags and the Host blocks of \
     ssh_config, through the relay or with --direct.",
    "Nothing of podssh runs on the host but a POSIX sh script, which each call sends and keeps as \
     ~/.podssh/jobs/jobs.sh. Each job is a directory beside it, of mode 0700, with its command, its state, \
     its output and its exit status. tmux is probed, never assumed: with no tmux on PATH, start exits 255 \
     and names it, and nothing starts.",
    "podssh job list HOST prints a line for each job, in the order of their starts: the ID, the state \
     (running; done; or lost, when neither the job's session nor its status is there, as after a restart \
     of the host), the exit status (a dash while there is none) and the command. podssh job log HOST ID \
     writes the job's output to stdout, also after its end. podssh job stop HOST ID ends the tmux session \
     of that exact name, never another, and removes the job's directory with its output.",
    "The exit status is that of podssh ssh: 0; 64 for a usage error and 78 for a setting, before anything \
     connects; 255 when the host cannot be reached or logged in to, has no tmux, has no such job, or gives \
     no answer.",
];
