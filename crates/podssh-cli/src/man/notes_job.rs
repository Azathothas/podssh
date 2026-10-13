//! The notes of `podssh job` (T-193, T-197), apart from the others so that each
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
     (queued; running; done; or lost, when neither the job's session nor its status is there, as after a \
     restart of the host), the exit status (a dash while there is none) and the command. podssh job log HOST ID \
     writes the job's output to stdout, also after its end. podssh job stop HOST ID ends the tmux session \
     of that exact name, never another, and removes the job's directory with its output.",
    "podssh job submit HOST -- COMMAND queues the command on the host and prints its ID; a runner in the \
     host's tmux, podssh-runner, starts the oldest queued job while fewer jobs run there than the slots. \
     --slots N sets the slots, 1 to 64; they stay for the next submits, and are 1 until one sets them. The \
     name of the runner's session is its lock, so that no second runner starts; with nothing queued and \
     nothing running it ends, and the next submit starts one. HOST may be a list, with the braces and the \
     groups of podssh each: one list of each host gives its jobs queued or running, the host with the \
     fewest gets the job (the first of the list on a tie), and stdout gives HOST ID. There is no logic of \
     GPUs and no list of devices: the slots are the only limit.",
    "podssh job wait HOST ID reads the job's state every 5 s, each read a call of its own, and exits with \
     the job's status; after a lost connection it connects again, 5 times in a row at most. With --timeout \
     DURATION, it exits 75 when the job has not ended within DURATION, and the job runs on. podssh job \
     fetch HOST ID [DIR] copies the job's output to DIR/out, as podssh cp copies a file, and with --files \
     GLOB each file of that pattern of sh in the host's home directory to DIR/files, by its path; DIR is \
     ./podssh-job-ID by default. A job that is queued or running is not fetched, as its output is not whole \
     yet (75). podssh job list HOST --json gives one JSON object: the host, and each job with its id, state, \
     status, started_ms and command.",
    "The exit status is that of podssh ssh: 0; 64 for a usage error and 78 for a setting, before anything \
     connects; 255 when the host cannot be reached or logged in to, has no tmux, has no such job, or gives \
     no answer. wait gives the job's status, or 75 at its --timeout.",
];
