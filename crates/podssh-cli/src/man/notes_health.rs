//! The notes of `podssh health` (T-189), apart from the others so that each
//! file stays short.

pub const HEALTH: &[&str] = &[
    "podssh health logs in to one host as podssh ssh does (the relay or --direct, ssh_config, -J, -i), and \
     runs one command there that only reads: a fixed script, as sh -c, so that a login shell of fish or csh \
     only starts sh. No text of yours goes into it. It reads the files loadavg, uptime, meminfo, stat and \
     net/dev of /proc with the read of the shell, counts the processes, and runs sleep, df and uname only \
     where command -v finds them.",
    "One line for each fact: the load of 1, 5 and 15 minutes and the CPUs; the busy share of the CPUs over \
     one second; the memory available (MemAvailable of the kernel, else an estimate from the free memory, the \
     buffers and the cache, which the line names) and the swap used; the uptime; for each network interface \
     but the loopback, the bytes in and out since the start and over one second; the use of the file system \
     of the root and of the home, from df; the processes. A host with no sleep gives no rate and no busy \
     share; one with no df, no disk.",
    "A host with no /proc gives the name that uname prints, and no facts for this system, with exit 0. A \
     host with no sh, a login that fails, and an answer with none of the script's lines give exit 255, as \
     podssh ssh gives it. A name that the host gives (an interface, a mount) has the controls of a terminal \
     taken out.",
    "With --json, one JSON object on stdout, also after a failure: schema (1), podssh, destination, system \
     (for a host with no /proc), load, cpus, the busy percent and the seconds between the samples, memory \
     (in KiB, and whether the available memory is an estimate), the uptime in seconds, network (each \
     interface, its bytes and its bytes in a second), disks (each mount, its file system and its KiB), \
     processes, error and exit.",
];
