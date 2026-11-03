//! The notes of `podssh health` (T-189, T-480, T-482), apart from the others
//! so that each file stays short.

pub const HEALTH: &[&str] = &[
    "podssh health logs in to one host as podssh ssh does (the relay or --direct, ssh_config, -J, -i), and \
     runs one command there that only reads: a fixed script, as sh -c, so that a login shell of fish or csh \
     only starts sh. No text of yours goes into it. It reads the files loadavg, uptime, meminfo, stat and \
     net/dev of /proc with the read of the shell, counts the processes, reads the cgroup of its own shell \
     (/proc/self/cgroup, then the files of that cgroup under /sys/fs/cgroup, each only where it can be read), \
     and runs sleep, df and uname only where command -v finds them.",
    "One line for each fact: the load of 1, 5 and 15 minutes and the CPUs; the busy share of the CPUs over \
     one second; the memory available (MemAvailable of the kernel, else an estimate from the free memory, the \
     buffers and the cache, which the line names) and the swap used; the uptime; for each network interface \
     but the loopback, the bytes in and out since the start and over one second; the use of the file system \
     of the root and of the home, from df; the processes. A host with no sleep gives no rate and no busy \
     share; one with no df, no disk.",
    "CONTAINERS: /proc gives the whole host's CPUs, memory and load, also inside a container. Where the \
     cgroup of the far shell limits them, under cgroup v2 or v1, health gives the cgroup's beside the host's: \
     cpus N (SOURCE), M on the host, the least of the quota over its period (cpu.max, or cpu.cfs_quota_us of \
     v1), the CPUs of the effective cpuset, and the host's; the memory available of the limit (memory.max, \
     or memory.limit_in_bytes of v1), which is the limit less the working set (the use less the inactive \
     file cache, as docker stats counts it), never more than the host's MemAvailable, then the host's; and \
     the load line says that it is the whole host's. A limit of a parent cgroup binds as the cgroup's own \
     does. The cgroup's share of its CPUs over the second, the periods in which it was throttled, its \
     pressure (PSI: the share of the last 10 s that its tasks waited), and an io.max or a pids.max that \
     limits get their lines too. A cgroup with no limit, a limit at or above the host's (LXCFS), or a host \
     that hides /sys/fs/cgroup gives the host's facts, as before.",
    "A host with no /proc gives the name that uname prints, and no facts for this system, with exit 0. A \
     host with no sh, a login that fails, and an answer with none of the script's lines give exit 255, as \
     podssh ssh gives it. A name that the host gives (an interface, a mount) has the controls of a terminal \
     taken out.",
    "With --json, one JSON object on stdout, also after a failure: schema (1), podssh, destination, system \
     (for a host with no /proc), load, cpus, the busy percent and the seconds between the samples, memory \
     (in KiB, and whether the available memory is an estimate), the uptime in seconds, network (each \
     interface, its bytes and its bytes in a second), disks (each mount, its file system and its KiB), \
     processes, error and exit. Each of these is the host's. effective holds the facts to plan from, on any \
     host: cpus (a number, as 4.0 or 1.5), cpus_from (cgroup v2 cpu.max, cgroup v2 cpu.max of a parent, \
     cgroup v2 cpuset, cgroup v1 cfs_quota_us, cgroup v1 cpuset or host), memory_total_kib, \
     memory_available_kib, memory_from, and the cgroup's cpu_used, cpu_busy_percent, throttled_periods and \
     periods. cgroup, where one was read, holds its version, its path, and each value as it was read.",
    "PREFLIGHT: with --preflight, after the facts, the same login asks what the server allows of what a long \
     command needs later, each probe in 10 s at most, in lines as podssh doctor gives them: ok, FAIL or ????, \
     a name, and what came. login: the user, the hops of -J, the method that let the user in, and the \
     server's version line. road: the relay's limits on a session (64 MiB both ways, 180 s with no payload, \
     12 h, from its /relays.json where one was read), or none with --direct. sftp: the subsystem, its sizes \
     and its extensions, and what podssh cp does without copy-data, posix-rename@openssh.com, \
     hardlink@openssh.com and limits@openssh.com; no subsystem is ok, as podssh cp then copies by exec. \
     remote forward: a tcpip-forward on the server's loopback, on a port that the server chooses, then its \
     cancel at once; a refusal, or no answer, is FAIL, as -R cannot work there. jump: a direct-tcpip channel \
     to the server's own loopback, port 22, closed at once; one that opens, or one refused as connect failed, \
     is ok; administratively prohibited, an unknown channel type, or no answer is FAIL, as -J, -L, -D and -W \
     through that host cannot work.",
    "exec tools: one exec of sh names each tool on PATH that the copy by exec, podssh job, podssh cp --delta \
     and podssh ping use; a missing cat, mv, rm, mkdir, sleep or wc is FAIL, and each other missing tool is \
     named with what it stops. A host whose login runs no sh fails it. tmux: from the same exec; a missing \
     tmux is FAIL, with what could install it, as podssh job names it, and podssh job --no-tmux. cgroup: the \
     CPUs and the memory to plan from, from the facts. keepalive, last: one keepalive@openssh.com with a \
     reply wanted; a reply, a success or a failure, is ok; no reply, or a connection that ends at it, is \
     FAIL, and -o ServerAliveInterval=0 is the way round it. Nothing that a probe asks stays: the forward is \
     cancelled, and the channel and the SFTP session are closed, at once.",
    "With --preflight, once the login is done, the exit is that of podssh doctor: 1 when a check failed or \
     the facts did not come, else 0. A login that fails is 255, as without it, and its line is FAIL. With \
     --json, preflight holds checks, each with section, check, status and detail as podssh doctor --json \
     gives them, and counts (ok, fail and unknown); without --preflight it is null.",
];
