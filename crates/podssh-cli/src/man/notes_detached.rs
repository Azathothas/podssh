//! The notes of `podssh detached` (T-392), apart from the others so that
//! each file stays short.

pub const DETACHED: &[&str] = &[
    "podssh detached list writes a line for each run in the background that this user started with -f or \
     --detach (podssh ssh, pipe and node), by its name: the name, its state (running; running, its supervisor \
     gone, for a run of --restart whose supervisor ended; or ended), its pid and its words, with a tab between \
     them. A run's name is its --detach-name, else its verb and its pid (ssh-4242), which no other running run \
     has, so that a run with no name is never refused.",
    "Each run holds the lock of its name, NAME.lock in the directory detached of the cache (see FILES), from \
     before its connection to its end; with --restart its supervisor holds it, so that each restart keeps it, \
     and the run that it starts holds NAME.run.lock. A second start of a name that runs refuses with 75 before \
     it connects, and names the pid that runs; so does a start of a name whose run of --restart outlived its \
     supervisor. The system lets a lock go when its process ends, however it ends, so a run that crashed \
     leaves no name taken. With PODSSH_CACHE_DIR set to none there is no lock: a line says so, and the run goes \
     on, as a run that never starts locks its server out.",
    "status NAME writes the run's name, state, pid (with --restart, its supervisor's, and its run's on a line of \
     its own), verb, words, log and start, one to a line; it exits 0 when the run runs, 69 when it does not. \
     stop NAME sends SIGTERM to the holder of the name (a supervisor passes it to its run), then after 10 s \
     SIGKILL to each holder still there, the supervisor first; on Windows it ends each at once \
     (TerminateProcess), the supervisor first. It exits 0 once each lock of the name is free, 69 when nothing of \
     that name runs, and 75 when a lock is still held after the kill.",
    "Each reads the locks, never a pid alone: a run's record (NAME.json) stays after it ended, and the system \
     gives its pid to another process, which a signal would reach. A pid is sent a signal only while the lock of \
     its run is held, and it is the pid that the holder wrote there.",
];
