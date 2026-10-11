//! The notes of `podssh play` (T-033), apart from the others so that each
//! file stays short.

pub const PLAY: &[&str] = &[
    "podssh play FILE writes the output of a recording again, on stdout, with its timing: a file of podssh \
     ssh --record, or another asciicast v2 file. --speed plays it faster or slower, and --idle-limit cuts each \
     wait to its seconds, as the file's idle_time_limit does when it has one. A file of another version is \
     refused (exit 1), and an event of another kind than output is passed over.",
    "A recording holds what the session showed, its secrets too (a key that was printed, a password that a \
     program echoed), and never what was typed. Played again, its control sequences reach your terminal: play \
     only a file that you trust.",
];
