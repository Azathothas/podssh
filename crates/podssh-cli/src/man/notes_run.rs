//! The notes of `podssh run` (T-192), apart from the others so that each
//! file stays short.

pub const RUN: &[&str] = &[
    "podssh run HOST -- COMMAND copies the project here (the working directory, or --from DIR) to the \
     host, then runs the command in its far directory, on the same connection, and exits with the \
     command's status. The far directory is DIR of HOST:DIR, under the home directory when it is \
     relative; with none, ~/.podssh/run/NAME, NAME the name of the project here. A parent that is not \
     there is made, with mode 0700. The connection flags are those of podssh ssh, and the Host blocks of \
     ssh_config apply.",
    "The copy is that of podssh cp for a directory, over SFTP, with the times kept: each file to a \
     temporary name, verified by its digest, then renamed, several files at once, as podssh cp sends \
     them by default. So the next run sends only the files whose \
     size or time of change differs from the far file's. target/, node_modules/ and .git/ never go, at any \
     depth, nor what the project's .podsshignore (a pattern a line, as the file of --exclude-from), \
     --exclude and --exclude-from leave out; --no-ignore sends the first four too, and --exclude and \
     --exclude-from still apply. Before the command starts, \
     one line on stderr says what the copy did, as podssh cp says it at its end: the files copied, those \
     left as they were, the paths that the excludes left out, and how long it took; -q silences it, and \
     -v names each path left out with its pattern.",
    "Nothing on the host is removed: an exclude leaves a path out of the copy, and what an earlier run \
     sent stays on the host, as podssh run removes no path there. podssh cp -r has no default excludes and \
     reads no .podsshignore: it copies what its command line names, and only --exclude and \
     --exclude-from leave paths out.",
    "--dry-run connects and makes the copy's looks, which only read, then says on stdout each action \
     that the copy would take, as podssh cp -r --dry-run says it, but only for what changed: a mkdir for \
     each directory that is not there, a copy for each file whose size or time differs, a link for each \
     link that is not there as it is here; then the line run cd DIR && COMMAND. Nothing changes on either side \
     and nothing runs; stderr counts the paths that the excludes left out. It exits 0, or 255 when the \
     far side cannot be read, with no plan.",
    "The command runs as cd DIR && COMMAND in the login shell, with stdin, as podssh ssh runs one. When \
     the copy used most of what the relay carries in one session, the command runs on a new session. A \
     copy that failed exits 255 and runs nothing; else the exit status is the command's, with the rules \
     of podssh ssh.",
    "--result-file FILE writes one JSON object to FILE at the end, also of a run refused before it \
     connected: the keys of podssh cp, its verb run, files and transferred of the copy (up alone), and \
     the status, signal, end and bytes of the command as podssh ssh --result-file gives them; bytes is \
     null when the command did not run, as after a copy that failed. - is refused (exit 64), as stdout \
     is the command's.",
];
