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
     temporary name, verified by its digest, then renamed. So the next run sends only the files whose \
     size or time of change differs from the far file's. target/, node_modules/ and .git/ never go, at any \
     depth, nor what the project's .podsshignore (a pattern a line, as the file of --exclude-from), \
     --exclude and --exclude-from leave out. Nothing on the host is removed. With -v, podssh says how \
     many files it sent, and how many were as they are here.",
    "The command runs as cd DIR && COMMAND in the login shell, with stdin, as podssh ssh runs one. When \
     the copy used most of what the relay carries in one session, the command runs on a new session. A \
     copy that failed exits 255 and runs nothing; else the exit status is the command's, with the rules \
     of podssh ssh.",
];
