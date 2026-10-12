//! The notes of `podssh edit` (T-149), apart from the others so that each
//! file stays short.

pub const EDIT: &[&str] = &[
    "podssh edit [user@]host:path fetches one file of a server as podssh cp copies one down: over SFTP, or \
     by exec when the server has no SFTP, through the relay or with --direct, with the connection flags of \
     podssh ssh and -P for the port. The copy goes into a new directory of mode 0700 in the cache (see FILES), \
     as a file of mode 0600 with the far file's name, so that the editor knows its kind. Then the connection \
     closes, and the editor runs here, with no time limit: no relay session waits while a person edits.",
    "The editor is VISUAL, else EDITOR, else vi when PATH has it; with none, podssh edit exits 78 and names \
     EDITOR. A value is a program and its words, split at blanks with no shell, or one program whose path has \
     a blank. podssh edit needs a terminal on stdin and stdout (else 64). While the editor runs, SIGINT and \
     SIGQUIT are the editor's, and on Windows so is Ctrl-C.",
    "A copy with no change sends nothing (exit 0). Else a new connection, which logs in as the first did with \
     no second question, compares the far file with what came: its size and its time of change, and its \
     SHA-256. When the far file changed, nothing is sent, and the exit is 73. Else the copy goes up as podssh \
     cp sends one: a temporary name, the digests, the far file's mode, then the rename.",
    "After a success the copy here goes. After a failure it stays, and podssh names it, when it holds a \
     change; a copy with no change goes. An editor that ends with a status other than 0 sends nothing, and \
     podssh edit exits with that status. A symbolic link stays a link: over SFTP podssh edits the file that it \
     names; by exec, where no portable command names that file, a link is refused (66). The first SIGINT or \
     SIGTERM while a file moves ends the run with 130: during the fetch nothing stays here; during the send \
     the copy here stays, named.",
];
