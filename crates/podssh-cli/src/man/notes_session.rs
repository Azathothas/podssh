//! The notes of `podssh session` (T-186), apart from the others so that
//! each file stays short.

pub const SESSION: &[&str] = &[
    "podssh session start NAME [OPTIONS] HOST [COMMAND] starts a podssh of its own in the background, which logs \
     in to HOST as podssh ssh does, with its connection flags and the Host blocks of ssh_config, and holds one \
     session with a pty: the login shell, or COMMAND. start returns once the session is ready, with the path of \
     its socket on stdout; what the session's podssh says until then comes on stderr, and its exit code is \
     start's when it ends first (255 for a connection or a login that failed). The pty's size is that of \
     COLUMNS and LINES, else 80 by 24. A prompt opens no terminal: a key's passphrase comes from podssh agent or \
     SSH_ASKPASS, and a new host key needs StrictHostKeyChecking=accept-new or a known_hosts that has it.",
    "send NAME TEXT types TEXT and Enter (a carriage return; --no-enter leaves it out). In TEXT, \\r, \\n, \\t, \
     \\e (Escape), \\xNN (\\x03 is Ctrl-C) and \\\\ give the bytes they name; each other \\ is refused. send NAME \
     with no TEXT types stdin as it is: a password goes so, never in a command line, which each process can \
     read.",
    "wait NAME returns when the output has stopped for --idle (2s by default), counted from the last send, so \
     that a wait right after a send waits for what it brings; output that stops inside an escape sequence has \
     not stopped. With --match TEXT it returns when TEXT comes in the output since the last send, with the \
     terminal's sequences and control bytes taken out; the echo of the line that send typed counts too, so \
     match a text that only the command's output holds. It says idle or match on stdout, and exits 75 when \
     --timeout (60s) passes first, 69 when the session ended first.",
    "capture NAME writes the screen as a terminal of the pty's size shows it: its rows, with no blank at their \
     ends and no empty row at the end. --raw writes the last 64 KiB of the output as it came, from a place \
     where a terminal can start to read it, never inside a sequence or a character. stop NAME ends the session \
     and its podssh. list writes a line for each session that answers: its name, running or ended and the \
     status, and its host, with a tab between them.",
    "The session's podssh ends at stop, a minute after its session ended (so that the last screen can still \
     be read), after an hour with no request, or at SIGINT, SIGTERM or SIGHUP. serve NAME [OPTIONS] HOST is \
     that podssh in the foreground, for a program that keeps it itself: it writes one line of JSON on stdout \
     when it is ready, and its messages on stderr; with --detach it writes nothing more after that line, as \
     start runs it.",
    "THE SOCKET: start and serve listen on a socket of this user's: NAME.sock in the directory sessions of the \
     cache (see FILES), made mode 0700, the socket mode 0600; on Windows an AF_UNIX socket there, whose \
     clients must run as this user. --socket PATH names another, also \\\\.\\pipe\\NAME on Windows, and @NAME \
     on Linux, which has no file. A client of another user is closed before it is read. No TCP: a request \
     types into a shell. The bind is the probe: where this host refuses it, start exits 77 with the reason; \
     PODSSH_LISTEN set to no refuses start and serve before any bind (78), and so does PODSSH_CACHE_DIR set to \
     none with no --socket.",
    "THE RISK: each program that runs as you can type into the session and read its screen, as it can with \
     your keys. The socket carries no key, password or token: the session's podssh logs in with what podssh \
     ssh would use. One line of JSON is each request and each answer, with the version first ({\"schema\":1, \
     ...}), for a program that speaks to the socket itself: info, send (text, or bytes in base64), wait \
     (idle_ms, match, timeout_ms), capture (raw) and stop, each with the session's name.",
];
