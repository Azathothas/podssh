//! The notes of `podssh containers` (T-190), apart from the others so that
//! each file stays short.

pub const CONTAINERS: &[&str] = &[
    "podssh containers HOST logs in to HOST as podssh ssh does, through the relay or with --direct, with \
     the connection flags of podssh ssh: -p, -l, -i, -o, -F and -J. One command, with no pty, runs sh there: \
     sh looks for docker, podman and kubectl on its PATH, and lists the containers that each one has: \
     the names of docker ps and of podman ps, and the pods of kubectl in its current context and \
     namespace, which kubectl waits 20 s at most for. --tool asks one of them alone. No program runs \
     here, and none runs there that sh did not find. The list waits 60 s at most.",
    "Each line on stdout gives the tool, the name, and the podssh ssh command that enters that \
     container with its sh and a pty, with the connection flags that were given. A name has letters, \
     digits, underscores, dots and hyphens alone, with a letter or a digit first (and pod/ first for kubectl), so that \
     each shell reads it as one word: a name of another form is left out and named on stderr. A tool \
     that fails (no access to the socket of docker, a cluster that does not answer) gives its lines \
     on stderr, and the other tools go on.",
    "--exec NAME enters NAME on the same connection after the list, so that a password is asked once: \
     the tool that lists it runs its exec there, with the program of --shell (sh by default). The \
     session has a pty when this side has a terminal, or with -tt, and the tool then gets -i and -t; \
     with no pty, -i alone. When docker and podman each list NAME, the first in the order docker, \
     podman, kubectl is entered, and --tool enters another. For kubectl, NAME may leave out pod/.",
    "The exit status: 0 when each tool gave its whole list; 65 when a tool listed a name that is left \
     out; 69 when the host has none of the tools, one of them failed, sh did not run the list to its \
     end, or --exec names no container that a list has; 255 when the connection or the login failed. \
     With --exec, the status of the session, as podssh ssh gives it. A node:// or iroh: destination is \
     for podssh ssh (64), and the forwards, X11 and the control socket of ssh_config are not used.",
];
