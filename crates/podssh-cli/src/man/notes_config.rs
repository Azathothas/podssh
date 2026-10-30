//! The notes of `podssh config` (T-047), apart from the others so that each
//! file stays short.

pub const CONFIG: &[&str] = &[
    "podssh config import ansible FILE prints a Host block of ssh_config for each host of an Ansible \
     inventory in its INI form (FILE, or - for stdin), with a summary on stderr; it writes no file, and you \
     add what it printed to ~/.ssh/config. A host's ansible_host, ansible_port, ansible_user and \
     ansible_ssh_private_key_file (or their ansible_ssh_ names) give HostName, Port, User and IdentityFile, \
     combined from all, its groups and its own line as Ansible combines them; host:PORT and ranges such as \
     www[01:03] are read as Ansible reads them.",
    "The -o options of ansible_ssh_common_args and ansible_ssh_extra_args, which Ansible gives to ssh, follow \
     as lines of the block, and -J as ProxyJump; ProxyCommand and the other keywords that run a command, and \
     each other flag, are named in a comment, with no value.",
    "A password or a passphrase (a variable whose name holds pass) is never imported and never printed: the \
     summary counts it. A host whose ansible_connection is not ssh gets a comment and no block. A host \
     name that a Host line cannot hold (a space, *, ?, !, \" or #) is refused by name. A bad line ends the \
     run with its number (exit 65); a file that cannot be read gives 66.",
    "podssh config import putty FILE reads PuTTY's sessions: a .reg file of the registry's key \
     Software\\SimonTatham\\PuTTY\\Sessions (from regedit or reg export, in UTF-16 or UTF-8), or the session \
     files of PuTTY on Unix, a file or its directory. The session Default Settings is PuTTY's template, \
     not a host. user@host in HostName gives User; a key of PuTTY's format (.ppk), which ssh cannot read, \
     is a comment that says how puttygen converts it; an SSH proxy gives ProxyJump; ProxyPassword is \
     counted. Environment, a proxy command and the other proxies are comments with no value.",
    "podssh config import mobaxterm FILE reads MobaXterm's sessions, an .mxtsessions export or the \
     bookmarks of MobaXterm.ini: the SSH sessions, each with its folder in a comment; the gateways give \
     ProxyJump; a command after the login, a proxy and a key path in MobaXterm's own form are comments; \
     each entry of [Passwords] and [Sesspass] is counted. podssh config import remmina FILE reads one \
     profile of Remmina, or each of a directory (~/.local/share/remmina): protocol=SSH makes a block, \
     server gives HostName and Port, name the label and group the folder; each secret, in the keyring or \
     encrypted, is counted; a placeholder of a template such as %Host% is no host.",
    "A session's label becomes the name of its block, each run of characters that a Host line cannot hold \
     made one -, with the label itself in a comment above it; a session of another protocol gets a \
     comment and no block. The formats of FinalShell, mRemoteNG and Termius, and Ansible's YAML, are \
     refused by name (exit 64) until a real export of each is at hand to test against.",
];
