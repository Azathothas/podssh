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
     run with its number (exit 65); a file that cannot be read gives 66. The formats of PuTTY, MobaXterm, \
     Remmina, FinalShell, mRemoteNG and Termius, and Ansible's YAML, are refused by name (exit 64) until a \
     real export of each is at hand to test against.",
];
