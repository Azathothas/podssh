//! The notes of `podssh each` (T-183), apart from the others so that each
//! file stays short.

pub const EACH: &[&str] = &[
    "podssh each HOSTS -- COMMAND runs one command on each host of a comma list, [user@]host[:port],..., \
     through the relay or with --direct, with the connection flags of podssh ssh: -p and -l for each host \
     that names none, -i, -o, -F and -J; the Host blocks of ssh_config apply to each host as podssh ssh \
     applies them. Each host is checked before anything connects: a bad one exits 64, and nothing has run \
     anywhere. A host named twice runs once.",
    "An item of the list takes the braces of bash: web{1..3} is web1, web2 and web3, {01..12} keeps its \
     zero padding, {a..c} gives letters, {1..9..2} a step, a{b,c}d is abd and acd, and braces nest. @NAME \
     is the group NAME of the settings file (see FILES): after a line [groups], each line is NAME HOSTS, \
     whose hosts are a list of the same kind and can name groups. 1000 hosts at most; more, none, an \
     empty host, a range that runs backwards or a group that is not there is a usage error (64), and a \
     group that names itself, through others or not, is refused with the file (78). Square brackets stay \
     an IPv6 address. podssh ssh takes a pattern of one host, and refuses one of more, naming podssh each.",
    "At most --parallel hosts run at once (8; 1 to 64), each on a connection of its own. No host gets a \
     terminal or stdin: each session is as podssh ssh -T -n makes it. Nothing asks a question: BatchMode is \
     on, and an unknown host key refuses its host and names its fingerprint and -o \
     StrictHostKeyChecking=accept-new, which records each new key. Through the relay, one token serves \
     each host.",
    "Each line of a host's output starts with HOST: , on stdout or stderr as the host wrote it, and \
     podssh's own messages about a host start with podssh: HOST: . A line is never cut by another host's; \
     one longer than 64 KiB comes in pieces, each with its host. With --output-dir DIR, the bytes go \
     unchanged into DIR/HOST.out and DIR/HOST.err, and the exit status into DIR/HOST.status at the host's \
     end; each byte of HOST but a letter, a digit, a dot, an underscore, a hyphen and @ is written %XX. \
     The files are made before anything connects (73 when they cannot be), and a host with no status \
     file did not run.",
    "--snippet NAME runs the command NAME of the settings file on each host, as podssh ssh --snippet runs \
     it (see podssh ssh): the words after HOSTS fill {{1}} to {{9}}, and {{host}}, {{user}} and {{port}} \
     are those of each host. podssh shows each host and its command once, before anything connects and \
     before a file of --output-dir is made, and asks once for all the hosts; --yes runs them with no \
     question.",
    "At the end a summary on stderr gives each host and its status; -q leaves it out. The exit status is \
     the largest of the hosts': 0 only when each host gave 0, and 255 when one could not connect or log \
     in. With --fail-fast no host starts after one failed, and the hosts that run end as they end.",
    "podssh each --interactive HOSTS (T-185) opens a shell with no pty on each host, 64 hosts at most, and \
     each line typed goes to the hosts of the selection, at first each host; the output of each comes as \
     HOST: LINE. The terminal keeps its normal mode, so that its own line discipline edits the line. A line \
     that starts with : is for podssh: :all, :none, :only HOST... (braces and @GROUP as in HOSTS, and USER@ \
     may be left out), :list, :intr (signal INT to each selected host, which a server may ignore) and \
     :help; a line that starts with :: goes to the hosts with one : less. With --confirm, a line for more \
     than one host waits for a second Enter, and another line drops it. A COMMAND, --parallel, --fail-fast \
     and --output-dir are refused (64).",
    "The emergency stop is Ctrl-\\ (SIGQUIT) on Unix and Ctrl-Break on Windows: at once, also while a line \
     is half typed, no host is selected, and each byte that waits for a host is dropped; podssh says \
     broadcast stopped; :all starts it again. On Unix, --stop-key ^X makes another control key the stop \
     for the run, as the terminal's QUIT character, and puts the old one back at the end; a key that the \
     terminal keeps for INTR, EOF, SUSP, ERASE, KILL or the end of a line is refused (64), and so is the \
     flag on Windows. It is armed before anything connects, and where it cannot \
     be, podssh exits 78. Each host has a queue of 64 KiB, what its shell has not read yet: a line that \
     does not fit does not go to that host, which leaves the selection, and podssh names it. Ctrl-C goes \
     to no host. At the end of the input (Ctrl-D, or Ctrl-Z on Windows), each shell reads what waits for \
     it, then its end; Ctrl-C then cuts the hosts whose shell still runs, each with 130.",
];
