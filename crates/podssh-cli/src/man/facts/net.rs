//! The variables of the net (T-429), of the pairing by a short code
//! (T-086), of a service's journal (T-640) and of a node's upgrade in place
//! (T-668), apart from `facts.rs` for the length of that file.

/// Each one: its names, and what it does.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_NET"],
        "The net's document of podssh net (T-429): the absolute path of its file, in place of net.doc in the \
          cache's directory. no: the net is off, so that no member's name, no node's door and no document of the \
          end-to-end channel comes from it, and podssh net refuses (78). Unset, empty or yes: net.doc in the \
          cache; another word, such as a relative path, is a configuration error (78), and the net is off.",
    ),
    (
        &["PODSSH_PAIR_MAILBOX"],
        "The mailboxes of podssh relay pair --code and podssh relay join (T-086), and of podssh net invite and \
          podssh net join (T-616), as --pair-mailbox, which wins: ws:// or wss:// URLs by commas, in order, such as \
          podssh relay serve's wss://HOST/v1/mailbox. Unset, empty or yes: magic-wormhole's public mailbox, then \
          Least Authority's; no: no code, which then refuses (78) with the way left, the operator's file or podssh \
          net add and take; a URL that cannot be read is a configuration error (78), which does not echo it.",
    ),
    (
        &["JOURNAL_STREAM"],
        "Set by systemd for a service whose stderr is the journal: the device and inode of that stream. Where \
          they are those of podssh's own stderr (a program that inherited the variable has another), each error \
          line also goes to the journal's socket beside that stream as one entry, at its priority (3, and 2 for a \
          fatal one), so that journalctl -p warning shows a refusal and why a node ended; each line stays on \
          stderr, at the stream's info, as before. The SSH client's lines go too (T-674): an error at 3, and a \
          warning at 4 (a forward that the server refused, a channel that it opened unasked, a setting that may \
          cut the session), which shows at INFO as in OpenSSH, so -q and -o LogLevel=ERROR hide it; a log in a \
          file (-E) sends nothing. The socket binds nothing, and a send that fails is dropped, never an exit \
          code. No flag turns it on or off (T-640).",
    ),
    (
        &["PODSSH_HANDOVER"],
        "Set by podssh alone, never by hand: between the two binaries of a node's upgrade in place (T-668, see \
          the notes of podssh node), it names the descriptor of the memory that holds the node's sessions and what \
          its roads keep of the run (a key for the run only, a quick tunnel's name, T-679), and the node's pid, \
          so that only that process reads it, never a program that the node starts. probe makes podssh \
          --version add the line podssh-handover and the version of the sessions that this binary takes, \
          which a node reads before it hands its sessions to a binary.",
    ),
];
