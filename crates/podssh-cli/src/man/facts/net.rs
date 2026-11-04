//! The variables of the net (T-429) and of the pairing by a short code
//! (T-086), apart from `facts.rs` for the length of that file.

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
        "The mailboxes of podssh relay pair --code and podssh relay join (T-086), as --pair-mailbox, which wins: \
          ws:// or wss:// URLs by commas, in order, such as podssh relay serve's wss://HOST/v1/mailbox. Unset, \
          empty or yes: magic-wormhole's public mailbox, then Least Authority's; no: no pairing by code, which \
          then refuses (78) with the way of the operator's file; a URL that cannot be read is a configuration \
          error (78), which does not echo it.",
    ),
];
