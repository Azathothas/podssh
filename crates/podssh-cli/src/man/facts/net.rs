//! The variable of the net (T-429), apart from `facts.rs` for the length of
//! that file.

/// Each one: its names, and what it does.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[(
    &["PODSSH_NET"],
    "The net's document of podssh net (T-429): the absolute path of its file, in place of net.doc in the cache's \
      directory. no: the net is off, so that no member's name, no node's door and no document of the end-to-end \
      channel comes from it, and podssh net refuses (78). Unset, empty or yes: net.doc in the cache; another word, \
      such as a relative path, is a configuration error (78), and the net is off.",
)];
