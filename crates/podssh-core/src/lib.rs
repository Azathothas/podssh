//! podssh-core: protocol state machines with no I/O: the IRC client
//! (`irc/`), and chat between two podssh ends over the roads (`chat/`,
//! T-099). The hand-written SSH client that lived beside them was replaced
//! by `podssh-ssh` (russh) on 2026-10-08.

pub mod chat;
pub mod irc;
