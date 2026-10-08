//! podssh-core: protocol state machines with no I/O. Today that is the IRC
//! client (`irc/`); the hand-written SSH client that lived beside it was
//! replaced by `podssh-ssh` (russh) on 2026-10-08.

pub mod irc;
