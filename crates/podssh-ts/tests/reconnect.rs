//! The fork's reconnect loop (T-104, patch 0019), tested here too: podssh's workspace and its
//! CI build this crate, and not the fork's own tests. The tests are the fork's file, unchanged.

// The fork's file keeps the fork's formatting: podssh's rustfmt passes it by.
#[rustfmt::skip]
#[path = "../../../vendor/tailscale-rs/ts_runtime/tests/reconnect.rs"]
mod fork;
