//! `podssh-ts`: podssh's tailnet adapter over the vendored `tailscale` fork.
//!
//! The engine boundary: `TsConfig` in, `TsNode` out. Selection, CLI and ops
//! live in `podssh-cli`; this crate never learns SSH and the transport never
//! learns tailscale.

pub mod chain;
pub mod classify;
pub mod config;
pub mod node;
pub mod pipe;
pub mod secret;
pub mod status;
