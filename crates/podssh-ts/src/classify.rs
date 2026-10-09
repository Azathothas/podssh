//! The `1008` split: the relay's reason decides the exit, like 1001 in `exitmap`.
//!
//! A close code without its reason is half a fact. The relay closes `1008`
//! for "not authorized" (exit 77, with the wait hint) and also for bad client
//! info, duplicate login and mesh violations (exit 70) — `exitmap.rs` maps
//! `1008` to one fault today, and the `ts` verb splits it here first.

/// What a closed DERP socket means for the process exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// `1008 "not authorized"` or a refused auth key: exit 77, with the wait hint.
    NotAuthorized,
    /// Any other 1008 (bad client info, duplicate login, mesh) or framing: exit 70.
    Session,
}

/// Split a WebSocket close `1008` reason into its fault. `None` (no reason
/// on the wire) is `Session`: an unnamed refusal is a broken session, never
/// an auth hint.
pub fn classify_1008(reason: Option<&str>) -> Fault {
    match reason {
        Some(r) if r.contains("not authorized") => Fault::NotAuthorized,
        _ => Fault::Session,
    }
}
