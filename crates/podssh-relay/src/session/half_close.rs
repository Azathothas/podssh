//! The end of one direction (T-632): `END`, the record that says that this
//! side's application ended its bytes, while the session goes on for the
//! peer's.
//!
//! The layer's `CLOSE` ends the whole session, so a client that writes a
//! request, ends its input and waits for the answer lost the answer where no
//! channel runs above the layer: `echo QUERY | podssh proxy HOST PORT` on the
//! relay role's road, to a target that reads to the end of its input. With
//! both sides naming [`END`], a read of nothing from the application sends
//! `END` after its last `DATA`, with the offset after that byte, and the
//! session goes on; the peer shuts its application's write side once it wrote
//! each byte before the end, and reads on. The side whose application ends
//! second sends `CLOSE`, as each side did before, and the session ends when
//! the `CLOSE` is answered. A read that fails is no end of one direction: it
//! ends the whole session with `CLOSE`, as a signal of the user does.
//!
//! A far end of this build names it in each `GREETING`; a client names it in
//! its `OPEN` where its application ends one direction and reads on
//! ([`Settings::half_close`]). A peer of an older build names no such feature
//! and decodes no such record: it never gets one, and its sessions end with
//! `CLOSE` as before. The feature is agreed in a session's first handshake
//! and holds across its links, as `replay.v1` does; each new link sends this
//! side's `END` again after the bytes that it sends again, and a peer that
//! had it takes it once.

use super::Settings;

/// The feature name of the end of one direction.
pub const END: &str = "end.v1";

/// Add the ask of `END` to `names`, the features of a client's `OPEN`,
/// where `settings` ask for it.
pub fn ask(settings: &Settings, names: &mut Vec<String>) {
    if settings.half_close && !names.iter().any(|name| name == END) {
        names.push(END.to_string());
    }
}

/// Whether both sides named `END`, by the names that both gave.
pub fn agreed(features: &[String]) -> bool {
    features.iter().any(|name| name == END)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_asks_only_where_its_settings_ask() {
        let mut names = vec!["replay.v1".to_string()];
        ask(&Settings::default(), &mut names);
        assert_eq!(names, ["replay.v1"], "not asked by default");
        let half = Settings { half_close: true, ..Settings::default() };
        ask(&half, &mut names);
        ask(&half, &mut names);
        assert_eq!(names, ["replay.v1", END], "asked once");
        assert!(agreed(&names));
        assert!(!agreed(&["replay.v1".to_string(), "once.v1".to_string()]), "a peer of an older build");
    }
}
