//! The window's title as the place of a notice (T-302): saved on the
//! terminal's stack of titles before the notice (XTWINOPS `CSI 22 ; 2 t`),
//! and taken back from it after (`CSI 23 ; 2 t`), so that the title that the
//! user or a program set comes back. A terminal with no such stack would
//! keep the notice as its title, so podssh writes one only where the
//! terminal is known to keep a stack (AGENTS.md, section 5, rule 1).
//!
//! What is known of the terminal comes from its environment: a terminal can
//! answer a query, but the answer comes on stdin, where the session's keys
//! are read already. The list is xterm's documentation of XTWINOPS and
//! VTE's; which terminals keep the stack is to be measured
//! (`scripts/title-stack.py`), and `PODSSH_TITLE_STACK` says it for a
//! terminal that the list does not name.

/// `yes` or `no`: whether the terminal keeps a stack of titles, for a
/// terminal that the list does not know, or to turn the notice off.
pub const TITLE_STACK_ENV: &str = "PODSSH_TITLE_STACK";

/// Save the window's title on the terminal's stack.
pub const PUSH: &[u8] = b"\x1b[22;2t";
/// Take the window's title back from the stack.
pub const POP: &[u8] = b"\x1b[23;2t";

/// The terminal that keeps a stack of titles, by its name, from the
/// environment that `var` reads; `None` when none is known. Inside tmux or
/// screen, the variables of the outer terminal stay, but the bytes go to the
/// multiplexer, whose stack is not known.
pub fn known_stack(var: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    let set = |name: &str| var(name).is_some_and(|v| !v.trim().is_empty());
    match var(TITLE_STACK_ENV).map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("yes") => return Some(TITLE_STACK_ENV),
        Some("no") => return None,
        _ => {}
    }
    let term = var("TERM").unwrap_or_default();
    if set("TMUX") || set("STY") || term.starts_with("screen") || term.starts_with("tmux") {
        return None;
    }
    // xterm sets XTERM_VERSION; its control sequences (ctlseqs, XTWINOPS)
    // give the stack of titles. UNVERIFIED here: the measurement of T-302.
    if set("XTERM_VERSION") {
        return Some("xterm");
    }
    // VTE (GNOME Terminal and others) sets VTE_VERSION, and keeps a stack
    // of titles. UNVERIFIED here: the measurement of T-302.
    if set("VTE_VERSION") {
        return Some("VTE");
    }
    None
}

/// The window's title `text`: OSC 2, ended by BEL, with each control
/// character and each `;` left out, as a model terminal may cut the title
/// at a `;`.
pub fn set(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_control() && *c != ';').collect();
    let mut out = b"\x1b]2;".to_vec();
    out.extend_from_slice(clean.as_bytes());
    out.push(0x07);
    out
}
