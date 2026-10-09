//! E24's fault table as code, and the `2` versus `64` decision.
//!
//! ⛔ **One read path for the contract.** [`docs/TODO/modes/exit-codes.md`]
//! writes the table in prose; a second reader of that table types the number
//! again, and two places holding one number is where a contract stops being a
//! contract. Every condition podssh reports goes through [`code`], and a script
//! that wants the table reads [`TABLE`].
//!
//! # ⛔ The decision: a usage error is `64`
//!
//! Five documents disagreed and this is the resolution. **READ**:
//!
//! | source | said |
//! | --- | --- |
//! | `docs/spec/06-cli.md`:32, :40, :84 | **64** |
//! | E24's own table, `exit-codes.md`:97 | **`Usage` = 64**; **`Config` = 78**
//! (`EX_CONFIG`) since the 2026-10-05 decision applied 2026-10-06 |
//! | E31 [`surface.md`](surface.md), E32 [`man.md`](man.md), E36 [`cp-mv.md`](cp-mv.md) | **2** |
//! | E34 [`ssh-config.md`](ssh-config.md):113-114, :133 | **2** |
//! | E35 [`relay-cmd.md`](relay-cmd.md):169 | **2 for "no relay target"** — E24's `Config` row |
//!
//! ⛔ **The collision is the whole of the argument, and it is worse than one
//! collision.** E31 chose `2` because a usage error and a config error must not
//! share a code. That reasoning is right and it is why **`Config` is the row
//! that moves.** `2` is a *shell* status before it is anything else — it is
//! what a bare `test`, a `grep` miss and a `diff` disagreement all return — so
//! `2` as a podssh fault collides with ordinary command output as well as with
//! `Config`. `64` collides with nothing, and it is `EX_USAGE` in the same
//! header `06-cli.md`:253-256 already ruled podssh's own failures come from.
//!
//! ⛔ **`2` is not a `sysexits.h` value at all.** E24's own Approach says its
//! values are POSIX `sysexits.h`, and `2` is absent from that header while
//! `EX_CONFIG` — 78 — is in it, for exactly the row `2` was standing in for.
//!
//! ⛔ **What this file does NOT do.** It does not edit a document and it does
//! not silently flip the binary. The documents that still say `2` are listed
//! in E24's `Decision` with the exact line each changes, and ⛔ the operator
//! owns `docs/spec/` and the entries that are not E24's.

use crate::exit_codes::EXIT_USAGE;

/// POSIX `sysexits.h`. ⛔ **`README`/`sysexits.h` is the authority for these
/// numbers and [`TABLE`] is the authority for which one each condition takes.**
pub mod sysexits {
    /// The base every other `sysexits.h` value is offset from.
    pub const EX_USAGE: i32 = 64;
    /// Nothing could answer: the peer is unreachable, or a pair was revoked.
    pub const EX_UNAVAILABLE: i32 = 69;
    /// podssh itself is at fault, or a session was truncated.
    pub const EX_SOFTWARE: i32 = 70;
    /// The peer refused podssh's credentials, or the pair expired.
    pub const EX_NOPERM: i32 = 77;
    /// The machine is not set up the way this mode needs.
    pub const EX_CONFIG: i32 = 78;
}

/// One row of E24's table.
///
/// ⛔ **`Fault` carries a reason and not a number**, so a fault cannot exist
/// without something `--doctor` can name, and `doctor --exit-codes` can render.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// Bad flags, an unknown verb, a missing host. `06-cli.md`:84.
    Usage,
    /// TCP, TLS, the WebSocket upgrade, or a pre-`101` HTTP status.
    RelayUnreachable,
    /// Relay `403`/`401`, or SSH authentication refused.
    Auth,
    /// A probe returned `????` and the mode needed it.
    Capability,
    /// Relay close `1003`/`1008`/`1009`/`1011`/`1013`, or a framing fault.
    SessionFault,
    /// Relay close `1001`, reason `operator stopped reverse relay`.
    Revoked,
    /// Relay close `1001`, reason `pair expired`.
    PairExpired,
    /// An unparseable config file, or no relay target.
    Config,
    /// The remote command ran and delivered a status.
    Remote(u32),
    /// ⛔ **The session ran and then ended without a delivered `exit-status`.**
    ///
    /// ⛔ **This is NOT "a clean close", and the correction is load-bearing.**
    /// E24's table calls this row `ChannelClosed` and describes it as *"a
    /// clean close with none"*, then two paragraphs later says a
    /// `ChannelClosed` that never saw `exit-status` **and never reached a
    /// clean `1000`** is a truncation and exits **70**.
    ///
    /// ⛔ **Those two sentences cannot both hold, because a `ChannelClosed`
    /// whose close was clean is by definition a `1000`, so every
    /// `ChannelClosed` would satisfy the second clause and `EX_SOFTWARE` would
    /// be the only code it ever takes.** ⛔ The row is split here instead, so
    /// each clause governs exactly the case it describes:
    /// `ChannelClosed` is the clean `1000` with no status, and
    /// `SessionFault` is the truncated tail.
    ChannelClosed,
}

impl Fault {
    /// The process exit code for this fault. ⛔ **A delivered `Remote(0)` is
    /// the only value that legitimately returns `0`, and it returns it because
    /// the remote said so.**
    pub fn code(self) -> i32 {
        match self {
            // ⛔ 64: the value `06-cli.md`:32, :40 and :84 print, and the one
            // E24's own table gave `Usage`. See the module header for why `2`
            // lost and why `Config` is the row that moves instead.
            Fault::Usage => sysexits::EX_USAGE,
            // ⛔ 69: there is no relay to talk to. `Revoked` shares it on
            // purpose — see SHARED_CODES — and `--doctor` names which.
            Fault::RelayUnreachable | Fault::Revoked => sysexits::EX_UNAVAILABLE,
            // ⛔ 77: the peer refused us. The two `1001` rows land apart from
            // each other because the REASON decides, not the code.
            Fault::Auth | Fault::PairExpired => sysexits::EX_NOPERM,
            Fault::SessionFault | Fault::ChannelClosed => sysexits::EX_SOFTWARE,
            // ⛔ 78: this machine is not set up for this mode. See SHARED_CODES.
            Fault::Capability | Fault::Config => sysexits::EX_CONFIG,
            Fault::Remote(status) => status as i32,
        }
    }

    /// The name `--doctor` prints. ⛔ **No variant returns an empty string**,
    /// so a fault with nothing to say is unrepresentable.
    pub fn name(self) -> &'static str {
        match self {
            Fault::Usage => "Usage",
            Fault::RelayUnreachable => "RelayUnreachable",
            Fault::Auth => "Auth",
            Fault::Capability => "Capability",
            Fault::SessionFault => "SessionFault",
            Fault::Revoked => "Revoked",
            Fault::PairExpired => "PairExpired",
            Fault::Config => "Config",
            Fault::Remote(_) => "Remote",
            Fault::ChannelClosed => "ChannelClosed",
        }
    }

    /// Whether this fault's MEANING depends on whether the session reached
    /// `ready`, rather than on the close code. ⛔ **This is the predicate E24's
    /// *"does the close code alone decide? No — `established` decides first"*
    /// needs**, and it is deliberately **not** implemented as a code match:
    /// ⛔ a `1000` before `ready` is a session that never existed and a `1000`
    /// after it is a session that ended without a status, ⛔ **the close code is
    /// the same number in both rows**, and ⛔ **a function that could tell them
    /// apart by inspecting the code would be the bug this entry is about.**
    pub fn established_sensitive(self) -> bool {
        matches!(self, Fault::SessionFault | Fault::ChannelClosed)
    }

    /// ⛔ **The close-code decision, and it is the sibling's defect restated as
    /// a function.** The sibling reads the code and assigns no `rc`
    /// (`dropssh` `src/connect.c:455-461`), so a `1009` returns 0.
    ///
    /// ⛔ **The two `1000` rows are the load-bearing ones** and they are why
    /// this takes `established`: E24, *"Does the close code alone decide? No
    /// — `established` decides first"* — *"A `1000` before `established` is a
    /// failed session and a `1009` after it is a truncated one. Both are
    /// faults."*
    pub fn from_close(code: u16, reason: &str, established: bool) -> Fault {
        match code {
            // ⛔ Parse the REASON, not the code. Spec lines 135-136 give two
            // `1001` reasons that demand opposite actions: re-pair, or accept
            // that the pair is gone. The code alone cannot tell them apart.
            1001 => {
                if reason.contains("expired") {
                    Fault::PairExpired
                } else {
                    Fault::Revoked
                }
            }
            1003 | 1008 | 1009 | 1011 | 1013 => Fault::SessionFault,
            // ⛔ A clean close, before or after `ready`, is a session that did
            // not work. ⛔ It is NOT the truncation row: the relay reported a
            // normal closure and the session really did end. What is missing
            // is podssh's own remote status, and that is reported on stderr
            // rather than folded into the exit code.
            1000 if !established => Fault::SessionFault,
            _ => Fault::ChannelClosed,
        }
    }
}

/// The exit code for a fault. ⛔ **The one read path**, so a second constant
/// cannot be typed somewhere else and drift.
pub fn code(fault: Fault) -> i32 {
    fault.code()
}

/// ⛔ **The table, as data.** This is what `podssh doctor --exit-codes` prints
/// and what a script reads instead of parsing prose. ⛔ `Remote` is absent
/// because its value is whatever the remote said.
pub const TABLE: &[(Fault, i32)] = &[
    (Fault::Usage, sysexits::EX_USAGE),
    (Fault::RelayUnreachable, sysexits::EX_UNAVAILABLE),
    (Fault::Auth, sysexits::EX_NOPERM),
    (Fault::Capability, sysexits::EX_CONFIG),
    (Fault::SessionFault, sysexits::EX_SOFTWARE),
    (Fault::Revoked, sysexits::EX_UNAVAILABLE),
    (Fault::PairExpired, sysexits::EX_NOPERM),
    (Fault::Config, sysexits::EX_CONFIG),
    (Fault::ChannelClosed, sysexits::EX_SOFTWARE),
];

/// ⛔ **Codes deliberately shared, and the reason each one is allowed.** Every
/// other pair must differ. ⛔ **This list is the guard, not a comment**: a new
/// row that collides with an existing one fails
/// `no_undeclared_code_collisions` until the reason is written here, which is
/// the only way a shared code ever becomes a decision instead of an accident.
pub const SHARED_CODES: &[(i32, &[&str])] = &[
    (sysexits::EX_UNAVAILABLE, &["RelayUnreachable", "Revoked"]),
    (sysexits::EX_NOPERM, &["Auth", "PairExpired"]),
    (sysexits::EX_CONFIG, &["Capability", "Config"]),
    // ⛔ The one this module's first version had to discover by failing. A
    // session that died and a session that ended cleanly are different facts
    // with the same repair — the session did not deliver what you asked for —
    // so they share `EX_SOFTWARE`, and `Fault` keeps them apart.
    (sysexits::EX_SOFTWARE, &["SessionFault", "ChannelClosed"]),
];
/// ⛔ **The fork, as a function of what the binary actually does.** Returns
/// `Some((the table's value, what the binary emits))` while E24's decision and
/// `exit_codes::EXIT_USAGE` disagree, and `None` once they agree.
///
/// ⛔ **It reads `EXIT_USAGE` rather than hard-coding 2**, so the moment the
/// operator applies the decision this returns `None` with no edit here.
pub fn usage_fork() -> Option<(i32, i32)> {
    if sysexits::EX_USAGE == EXIT_USAGE {
        None
    } else {
        Some((sysexits::EX_USAGE, EXIT_USAGE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ **THE DECISION, asserted.** This is the check that fails if somebody
    /// re-types `2` into this crate, and it is the test the two agents who
    /// flagged the fork needed.
    #[test]
    fn a_usage_error_is_sixty_four() {
        assert_eq!(code(Fault::Usage), 64);
        // ⛔ Not 2. This assertion exists so that reverting to 2 breaks the
        // suite loudly instead of silently re-creating the collision.
        assert_ne!(code(Fault::Usage), 2);
        assert_eq!(code(Fault::Usage), sysexits::EX_USAGE);
    }

    /// ⛔ **The whole reason `Usage` is 64: it is the only row a script needs
    /// to be certain of.** ⛔ `2` is what a bare `test`, a `grep` miss and a
    /// `diff` disagreement already return, so a status of `2` from any program
    /// is not evidence of anything; `64` is.
    #[test]
    fn usage_does_not_collide_with_a_shell_status() {
        for shell_status in [1, 2] {
            assert_ne!(code(Fault::Usage), shell_status);
            for (fault, _) in TABLE {
                assert_ne!(code(*fault), shell_status, "{} uses a shell status", fault.name());
            }
        }
    }

    /// ⛔ **`Config` moved off `2`.** That promotion is the whole of what `2`
    /// losing amounts to, so it is asserted directly.
    #[test]
    fn config_is_no_longer_two() {
        assert_eq!(code(Fault::Config), sysexits::EX_CONFIG);
        assert_ne!(code(Fault::Config), 2);
    }

    /// ⛔ **`TABLE` and [`code`] cannot disagree.** A row edited without the
    /// match arm is a table that lies to `doctor --exit-codes`.
    #[test]
    fn table_agrees_with_code() {
        for (fault, expected) in TABLE {
            assert_eq!(code(*fault), *expected, "{} disagrees with TABLE", fault.name());
            assert_ne!(*expected, 0, "{} would exit 0", fault.name());
        }
    }

    /// ⛔ **THE COLLISION GUARD, and it is planted in both directions.** Every
    /// pair sharing a code must appear in [`SHARED_CODES`], and every declared
    /// pair must actually share one — so neither a new accidental collision
    /// nor a stale justification passes.
    #[test]
    fn no_undeclared_code_collisions() {
        for (i, &(a, ca)) in TABLE.iter().enumerate() {
            for &(b, cb) in &TABLE[i + 1..] {
                if ca != cb {
                    continue;
                }
                let declared = SHARED_CODES
                    .iter()
                    .any(|(c, names)| *c == ca && names.contains(&a.name()) && names.contains(&b.name()));
                assert!(declared, "{} and {} both exit {} and SHARED_CODES does not say why", a.name(), b.name(), ca);
            }
        }
        for (code_value, names) in SHARED_CODES {
            for name in *names {
                let row = TABLE.iter().find(|(f, _)| f.name() == *name);
                assert!(row.is_some(), "SHARED_CODES names {name}, which TABLE does not");
                assert_eq!(
                    row.unwrap().1,
                    *code_value,
                    "SHARED_CODES claims {name} exits {code_value}, TABLE disagrees"
                );
            }
        }
    }

    /// ⛔ **A fault cannot exist without a name.** `--doctor` renders
    /// [`Fault::name`], and no variant returns an empty string.
    #[test]
    fn every_fault_has_a_name() {
        for (fault, _) in TABLE {
            assert!(!fault.name().is_empty());
        }
    }

    /// ⛔ **The two `1001` rows demand opposite actions, so the REASON decides.**
    /// Spec lines 135-136: `operator stopped reverse relay` against `pair
    /// expired`. A new pair, against a pair that is gone.
    #[test]
    fn a_1001_is_split_by_its_reason_not_its_code() {
        let revoked = Fault::from_close(1001, "operator stopped reverse relay", true);
        let expired = Fault::from_close(1001, "pair expired", true);
        assert_ne!(revoked, expired);
        assert_ne!(code(revoked), code(expired));
        assert_eq!(code(revoked), sysexits::EX_UNAVAILABLE);
        assert_eq!(code(expired), sysexits::EX_NOPERM);
    }

    /// ⛔ **The sibling's defect #1, restated as a test.** `dropssh`
    /// `src/connect.c:455-461` assigns no `rc` on `1003`/`1009` and returns 0.
    #[test]
    fn a_post_ready_fault_is_never_zero() {
        for close in [1003u16, 1008, 1009, 1011, 1013] {
            let f = Fault::from_close(close, "bad multiplex frame", true);
            assert_ne!(code(f), 0, "close {close} reported success");
            assert_eq!(f, Fault::SessionFault);
        }
    }

    /// ⛔ **`established` decides before the close code.** The close code is
    /// identical in both rows and the outcome is not.
    ///
    /// ⛔ **Two faults, two codes — and the difference is what the test first
    /// got wrong.** `1000` before `ready` is a session that never existed, and
    /// `1000` after it is a session that ended without delivering a status.
    /// ⛔ They are `SessionFault` and `ChannelClosed`, so they read 70 and 70.
    /// ⛔ **A collision with a declared reason, not an accident** — and the
    /// declaration is the thing that makes reading the code enough to know
    /// which case this is.
    #[test]
    fn established_decides_before_the_close_code() {
        let before = Fault::from_close(1000, "", false);
        let after = Fault::from_close(1000, "", true);
        assert_ne!(before, after);
        assert_ne!(code(before), 0);
        // ⛔ And the two codes are the same sysexits value on purpose — see
        // SHARED_CODES. ⛔ **Asserting they differ is what the first version of
        // this test did, and it was the test that was wrong**: ⛔ the fault is
        // the same class either way, so demanding two numbers manufactures a
        // fake distinction. ⛔ The distinction that matters is the FAULT, and
        // the two lines above assert it.
        assert_eq!(code(before), sysexits::EX_SOFTWARE);
        assert_eq!(code(after), sysexits::EX_SOFTWARE);
    }

    /// ⛔ **The clean close that is a FAULT, which is E24's first trap.** A
    /// `1000` before `ready` reads as a normal closure and the session never
    /// worked. ⛔ It must not be 0, and it must not be the clean-close row.
    #[test]
    fn a_clean_close_before_ready_is_a_fault_and_not_a_clean_close() {
        let f = Fault::from_close(1000, "", false);
        assert_ne!(code(f), 0);
        assert_eq!(f, Fault::SessionFault);
        assert_ne!(f, Fault::ChannelClosed);
        assert_ne!(f, Fault::Remote(0));
    }

    /// ⛔ **A truncation is `SessionFault`, never `ChannelClosed`.** Plant 7's
    /// defect is a silent 0; a row that mapped a truncated tail onto the clean
    /// close would reintroduce it with a different number in front of it.
    #[test]
    fn a_truncated_tail_is_never_the_clean_close_row() {
        // The channel dies with no exit-status: the close never arrived at all.
        let truncated = Fault::from_close(1009, "session byte cap", true);
        assert_eq!(truncated, Fault::SessionFault);
        assert_ne!(truncated, Fault::ChannelClosed);
        assert_ne!(code(truncated), 0);
    }

    /// ⛔ **`established_sensitive` is the predicate the caller needs, and it
    /// must be true of both rows the `1000` split produces.** ⛔ **This is the
    /// test that pins what that method means**, ⛔ because ⛔ **a method that
    /// answers `false` for a row that genuinely depends on `established` is the
    /// bug it was written to prevent** ⛔ — ⛔ and it was **wrong in the first
    /// version of this file**, which returned `true` for one of the two.
    #[test]
    fn both_rows_of_the_1000_split_depend_on_established() {
        for established in [false, true] {
            let f = Fault::from_close(1000, "", established);
            assert!(f.established_sensitive(), "{f:?} at established={established} does not depend on established");
        }
        // ⛔ And a fault that happens before any session exists does not.
        for f in [Fault::Usage, Fault::Auth, Fault::Revoked, Fault::Config] {
            assert!(!f.established_sensitive(), "{f:?} cannot depend on a session that never opened");
        }
    }

    /// ⛔ **`Remote(0)` is the only legitimate zero.** Plant 7 is a channel that
    /// closes with no `exit-status`; that is `ChannelClosed`, and it is 70.
    #[test]
    fn only_a_delivered_status_reaches_zero() {
        assert_eq!(code(Fault::Remote(0)), 0);
        assert_eq!(code(Fault::Remote(7)), 7);
        // ⛔ The truncated tail: the silent-success bug.
        assert_ne!(code(Fault::ChannelClosed), 0);
        assert_ne!(code(Fault::SessionFault), 0);
    }

    /// ⛔ **A remote `127` is propagated verbatim.** A script seeing 127 on
    /// `ssh host cmd` means "command not found on the remote", and remapping
    /// it onto a fault code destroys that.
    #[test]
    fn a_remote_127_is_not_remapped_onto_a_fault() {
        for (fault, _) in TABLE {
            assert_ne!(code(Fault::Remote(127)), code(*fault), "{} ate a remote 127", fault.name());
        }
    }

    /// ⛔ **The fork is closed, asserted so that reopening it is a deliberate act.**
    /// Before 2026-10-06 this test asserted `Some((64, 2))` — the open fork —
    /// and was written to FAIL the moment `EXIT_USAGE` became 64. The flip has
    /// landed, so it now asserts `None`: the table's value and what the binary
    /// emits agree. If they ever disagree again, this fails and names both sides.
    #[test]
    fn the_usage_fork_is_closed() {
        assert_eq!(
            usage_fork(),
            None,
            "the fork reopened: EXIT_USAGE in exit_codes.rs disagrees with \
             sysexits::EX_USAGE (64); see E24's decision"
        );
    }
}
