//! Exit codes, and this file is where `64` versus `2` was decided.
//!
//! ⛔ **The fork is closed.** [`docs/TODO/modes/exit-codes.md`](../modes/exit-codes.md):300,
//! *"the operator has now named `64`"*, applied here: `Usage` is **64**
//! (`EX_USAGE`) and `Config` is **78** (`EX_CONFIG`).
//!
//! * **READ**, `docs/spec/06-cli.md`:32 and :40 — the transcript shows
//!   `podssh example.org` printing `Try: podssh ssh example.org` and `echo $?`
//!   reading **64**. Line 84 repeats it: *"An unknown flag is an error naming
//!   the nearest known flag, exit 64."*
//! * **READ**, [`docs/TODO/modes/exit-codes.md`](../modes/exit-codes.md):97 —
//!   E24 assigns `Usage` — *"bad flags, missing host"* — the value **64**,
//!   `EX_USAGE`, and line 142 asserts `podssh ssh --bogus-flag x` reads 64.
//!
//! ⛔ **A half-flipped tree that exits 64 in one path and 2 in another is worse
//! than either value** — so this file is not edited alone: the flip is one
//! change across `exit_codes.rs`, `exitmap.rs` and every test that pinned `2`
//! (`man.rs`, `man_page.rs`, `binary_streams.rs`, `plants.rs`).
//!
//! ⛔ **Why 2 lost, kept because it is the reason the flip was worth the churn:**
//! E24's own table gave **`Config` = 2**, and `06-cli.md`:258-259 says that
//! plainly, *"A previous draft of this document said `2` for a usage error,
//! which contradicted E24... The mistake this would have shipped: a script
//! testing `$? -eq 2` to detect a typo would instead catch a config error."*
//! ⛔ **Choosing 2 reproduces exactly the collision `06-cli.md` warns about**,
//! and the decision moves `Config` to 78 so that it does not.
//!
//! ⛔ **Redundancy, per the operator's long-session order (fallbacks from day
//! one, never "efficient"):** the contract is asserted in three places at once
//! — [`EXIT_USAGE`] here, `exitmap::TABLE` + `exitmap::code`, and the
//! process-level suites (`binary_streams.rs`, `man_page.rs`, `plants.rs`) — so
//! a drift in any one of them fails loudly against the other two instead of
//! silently shipping.

/// A usage error: bad flags, an unknown verb, a missing host. `EX_USAGE` (64).
/// ⛔ **Applied 2026-10-06 from E24's decision** — `Usage` is 64, `Config` is 78.
/// See the module header for why `2` lost.
pub const EXIT_USAGE: i32 = 64;

/// The exit for `podssh` reaching a path that has no behaviour yet. ⛔ Not 0 —
/// `06-cli.md`:244-245.
pub const EXIT_NOT_IMPLEMENTED: i32 = 70;

/// `EX_SOFTWARE`, per E24's `SessionFault` row.
pub const EXIT_SOFTWARE: i32 = EXIT_NOT_IMPLEMENTED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_usage_error_is_sixty_four() {
        // ⛔ **The post-flip value.** E24's decision (operator 2026-10-05,
        // applied 2026-10-06): `Usage` is 64 (`EX_USAGE`), `Config` is 78.
        // Exit 0 is the other thing this asserts: a silently-dropped
        // `-o StrictHostKeyChecking=no` reports success, and that is the
        // spec's security bug. Exit 2 is asserted absent: it is the shell
        // status this contract must not collide with.
        assert_eq!(EXIT_USAGE, 64);
        assert_ne!(EXIT_USAGE, 0);
        assert_ne!(EXIT_USAGE, 2);
    }
}
