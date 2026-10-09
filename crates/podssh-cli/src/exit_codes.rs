//! Exit codes, and this file is where `64` versus `2` was decided.
//!
//! **The fork is closed.** The operator ruled it (`docs/decisions.md`, "Product", 2026-10-05):
//! *"64 for a usage error, 78 for a configuration error"*, applied here: `Usage` is **64**
//! (`EX_USAGE`) and `Config` is **78** (`EX_CONFIG`).
//!
//! * **READ**, `docs/cli.md`, "A word with no subcommand" and "Exit codes":
//!   `podssh example.org` prints `Try: podssh ssh example.org`, and `echo $?`
//!   reads **64**. "Options of `podssh ssh`" repeats it: *"An unknown flag is an
//!   error that names the nearest real flag (exit 64)."*
//! * **READ**, the fault table of `exitmap.rs` —
//!   it gives `Usage` — *"Bad flags, an unknown verb, a missing host"* — the value **64**,
//!   `EX_USAGE`, so `podssh ssh --bogus-flag x` reads 64.
//!
//! **A half-flipped tree that exits 64 in one path and 2 in another is worse
//! than either value** — so this file is not edited alone: the flip is one
//! change across `exit_codes.rs`, `exitmap.rs` and every test that pinned `2`
//! (`man/mod.rs`, `man_page.rs`, `binary_streams.rs`, `plants.rs`).
//!
//! **Why 2 lost, kept because it is the reason the flip was worth the churn:**
//! The first exit-code table gave **`Config` = 2**, and `docs/cli.md` ("Exit codes") says
//! plainly, *"The shell statuses 1 and 2 are not used for these, because a
//! script cannot tell them from other programs' failures."* A script
//! testing `$? -eq 2` to detect a typo would instead catch a config error.
//! **Choosing 2 reproduces exactly the collision `docs/cli.md` warns about**,
//! and the decision moves `Config` to 78 so that it does not.
//!
//! **Redundancy, per the operator's long-session order (fallbacks from day
//! one, never "efficient"):** the contract is asserted in three places at once
//! — [`EXIT_USAGE`] here, `exitmap::TABLE` + `exitmap::code`, and the
//! process-level suites (`binary_streams.rs`, `man_page.rs`, `plants.rs`) — so
//! a drift in any one of them fails loudly against the other two instead of
//! silently shipping.

/// A usage error: bad flags, an unknown verb, a missing host. `EX_USAGE` (64).
/// **The decision of 2026-10-05** (`docs/decisions.md`): `Usage` is 64, `Config` is 78.
/// See the module header for why `2` lost.
pub const EXIT_USAGE: i32 = 64;

/// The exit for `podssh` reaching a path that has no behaviour yet. Not 0 —
/// `docs/cli.md`, "Exit codes".
pub const EXIT_NOT_IMPLEMENTED: i32 = 70;

/// `EX_SOFTWARE`, per the `SessionFault` row of `exitmap::TABLE`.
pub const EXIT_SOFTWARE: i32 = EXIT_NOT_IMPLEMENTED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_usage_error_is_sixty_four() {
        // **The post-flip value.** The operator's decision (2026-10-05,
        // `docs/decisions.md`): `Usage` is 64 (`EX_USAGE`), `Config` is 78.
        // Exit 0 is the other thing this asserts: a silently-dropped
        // `-o StrictHostKeyChecking=no` reports success, and that is the
        // spec's security bug. Exit 2 is asserted absent: it is the shell
        // status this contract must not collide with.
        assert_eq!(EXIT_USAGE, 64);
        assert_ne!(EXIT_USAGE, 0);
        assert_ne!(EXIT_USAGE, 2);
    }
}
