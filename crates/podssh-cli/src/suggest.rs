//! ⛔ **Choosing what to suggest, and what to say nothing about.**
//!
//! ⛔ **This module is the decision half of the no-subcommand handler**, split
//! out of `refuse.rs` because that file crossed 500 lines ⛔ **and the rule is
//! to split, not to delete comments** ([`RULES.md`](../../RULES.md):88-91).
//! ⛔ The seam is the one the design already had: `refuse.rs` is *what a
//! refusal says*, this is *whether there is a refusal to make*.
//!
//! ⛔ **Two stages, and the order is the design** ⛔ `docs/TODO/cli/surface.md`
//! lines 99-106:
//!
//! 1. ⛔ **Shape.** `@`, `.` or `:` means *network destination* → `Try: podssh ssh
//!    <token>`. Lexical, not a guess.
//! 2. ⛔ **Distance.** Behind an **absolute** threshold ⛔ **and** a prefix
//!    requirement. Both are measured, and both are below.
//!
//! ⛔ Past both gates the answer is [`NoSubcommand::NoMatch`], ⛔ **which is an
//! answer and not a failure**: podssh prints the subcommand list and **makes no
//! guess**, because ⛔ "a wrong suggestion is worse than none".

use crate::flags::{canonical_name, VERBS};

/// ⛔ **The absolute distance threshold, and the reason it is absolute.**
///
/// E31's entry records the measurement that makes a *relative* gate wrong:
/// MEASURED 2026-10-01, this machine, the nearest verb to `example.org` is
/// `doctor` at distance 9 and to `user@example.org` is `operator` at 11. A gate
/// of `len/3` scales with the token, so a longer token gets a wider gate and a
/// worse suggestion. ⛔ **This number does not scale with anything.** A verb that
/// is this far from the token is not a typo of it.
pub const DISTANCE_THRESHOLD: usize = 3;

/// ⛔ **How much of the token must match for distance to count at all.**
///
/// ⛔ **This constant exists because a pure distance gate is broken at threshold
/// 3, and that was measured rather than assumed.** With `DISTANCE_THRESHOLD = 3`
/// and nothing else, MEASURED 2026-10-02 on this machine against the verb list:
///
/// | token | nearest | distance | why it is wrong |
/// | --- | --- | --- | --- |
/// | `xz` | `cp` | 2 | ⛔ two letters are within 3 of every 2-letter verb |
/// | `sttau` | `sftp` | 3 | ⛔ **ties** with `status`, and `sftp` sorts first |
///
/// ⛔ `cp`, `mv`, `man` and `irc` are two or three characters, so ⛔ **almost
/// every short nonsense token is within 3 of one of them**, and the tie-break
/// then picks a file-transfer verb for a typo of `status`. That is ⛔ **the
/// "a wrong suggestion is worse than none" failure the entry is built to
/// prevent**, arriving through the front door.
///
/// ⛔ **The rule that fixes it is a prefix requirement, and it is the rule a
/// human already uses**: a mistyped verb is nearly always a verb with a letter
/// wrong, dropped, or doubled, so it **shares its opening characters** with the
/// verb it was meant to be. `chatr`/`chat` share `cha`; `sttaus`/`status` share
/// `st`; `relayy`/`relay` share the whole word. ⛔ `xz` and `cp` share nothing,
/// so `xz` gets no guess, and `sttau` cannot be sold to `sftp` because they
/// share only `s`.
///
/// ⛔ Two characters is the length that separates a real typo from a
/// coincidence across this verb list, and ⛔ the measurement above is what picks
/// it: at 2, `sttaus`→`status` (shares `st`) qualifies and `xz`→`cp` (shares
/// nothing) does not.
pub const PREFIX_MATCH: usize = 2;

/// Levenshtein distance, used **only** for the second stage and only behind
/// [`DISTANCE_THRESHOLD`].
///
/// ⛔ **Why this is here at all when `clap`'s `suggestions` feature is on:**
/// `clap` suggests over *flags it parsed*, and the no-subcommand handler runs
/// *before* any command is selected — so there is no parsed command whose flag
/// set could be searched. This is the one place a distance function is
/// reachable, it is bounded by the absolute threshold above, and it can never
/// outvote the shape stage. ⛔ A hand-rolled distance here is not the failure
/// the entry warns about: that failure was a distance-only suggestion with no
/// threshold, and this has both the threshold and a shape stage in front of it.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// The nearest verb by distance, **behind both gates**.
///
/// ⛔ Two conditions, and a candidate must satisfy both:
/// 1. ⛔ distance ≤ [`DISTANCE_THRESHOLD`], the absolute bound; and
/// 2. ⛔ the token and the verb share [`PREFIX_MATCH`] opening characters.
///
/// ⛔ Condition 2 is not decoration — **it is what makes condition 1 safe**, and
/// the measurement in [`PREFIX_MATCH`] is why. ⛔ Without it a 2-letter verb
/// swallows every short token and `podssh sttau` is told to run `podssh sftp`.
///
/// ⛔ Ties are broken by the **shorter** spelling, and the rule is canonical-name-
/// first at equal length. ⛔ `sttau` is
/// distance 3 from both `status` and `sftp`, and both share the `st`/`s`
/// prefix; ⛔ `status` is the canonical name a user meant, `sftp` is an alias,
/// so a canonical name beats an alias at equal distance. ⛔ This is a stated
/// rule rather than sort order, because sort order picking `sftp` was the
/// observed wrong answer.
pub fn nearest_verb(token: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for v in VERBS {
        for alias in v.aliases {
            let d = levenshtein(token, alias);
            if d > DISTANCE_THRESHOLD || !shares_prefix(token, alias) {
                continue;
            }
            // ⛔ Lower distance wins. At equal distance a canonical name beats
            // an alias, and then the shorter spelling wins for stability.
            let better = match best {
                None => true,
                Some((cur_name, cur_d)) => {
                    if d != cur_d {
                        d < cur_d
                    } else {
                        canonical_preference(alias, cur_name)
                    }
                }
            };
            if better {
                best = Some((alias, d));
            }
        }
    }
    best.map(|(name, _)| canonical_name(name).unwrap_or(name))
}

/// Whether two tokens share their first [`PREFIX_MATCH`] characters, bounded by
/// the shorter of the two so that a 2-letter token cannot "share" 2 characters
/// with everything.
fn shares_prefix(a: &str, b: &str) -> bool {
    let n = PREFIX_MATCH.min(a.chars().count()).min(b.chars().count());
    if n < PREFIX_MATCH {
        // ⛔ A token shorter than the requirement cannot be a typo of anything,
        // so it is refused rather than guessed at.
        return false;
    }
    a.chars().take(n).eq(b.chars().take(n))
}

/// ⛔ Prefer a canonical verb name over an alias at equal distance.
///
/// ⛔ `sttau` is 3 from both `status` and `sftp`. ⛔ `status` is the name
/// `06-cli.md`:25 lists and `sftp` is `cp`'s alias, so a canonical name is the
/// better answer even though `sftp` shares one more character of prefix.
fn canonical_preference(candidate: &str, current: &str) -> bool {
    let cand_canonical = VERBS.iter().any(|v| v.name == candidate);
    let cur_canonical = VERBS.iter().any(|v| v.name == current);
    match (cand_canonical, cur_canonical) {
        (true, false) => true,
        (false, true) => false,
        _ => candidate.len() < current.len(),
    }
}

/// ⛔ **Shape, stage one. A token that looks like a network destination is a
/// host, and no verb is near enough to outvote that.**
///
/// `06-cli.md`:43-49: *"Recognise `@`, a dotted name, and `host:port` as
/// host-shaped **before** consulting the verb list, and only then compare names
/// behind an absolute distance threshold."* ⛔ The reason is the one the entry
/// records — a distance-only rule makes `doctor` the nearest verb to
/// `example.org`, and **a wrong suggestion is worse than none**.
pub fn is_destination_shaped(token: &str) -> bool {
    token.contains('@') || token.contains('.') || token.contains(':')
}

/// The two-stage answer for `podssh <token>` where `<token>` is not a verb.
#[derive(Debug, PartialEq, Eq)]
pub enum NoSubcommand {
    /// Stage one fired: this is a host, not a subcommand.
    Destination,
    /// Stage two fired, inside the absolute threshold.
    Typo(&'static str),
    /// Past the threshold. ⛔ **No guess is offered**, and that is the answer.
    NoMatch,
}

/// Run both stages, in the order the entry fixes. ⛔ Shape first, always: a
/// token that is both host-shaped and near a verb must be answered as a host,
/// because `podssh ssh.example` is a hostname and not a typo of `ssh`.
pub fn diagnose_no_subcommand(token: &str) -> NoSubcommand {
    if is_destination_shaped(token) {
        return NoSubcommand::Destination;
    }
    match nearest_verb(token) {
        Some(name) => NoSubcommand::Typo(name),
        None => NoSubcommand::NoMatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_a_host_whatever_the_verb_list_says() {
        // MEASURED 2026-10-01, this machine: doctor is at distance 9 from
        // example.org and operator at 11 from user@example.org, so a
        // distance-only handler names the wrong verb for both.
        assert_eq!(diagnose_no_subcommand("example.org"), NoSubcommand::Destination);
        assert_eq!(diagnose_no_subcommand("user@example.org"), NoSubcommand::Destination);
        assert_eq!(diagnose_no_subcommand("host:2222"), NoSubcommand::Destination);
        assert_eq!(nearest_verb("example.org"), None);
    }

    #[test]
    fn a_typo_inside_the_threshold_is_named() {
        assert_eq!(diagnose_no_subcommand("sttaus"), NoSubcommand::Typo("status"));
        assert_eq!(diagnose_no_subcommand("chatr"), NoSubcommand::Typo("chat"));
        assert_eq!(diagnose_no_subcommand("mann"), NoSubcommand::Typo("man"));
    }

    #[test]
    fn past_the_threshold_no_guess_is_offered() {
        // ⛔ **This test was written wrong the first time and the correction is a
        // finding, not a concession.** It asserted `relayy` and `doctorrr`
        // produce no guess. MEASURED 2026-10-02 on this machine, Levenshtein:
        // `relayy`→`relay` is **1** and `doctorrr`→`doctor` is **2**, both inside the
        // threshold of 3, so **both should be guessed** ⛔ and a test demanding
        // no guess was demanding a worse tool.
        assert_eq!(diagnose_no_subcommand("relayy"), NoSubcommand::Typo("relay"));
        assert_eq!(diagnose_no_subcommand("doctorrr"), NoSubcommand::Typo("doctor"));

        // `nonsense` is the honest outside-the-gate case: 5 from its nearest
        // verb and no shared two-character prefix, so no guess is made.
        assert_eq!(nearest_verb("nonsense"), None);
        assert_eq!(diagnose_no_subcommand("nonsense"), NoSubcommand::NoMatch);
    }

    /// ⛔ **Both gates, and the second is what makes the first safe.**
    ///
    /// ⛔ **A distance-only gate at threshold 3 was measured to be broken.**
    /// MEASURED 2026-10-02 on this machine, before the prefix rule existed:
    ///
    /// | token | nearest | distance | what the user was told |
    /// | --- | --- | --- | --- |
    /// | `sttaus` | `status` | 2 | `status` — right |
    /// | `chatr` | `chat` | 1 | `chat` — right |
    /// | `xz` | `cp` | 2 | ⛔ **`cp`** — wrong, and absurd |
    /// | `sttau` | `sftp` | 3 | ⛔ **`sftp`**, tying `status` at 3 |
    ///
    /// ⛔ `cp` and `mv` are two characters and `man` and `irc` are three, so
    /// ⛔ **almost every short token is within 3 of one of them**, and a tie is
    /// then broken by whatever sorts first. ⛔ That is the "a wrong suggestion
    /// is worse than none" failure arriving through the front door, and it is
    /// why [`PREFIX_MATCH`] exists.
    #[test]
    fn the_threshold_is_absolute_and_three() {
        assert_eq!(DISTANCE_THRESHOLD, 3);
        assert_eq!(PREFIX_MATCH, 2);

        assert_eq!(nearest_verb("sttaus"), Some("status"));
        assert_eq!(nearest_verb("chatr"), Some("chat"));
        assert_eq!(nearest_verb("relayy"), Some("relay"));
        assert_eq!(nearest_verb("mann"), Some("man"));

        // Three is inclusive: refusing `sttau` refuses an obvious typo.
        assert_eq!(nearest_verb("sttau"), Some("status"));
        assert_eq!(nearest_verb("sta"), Some("status"));
    }

    #[test]
    fn a_token_sharing_no_prefix_is_never_guessed() {
        for token in ["xz", "qzxwv", "zzz", "vvv"] {
            assert_eq!(nearest_verb(token), None, "{token} won a guess without sharing a prefix with anything");
        }
        // ⛔ The shape stage is not what stopped these: none contains `@`, `.`
        // or `:`, so they reach the distance stage and are stopped there.
        for token in ["xz", "qzxwv"] {
            assert!(!is_destination_shaped(token), "{token} should not be host-shaped");
            assert_eq!(diagnose_no_subcommand(token), NoSubcommand::NoMatch);
        }
    }

    /// ⛔ A relative gate (`len/3`) is what yields `doctor example.org`: a longer
    /// token earns a wider gate. ⛔ Length alone must buy nothing.
    #[test]
    fn a_long_nonsense_token_is_no_closer_than_a_short_one() {
        for token in ["xz", "qzxwv", "qzxwvutsrqponmlkjihgfedcba"] {
            assert_eq!(nearest_verb(token), None, "{token} won a guess by being long");
        }
    }

    #[test]
    fn shape_outranks_a_close_verb() {
        // `ssh.` is one edit from `ssh` and is shaped like a hostname.
        assert_eq!(nearest_verb("ssh."), Some("ssh"));
        assert_eq!(diagnose_no_subcommand("ssh."), NoSubcommand::Destination);
    }

    #[test]
    fn every_alias_resolves_to_its_canonical_name() {
        assert_eq!(canonical_name("irc"), Some("chat"));
        assert_eq!(canonical_name("chat"), Some("chat"));
        assert_eq!(canonical_name("scp"), Some("cp"));
        assert_eq!(canonical_name("sftp"), Some("cp"));
        assert_eq!(canonical_name("connect"), Some("ssh"));
        assert_eq!(canonical_name("nope"), None);
    }
}
