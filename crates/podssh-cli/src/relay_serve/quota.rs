//! The counts of each key of `podssh relay serve` (T-636, GitHub #134):
//! `--quota MIB`, a key's budget for a day (UTC), both ways together, and
//! `--usage FILE`, the private file that keeps each key's totals of the day
//! and the day before across a restart. Both count the keys that mint, so a
//! role that mints for anyone, or for no one, refuses them (64). The counts
//! say their lines on stdout, beside the role's events; SIGHUP says each
//! key's totals on stderr, beside the certificate's reload.

use std::io::Write;
use std::sync::Arc;

use podssh_relay::serve::usage::{quota_words, Usage};
use podssh_relay::serve::Mint;

use super::ServeArgs;
use crate::relay_settings::Refusal;

/// The largest `--quota`, in MiB: 16 TiB a day.
pub const QUOTA_MOST: u64 = 16 << 20;

/// The budget of `--quota MIB`, in bytes; none without the flag.
pub(super) fn quota_of(text: Option<&str>) -> Result<Option<u64>, Refusal> {
    let Some(text) = text else { return Ok(None) };
    match text.parse::<u64>() {
        Ok(mib @ 1..=QUOTA_MOST) => Ok(Some(mib << 20)),
        _ => Err(Refusal::usage(format!("--quota {text:?}: a key's MiB for a day, from 1 to {QUOTA_MOST}"))),
    }
}

/// The counts that `s` asks for, for whom `mint` mints, and their words for
/// the first line, after a comma: the budget, and the file with its keys.
pub(super) fn of(s: &ServeArgs, mint: &Mint) -> Result<(Usage, String), Refusal> {
    let quota = quota_of(s.quota.as_deref())?;
    let given = [(quota.is_some(), "--quota"), (s.usage.is_some(), "--usage")];
    if let Some((_, flag)) = given.iter().find(|(given, _)| *given) {
        if matches!(mint, Mint::Anyone | Mint::Nobody) {
            let why = "counts the keys that mint, and this relay mints for none: give --mint keys:FILE or net";
            return Err(Refusal::usage(format!("{flag} {why}")));
        }
    }
    // A file that does not read stops the start (78), as the pairs' does.
    let usage = Usage::open(quota, s.usage.as_deref().map(Into::into)).map_err(Refusal::config)?;
    usage.say_to(Arc::new(|line: &str| {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }));
    let budget = quota.map(|q| format!(", a quota of {} a day for each key", quota_words(q))).unwrap_or_default();
    let kept = match &s.usage {
        Some(file) => format!(", the counts of each key kept in {file} ({} keys now)", usage.keys()),
        None => String::new(),
    };
    Ok((usage, format!("{budget}{kept}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quota_is_whole_mib_within_its_bounds_and_counts_keys_alone() {
        assert_eq!(quota_of(None), Ok(None));
        assert_eq!(quota_of(Some("1024")), Ok(Some(1 << 30)));
        for bad in ["0", "-1", "lots", "1.5", "16777217"] {
            let refused = quota_of(Some(bad)).unwrap_err();
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{bad}");
            assert!(refused.message.starts_with(&format!("--quota {bad:?}: ")), "{refused}");
        }
        let s = ServeArgs { quota: Some("10".into()), ..ServeArgs::default() };
        let refused = of(&s, &Mint::Anyone).err().expect("a quota for anyone");
        assert!(refused.message.starts_with("--quota counts the keys that mint"), "{refused}");
        let s = ServeArgs { usage: Some("counts.json".into()), ..ServeArgs::default() };
        let refused = of(&s, &Mint::Nobody).err().expect("counts for no one");
        assert!(refused.message.starts_with("--usage counts the keys that mint"), "{refused}");
        let (usage, words) = of(&ServeArgs::default(), &Mint::Anyone).unwrap();
        assert_eq!((usage.quota(), words.as_str()), (None, ""), "nothing asked, nothing said");
    }
}
