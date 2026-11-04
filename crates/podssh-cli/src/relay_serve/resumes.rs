//! The sessions of `podssh relay serve`'s forward road in the resumable
//! layer (T-173), by its flags: `--resume-deadline TIME`, how long the role
//! keeps a session whose link is lost, by the words of a node's flag of the
//! same name; `--resume-budget MIB`, the replay buffers that its sessions
//! hold in all, which bounds how many it keeps; and `--resume-host
//! HOST[:PORT]`, the name of this process in its offer, where several
//! processes share one name and a resume must reach the one that holds its
//! session.

use podssh_relay::relay::parse_relay;
use podssh_relay::serve::layer::{Resumes, BUDGET};
use podssh_relay::session::{deadline, replay, Settings};

use super::ServeArgs;
use crate::relay_settings::Refusal;

/// The largest `--resume-budget`, in MiB: 16 GiB, 4096 sessions of the
/// default buffer.
const MOST_MIB: usize = 16 << 10;

/// The sessions of the flags of `serve`, and their words for its first line,
/// after a comma; none when no flag of them was given.
pub(super) fn of(s: &ServeArgs) -> Result<(Resumes, String), Refusal> {
    let mut settings = Settings::default();
    if let Some(text) = s.resume_deadline.as_deref() {
        settings.resume_deadline = crate::layered::parse_deadline(text).map_err(Refusal::usage)?;
    }
    let budget = match s.resume_budget.as_deref() {
        Some(text) => budget_of(text)?,
        None => BUDGET,
    };
    let mut resumes = Resumes::new(settings, budget);
    if let Some(text) = s.resume_host.as_deref() {
        let name = parse_relay(text).map_err(|why| {
            Refusal::usage(format!(
                "--resume-host: {why}; HOST[:PORT], a name of this process alone in its certificate"
            ))
        })?;
        resumes = resumes.named(name);
    }
    let given = s.resume_deadline.is_some() || s.resume_budget.is_some() || s.resume_host.is_some();
    let words = if given { words(&resumes) } else { String::new() };
    Ok((resumes, words))
}

/// `--resume-budget MIB`: 0 keeps no session, and serves none; else from
/// one session's buffer to [`MOST_MIB`].
fn budget_of(text: &str) -> Result<usize, Refusal> {
    let least = replay::DEFAULT_CAPACITY >> 20;
    match text.trim().parse::<usize>() {
        Ok(0) => Ok(0),
        Ok(mib) if (least..=MOST_MIB).contains(&mib) => Ok(mib << 20),
        _ => Err(Refusal::usage(format!(
            "--resume-budget {text:?}: the MiB of replay buffers of the resumable sessions in all, from {least} (one \
             session) to {MOST_MIB}, or 0 for none"
        ))),
    }
}

/// The sessions in the words of the first line.
fn words(resumes: &Resumes) -> String {
    let (budget, each) = (resumes.budget(), replay::DEFAULT_CAPACITY);
    if budget < each {
        return ", no resumable session (--resume-budget 0)".to_string();
    }
    let name = resumes.name().map(|n| format!(", each link to {}", podssh_relay::token::relay_name(n)));
    let n = budget / each;
    format!(
        ", resumable sessions within {} MiB of replay buffers ({n} session{} of 4 MiB), each kept {} after a loss{}",
        budget >> 20,
        if n == 1 { "" } else { "s" },
        deadline::span(resumes.deadline()),
        name.unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(deadline: Option<&str>, budget: Option<&str>, host: Option<&str>) -> ServeArgs {
        ServeArgs {
            resume_deadline: deadline.map(String::from),
            resume_budget: budget.map(String::from),
            resume_host: host.map(String::from),
            ..ServeArgs::default()
        }
    }

    #[test]
    fn with_no_flag_the_sessions_are_the_default_and_the_line_says_nothing() {
        let (resumes, words) = of(&args(None, None, None)).unwrap();
        let default = Settings::default().resume_deadline;
        assert_eq!((resumes.budget(), resumes.deadline(), resumes.name()), (BUDGET, default, None));
        assert_eq!(words, "");
    }

    #[test]
    fn the_flags_set_the_budget_the_deadline_and_the_name_and_the_line_says_them() {
        let (resumes, words) = of(&args(Some("30m"), Some("64"), Some("relay-2.relay.example.org:8443"))).unwrap();
        assert_eq!((resumes.budget(), resumes.deadline().as_secs()), (64 << 20, 1800));
        let name = resumes.name().cloned().unwrap();
        assert_eq!((name.host.as_str(), name.port), ("relay-2.relay.example.org", 8443));
        assert_eq!(
            words,
            ", resumable sessions within 64 MiB of replay buffers (16 sessions of 4 MiB), each kept 30 min after a \
             loss, each link to relay-2.relay.example.org:8443"
        );
        let (none, words) = of(&args(None, Some("0"), None)).unwrap();
        assert_eq!((none.budget(), words.as_str()), (0, ", no resumable session (--resume-budget 0)"));
        assert_eq!(none.offer()["layer"], false, "a budget of none offers no road");
    }

    #[test]
    fn a_flag_out_of_its_bounds_is_refused_with_its_words() {
        for (a, says) in [
            (args(Some("30s"), None, None), "from 1 minute to 72 h"),
            (args(Some("10x"), None, None), "a whole number, then s, m, h or d"),
            (args(None, Some("3"), None), "from 4 (one session) to 16384, or 0 for none"),
            (args(None, Some("16385"), None), "from 4 (one session) to 16384"),
            (args(None, Some("lots"), None), "--resume-budget \"lots\""),
            (args(None, None, Some("a/b")), "--resume-host"),
            (args(None, None, Some("relay.example.org:0")), "--resume-host"),
        ] {
            let refusal = of(&a).err().unwrap_or_else(|| panic!("taken: {a:?}"));
            assert_eq!(refusal.code, 64, "{a:?}");
            assert!(refusal.message.contains(says), "{a:?}: {}", refusal.message);
        }
    }
}
