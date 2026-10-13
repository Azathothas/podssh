//! `--expect TEXT --send TEXT` (T-191): rules that wait for a literal text
//! in the output of a session with a pty, then send keys, in the order
//! given; `--expect-timeout` is the time of each (`podssh_ssh::expect`).
//! The keys are on the command line, which each process of the host can
//! read: they are no place for a password, which comes through
//! `SSH_ASKPASS`. A session that cannot have a pty, or whose sessions
//! follow one another, cannot go with them, and such a run makes a
//! connection of its own: a master's session would not read the rules.

use std::time::Duration;

use podssh_ssh::expect::{Rule, Rules, WINDOW};
use podssh_ssh::{Request, RequestTty};

use super::args::SshArgs;
use super::resolve::Resolved;
use crate::relay_settings::Refusal;

/// How long each rule waits when `--expect-timeout` gives no time.
pub const WAIT: Duration = Duration::from_secs(30);

/// Check the rules, and keep them in `resolved`.
pub fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    if args.expect.is_empty() {
        if args.expect_timeout.is_some() {
            return Err("--expect-timeout is the time of each --expect; give --expect TEXT --send TEXT too".into());
        }
        return Ok(());
    }
    let rules = pairs(&args.expect)?;
    let wait = match args.expect_timeout.as_deref() {
        None => WAIT,
        Some(text) => crate::non_interactive::parse_duration("--expect-timeout", text)
            .map_err(|refusal| refusal.message.trim_start_matches("podssh: ").to_string())?,
    };
    let options = &resolved.options;
    let with = match &options.request {
        Request::StdioForward(_) => Some("-W"),
        Request::Nothing => Some("-N"),
        Request::Subsystem(_) => Some("-s"),
        _ if options.request_tty == RequestTty::No => Some("-T or RequestTTY=no"),
        _ if options.elevate.is_some() => Some("--sudo or --su"),
        _ if resolved.persist.is_some() => Some("--persist"),
        _ => None,
    };
    if let Some(with) = with {
        return Err(format!("--expect reads the output of a session with a pty; it cannot go with {with}").into());
    }
    if resolved.control.path.take().is_some() {
        resolved.notes.push("--expect makes a connection of its own: ControlPath has no effect".into());
    }
    resolved.options.expect = Some(Rules { rules, wait });
    Ok(())
}

/// The rules of `given`: each `--expect`, then its `--send`, in order.
pub fn pairs(given: &[(bool, String)]) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    let mut words = given.iter();
    while let Some((is_expect, text)) = words.next() {
        if !is_expect {
            return Err(format!("--send {text:?} has no --expect before it: give --expect TEXT --send TEXT"));
        }
        let Some((false, keys)) = words.next() else {
            return Err(format!("--expect {text:?} has no --send after it: give --expect TEXT --send TEXT"));
        };
        if text.is_empty() || text.len() > WINDOW {
            return Err(format!("--expect {text:?}: a text of 1 byte to {} KiB", WINDOW / 1024));
        }
        rules.push(Rule { expect: text.as_bytes().to_vec(), send: keys_of(keys)? });
    }
    Ok(rules)
}

/// The bytes of a `--send`: `\r`, `\n`, `\t`, `\\` and `\xNN` (two hex
/// digits) read, each other byte as it is.
pub fn keys_of(text: &str) -> Result<Vec<u8>, String> {
    let bad = || format!("--send {text:?}: after \\ comes r, n, t, \\ or x and two hex digits");
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b't') => out.push(b'\t'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let hex =
                    text.get(i + 2..i + 4).filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(bad)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| bad())?);
                i += 2;
            }
            _ => return Err(bad()),
        }
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(words: &[(bool, &str)]) -> Vec<(bool, String)> {
        words.iter().map(|(e, t)| (*e, t.to_string())).collect()
    }

    #[test]
    fn the_keys_read_their_escapes() {
        assert_eq!(keys_of(r"echo EXP\r").unwrap(), b"echo EXP\r");
        assert_eq!(keys_of(r"a\nb\tc\\d\x03\x1B").unwrap(), b"a\nb\tc\\d\x03\x1b");
        assert_eq!(keys_of("plain é").unwrap(), "plain é".as_bytes());
        for bad in [r"\q", r"\", r"\x1", r"\xZZ", r"a\x"] {
            assert!(keys_of(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn each_expect_has_its_send_after_it() {
        let rules =
            pairs(&given(&[(true, "$ "), (false, r"echo EXP\r"), (true, "EXP"), (false, r"exit 4\r")])).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!((rules[1].expect.as_slice(), rules[1].send.as_slice()), (&b"EXP"[..], &b"exit 4\r"[..]));
        for bad in [
            given(&[(false, "x")]),
            given(&[(true, "a")]),
            given(&[(true, "a"), (true, "b"), (false, "c")]),
            given(&[(true, ""), (false, "x")]),
        ] {
            assert!(pairs(&bad).is_err(), "{bad:?}");
        }
        assert!(pairs(&given(&[(true, "a"), (false, "")])).is_ok(), "an empty --send waits and sends nothing");
    }

    /// The rules through the parser and `resolve`: a session with a pty
    /// takes them, and what cannot have one refuses them.
    #[test]
    fn the_rules_go_with_a_session_that_can_have_a_pty() {
        let env = crate::ssh::resolve::Env { user: Some("user".into()), ..Default::default() };
        let resolved = |words: &[&str]| {
            let mut argv = vec!["ssh"];
            argv.extend_from_slice(words);
            let crate::tree::Parsed::Command { ssh: Some(args), .. } = crate::tree::parse(argv) else {
                panic!("{words:?} is no ssh command")
            };
            crate::ssh::resolve::resolve(&args, &env)
        };
        let ok = resolved(&["-tt", "--expect", "$ ", "--send", r"exit\r", "--expect-timeout", "2s", "h"]).unwrap();
        let rules = ok.options.expect.expect("the rules");
        assert_eq!((rules.rules.len(), rules.wait), (1, Duration::from_secs(2)));
        assert!(resolved(&["h"]).unwrap().options.expect.is_none());
        for (words, says) in [
            (&["-T", "--expect", "a", "--send", "b", "h"][..], "-T"),
            (&["-N", "--expect", "a", "--send", "b", "h"][..], "-N"),
            (&["--expect", "a", "--send", "b", "-W", "x:1", "h"][..], "-W"),
            (&["--expect", "a", "--send", "b", "--expect-timeout", "0", "h"][..], "--expect-timeout"),
            (&["--expect-timeout", "5s", "h"][..], "--expect-timeout"),
            (&["--send", "b", "--expect", "a", "h"][..], "no --expect before it"),
        ] {
            let why = resolved(words).unwrap_err();
            assert!(why.contains(says), "{words:?}: {why}");
        }
    }
}
