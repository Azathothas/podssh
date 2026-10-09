//! The addresses of `podssh pipe A B` (T-174): `KIND:REST`, both checked
//! before anything starts. `-` is `stdio`. The local kinds are here:
//! `stdio`, `fd:N` (Unix) and `exec:CMD`. The kinds of later entries are
//! known, and refused as not built yet, so that a script gets 70 and not a
//! usage error.

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::relay_settings::Refusal;

/// One side of a pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// stdin and stdout.
    Stdio,
    /// A descriptor that podssh inherited, 3 or more (Unix).
    Fd(i32),
    /// A program and its words, started with no shell.
    Exec(Vec<String>),
}

/// The kinds that an unknown kind lists.
pub const KINDS: &[&str] = &["-", "stdio", "fd:N", "exec:CMD"];

/// The kinds of later entries: remote ends (T-175), a local socket (T-176),
/// listeners (T-177) and a serial line (T-181).
const LATER: &[&str] = &["relay", "ssh", "node", "iroh", "unix-connect", "unix-listen", "tcp-listen", "serial"];

/// A and B, each checked: no side starts before both are good.
pub fn both(a: Option<&str>, b: Option<&str>) -> Result<(Address, Address), Refusal> {
    let a = parse(a.ok_or("missing A and B: the two addresses to join, such as stdio exec:CMD")?)?;
    let b = parse(b.ok_or("missing B: the second address")?)?;
    if a == Address::Stdio && b == Address::Stdio {
        return Err(Refusal::usage("stdio on both sides joins stdin to stdout; name another address"));
    }
    Ok((a, b))
}

/// One address.
pub fn parse(text: &str) -> Result<Address, Refusal> {
    if text == "-" || text == "stdio" {
        return Ok(Address::Stdio);
    }
    let kinds = KINDS.join(", ");
    let Some((kind, rest)) = text.split_once(':') else {
        return Err(Refusal::usage(format!("{text}: not an address; the kinds are {kinds}")));
    };
    match kind {
        "fd" => fd(rest).map(Address::Fd),
        "exec" => words(rest).map(Address::Exec).map_err(|why| Refusal::usage(format!("exec:{rest}: {why}"))),
        "stdio" => Err(Refusal::usage("stdio takes nothing after it")),
        later if LATER.contains(&later) => Err(Refusal {
            message: format!("{later}: addresses are not built yet; the kinds are {kinds}"),
            code: EXIT_NOT_IMPLEMENTED,
        }),
        other => Err(Refusal::usage(format!("{other}: no such kind of address; the kinds are {kinds}"))),
    }
}

fn fd(rest: &str) -> Result<i32, Refusal> {
    if !cfg!(unix) {
        return Err(Refusal::usage(format!("fd:{rest}: descriptors are passed on Unix only")));
    }
    let n: i32 = rest.parse().map_err(|_| Refusal::usage(format!("fd:{rest}: N is a number")))?;
    if n < 3 {
        return Err(Refusal::usage(format!("fd:{n}: 0, 1 and 2 are stdio; name stdio")));
    }
    Ok(n)
}

/// The words of `exec:CMD`, as a shell splits them with its quotes only: no
/// variables, globs or backslash escapes, so a Windows path keeps its `\`.
/// podssh starts no shell, as it assumes none (`exec:sh -c 'CMD'` names one).
pub fn words(cmd: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    // A word that has begun, even an empty one in quotes.
    let mut begun = false;
    let mut quote: Option<char> = None;
    for c in cmd.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => word.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                begun = true;
            }
            None if c.is_whitespace() => {
                if begun {
                    words.push(std::mem::take(&mut word));
                    begun = false;
                }
            }
            None => {
                word.push(c);
                begun = true;
            }
        }
    }
    if let Some(q) = quote {
        return Err(format!("a {q} that does not close"));
    }
    if begun {
        words.push(word);
    }
    if words.is_empty() {
        return Err("names no program".into());
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(text: &str) -> i32 {
        parse(text).expect_err(text).code
    }

    #[test]
    fn the_local_kinds_parse_and_a_dash_is_stdio() {
        assert_eq!(parse("-").unwrap(), Address::Stdio);
        assert_eq!(parse("stdio").unwrap(), Address::Stdio);
        assert_eq!(parse("exec:cat").unwrap(), Address::Exec(vec!["cat".into()]));
        if cfg!(unix) {
            assert_eq!(parse("fd:3").unwrap(), Address::Fd(3));
        }
    }

    #[test]
    fn an_unknown_kind_is_a_usage_error_that_lists_the_kinds_and_a_later_kind_is_not_built() {
        let refusal = parse("tcp:example.org:80").unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.contains("exec:CMD"), "{}", refusal.message);
        assert_eq!(code("example.org"), 64);
        assert_eq!(code("stdio:x"), 64);
        for later in ["relay:example.org:80", "unix-connect:/run/x.sock", "tcp-listen:2222", "serial:/dev/ttyS0"] {
            assert_eq!(code(later), 70, "{later}");
        }
    }

    #[test]
    fn a_descriptor_is_a_number_from_3_and_only_on_unix() {
        assert_eq!(code("fd:x"), 64);
        assert_eq!(code("fd:0"), 64);
        assert_eq!(code("fd:2"), 64);
        if !cfg!(unix) {
            assert_eq!(code("fd:3"), 64);
        }
    }

    #[test]
    fn stdio_on_both_sides_is_refused_before_anything_starts() {
        let refusal = both(Some("-"), Some("stdio")).unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(both(Some("stdio"), Some("exec:cat")).is_ok());
        assert_eq!(both(None, None).unwrap_err().code, 64);
        assert_eq!(both(Some("stdio"), None).unwrap_err().code, 64);
        assert_eq!(both(Some("nonsense"), Some("exec:cat")).unwrap_err().code, 64);
    }

    #[test]
    fn words_split_at_blanks_and_keep_what_quotes_hold() {
        let split = |cmd: &str| words(cmd).unwrap();
        assert_eq!(split("sh -c 'exit 7'"), ["sh", "-c", "exit 7"]);
        assert_eq!(split(r#"printf "%s\n" a"#), ["printf", r"%s\n", "a"]);
        assert_eq!(split(r"C:\Tools\nc.exe -v"), [r"C:\Tools\nc.exe", "-v"]);
        assert_eq!(split("echo '' x"), ["echo", "", "x"]);
        assert_eq!(split("  a  b  "), ["a", "b"]);
        assert_eq!(split("a'b c'd"), ["ab cd"]);
        assert_eq!(split("echo $HOME *"), ["echo", "$HOME", "*"], "no variable and no glob");
        assert!(words("sh -c 'exit").is_err());
        assert!(words("   ").is_err());
        assert!(words("").is_err());
    }
}
