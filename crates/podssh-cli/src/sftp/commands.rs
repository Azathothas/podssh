//! A line of `sftp`, from a batch or the prompt, as OpenSSH reads it: an
//! optional `-` (an error does not end the batch) and `@` (the line is not
//! echoed), then the words of a command, with quotes and backslashes.

/// One line that names a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// `-`: an error of this command does not end a batch.
    pub keep_going: bool,
    /// Not `@`: a batch prints the line before it runs it.
    pub echo: bool,
    pub command: Command,
}

/// The commands of `podssh sftp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Get { remote: String, local: Option<String> },
    Put { local: String, remote: Option<String> },
    Rename { from: String, to: String },
    Rm(String),
    Mkdir { path: String, parents: bool },
    Rmdir(String),
    Ls { path: Option<String>, long: bool, all: bool },
    Cd(Option<String>),
    Lcd(Option<String>),
    Pwd,
    Lpwd,
    Chmod { mode: u32, path: String },
    Df { path: Option<String>, human: bool, inodes: bool },
    Help,
    Version,
    Bye,
}

/// The commands of OpenSSH's sftp that podssh has not built yet.
const NOT_YET: &[&str] =
    &["lls", "lmkdir", "ln", "symlink", "chgrp", "chown", "progress", "lumask", "copy", "cp", "lchdir"];

/// The commands that `help` lists, with their forms.
pub const HELP: &[(&str, &str)] = &[
    ("get [-af] remote [local]", "copy a file here, verified by its digest"),
    ("put [-af] local [remote]", "copy a file there, verified by its digest"),
    ("reget, reput", "the same: a copy that broke goes on by itself"),
    ("rename old new", "rename a file on the server"),
    ("rm path", "remove a file; * and ? match in the last name"),
    ("mkdir [-p] path", "make a directory"),
    ("rmdir path", "remove an empty directory"),
    ("ls [-la] [path]", "list a directory"),
    ("cd [path], lcd [path]", "change the directory there, or here"),
    ("pwd, lpwd", "print the directory there, or here"),
    ("chmod mode path", "set the permission bits, in octal"),
    ("df [-hi] [path]", "the space of a file system (statvfs@openssh.com)"),
    ("help, version", "this list; the SFTP version"),
    ("bye, exit, quit", "end"),
];

/// Read a line; `None` for an empty line or a comment.
pub fn parse_line(text: &str) -> Result<Option<Line>, String> {
    let mut rest = text.trim();
    if rest.is_empty() || rest.starts_with('#') {
        return Ok(None);
    }
    let (mut keep_going, mut echo) = (false, true);
    loop {
        if let Some(r) = rest.strip_prefix('-').filter(|_| !keep_going) {
            keep_going = true;
            rest = r;
        } else if let Some(r) = rest.strip_prefix('@').filter(|_| echo) {
            echo = false;
            rest = r;
        } else {
            break;
        }
    }
    let words = words(rest)?;
    let Some((name, args)) = words.split_first() else { return Ok(None) };
    Ok(Some(Line { keep_going, echo, command: command(name, args)? }))
}

/// The words of a line: blanks separate them; `'…'` is taken as it is;
/// `"…"` and an unquoted `\` escape the next character.
pub fn words(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => out.extend(word.take()),
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => w.push(c),
                        None => return Err("a quote ' is not closed".into()),
                    }
                }
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => w.push(chars.next().ok_or("a line ends with \\")?),
                        Some(c) => w.push(c),
                        None => return Err("a quote \" is not closed".into()),
                    }
                }
            }
            '\\' => word.get_or_insert_with(String::new).push(chars.next().ok_or("a line ends with \\")?),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    out.extend(word);
    Ok(out)
}

/// The switches at the head of `args` (`-la`), and the words after them.
fn switches<'a>(name: &str, args: &'a [String], known: &str) -> Result<(String, &'a [String]), String> {
    let mut seen = String::new();
    let mut i = 0;
    while let Some(word) = args.get(i).filter(|w| w.len() > 1 && w.starts_with('-')) {
        for c in word[1..].chars() {
            if !known.contains(c) {
                return Err(format!("{name}: -{c} is not an option of {name}"));
            }
            seen.push(c);
        }
        i += 1;
    }
    Ok((seen, &args[i..]))
}

fn command(name: &str, args: &[String]) -> Result<Command, String> {
    let arity = |want: std::ops::RangeInclusive<usize>, got: &[String], form: &str| {
        if want.contains(&got.len()) {
            Ok(())
        } else {
            Err(format!("{name}: the form is {form}"))
        }
    };
    let opt = |list: &[String], i: usize| list.get(i).cloned();
    Ok(match name {
        "get" | "reget" | "put" | "reput" => {
            let (seen, rest) = switches(name, args, "afpR")?;
            if seen.contains('p') {
                return Err(format!("{name} -p: keeping the mode and the times of a file is not implemented yet"));
            }
            if seen.contains('R') {
                return Err(format!("{name} -R: copying a directory is not implemented yet"));
            }
            arity(1..=2, rest, &format!("{name} [-af] path [path]"))?;
            if name.ends_with("get") {
                Command::Get { remote: rest[0].clone(), local: opt(rest, 1) }
            } else {
                Command::Put { local: rest[0].clone(), remote: opt(rest, 1) }
            }
        }
        "rename" => {
            arity(2..=2, args, "rename old new")?;
            Command::Rename { from: args[0].clone(), to: args[1].clone() }
        }
        "rm" => {
            arity(1..=1, args, "rm path")?;
            Command::Rm(args[0].clone())
        }
        "mkdir" => {
            let (seen, rest) = switches(name, args, "p")?;
            arity(1..=1, rest, "mkdir [-p] path")?;
            Command::Mkdir { path: rest[0].clone(), parents: seen.contains('p') }
        }
        "rmdir" => {
            arity(1..=1, args, "rmdir path")?;
            Command::Rmdir(args[0].clone())
        }
        "ls" | "dir" => {
            let (seen, rest) = switches(name, args, "1afhlnrSt")?;
            arity(0..=1, rest, "ls [-1afhlnrSt] [path]")?;
            Command::Ls { path: opt(rest, 0), long: seen.contains('l') || seen.contains('n'), all: seen.contains('a') }
        }
        "cd" | "chdir" => {
            arity(0..=1, args, "cd [path]")?;
            Command::Cd(opt(args, 0))
        }
        "lcd" => {
            arity(0..=1, args, "lcd [path]")?;
            Command::Lcd(opt(args, 0))
        }
        "pwd" => Command::Pwd,
        "lpwd" => Command::Lpwd,
        "chmod" => {
            let (_, rest) = switches(name, args, "h")?;
            arity(2..=2, rest, "chmod mode path")?;
            let mode = u32::from_str_radix(&rest[0], 8)
                .ok()
                .filter(|m| *m <= 0o7777)
                .ok_or_else(|| format!("chmod: {:?} is not a mode in octal", rest[0]))?;
            Command::Chmod { mode, path: rest[1].clone() }
        }
        "df" => {
            let (seen, rest) = switches(name, args, "hi")?;
            arity(0..=1, rest, "df [-hi] [path]")?;
            Command::Df { path: opt(rest, 0), human: seen.contains('h'), inodes: seen.contains('i') }
        }
        "help" | "?" => Command::Help,
        "version" => Command::Version,
        "bye" | "exit" | "quit" => Command::Bye,
        name if name.starts_with('!') => return Err("! runs a local command, which podssh sftp does not".into()),
        name if NOT_YET.contains(&name) => return Err(format!("{name}: not implemented yet in podssh sftp")),
        name => return Err(format!("{name}: not a command of sftp; help lists them")),
    })
}

/// Whether `name` matches `pattern`, where `*` matches any run and `?` one
/// character.
pub fn matches(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whether a path's last name holds a pattern.
pub fn is_pattern(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|last| last.contains(['*', '?']))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> Line {
        parse_line(text).expect("parses").expect("a command")
    }

    #[test]
    fn the_prefixes_and_the_quotes_are_read_as_openssh_reads_them() {
        assert_eq!(
            line("-rm /tmp/blah*"),
            Line { keep_going: true, echo: true, command: Command::Rm("/tmp/blah*".into()) }
        );
        assert_eq!(line("@-pwd"), Line { keep_going: true, echo: false, command: Command::Pwd });
        assert!(!line("-@pwd").echo);
        assert_eq!(
            line(r#"put 'a b' "c \"d\"""#).command,
            Command::Put { local: "a b".into(), remote: Some(r#"c "d""#.into()) }
        );
        assert_eq!(line(r"get a\ b").command, Command::Get { remote: "a b".into(), local: None });
        assert_eq!(parse_line("   "), Ok(None));
        assert_eq!(parse_line("# a comment"), Ok(None));
        assert!(parse_line("put 'a").is_err());
    }

    #[test]
    fn each_command_takes_its_form_and_refuses_another() {
        assert_eq!(line("mkdir -p a/b").command, Command::Mkdir { path: "a/b".into(), parents: true });
        assert_eq!(line("ls -la").command, Command::Ls { path: None, long: true, all: true });
        assert_eq!(line("chmod 640 f").command, Command::Chmod { mode: 0o640, path: "f".into() });
        assert_eq!(line("reget a b").command, Command::Get { remote: "a".into(), local: Some("b".into()) });
        assert_eq!(line("exit").command, Command::Bye);
        for (bad, says) in [
            ("get -p a", "not implemented yet"),
            ("put -R d", "copying a directory"),
            ("rename a", "the form is"),
            ("chmod 999 f", "octal"),
            ("ls -z", "not an option"),
            ("lmkdir d", "not implemented yet"),
            ("!ls", "local command"),
            ("frobnicate", "not a command"),
        ] {
            let why = parse_line(bad).expect_err(bad);
            assert!(why.contains(says), "{bad}: {why}");
        }
    }

    #[test]
    fn a_pattern_matches_as_a_shell_matches_one_name() {
        assert!(matches("blah*", "blah.txt") && matches("*", "") && matches("a?c", "abc"));
        assert!(matches("*.log", "x.y.log") && !matches("*.log", "x.log.gz") && !matches("a?c", "ac"));
        assert!(is_pattern("dir/*.txt") && !is_pattern("di*r/x.txt"));
    }
}
