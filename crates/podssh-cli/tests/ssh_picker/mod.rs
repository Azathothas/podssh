//! The host picker (T-188), a module of `tests/ssh_args.rs`, whose own file
//! is near 500 lines: with no destination, and stdin and stdout both
//! terminals, the literal `Host` names of ssh_config, a number that picks
//! and a text that narrows; in each other case nothing is read, and the run
//! refuses as before (64). The plant of the entry, the picker with stdout
//! alone a terminal, reads a line here and fails.

use std::path::PathBuf;

use podssh_cli::pager::Tty;
use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::picker::{choose, names, pick, wanted, Keys};
use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env};

/// The answers of a test, in order, and the prompts that came. With no
/// answer left, a prompt fails the test: the picker read a line.
struct Typed {
    answers: Vec<std::io::Result<String>>,
    prompts: Vec<String>,
}

impl Keys for Typed {
    fn line(&mut self, prompt: &str) -> std::io::Result<String> {
        self.prompts.push(prompt.to_string());
        assert!(!self.answers.is_empty(), "the picker read a line after: {prompt}");
        self.answers.remove(0)
    }
}

fn typed(answers: &[&str]) -> Typed {
    Typed { answers: answers.iter().map(|a| Ok(a.to_string())).collect(), prompts: Vec::new() }
}

/// A scratch home of one test, private as a user's home is (each file of
/// it is checked), removed when dropped.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("podssh-picker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        podssh_relay::cache::private_dir(&dir).expect("a scratch home");
        std::fs::create_dir_all(dir.join(".ssh").join("conf.d")).expect("a scratch home");
        Home(dir)
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("a config file");
        path.display().to_string()
    }

    /// `~/.ssh/config` of this home, and no system file.
    fn env(&self) -> Env {
        Env { home: Some(self.0.clone()), user: Some("lu".into()), ..Env::default() }
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const BOTH: Tty = Tty { stdin: true, stdout: true };

#[test]
fn no_terminal_or_stdout_alone_reads_nothing_and_exits_64() {
    let h = Home::new("gate");
    h.file(".ssh/config", "Host one\nHost two\n");
    let none = SshArgs::default();
    for tty in [Tty::none(), Tty { stdin: false, stdout: true }, Tty { stdin: true, stdout: false }] {
        assert!(!wanted(&none, tty), "{tty:?}");
        // No answer: a prompt would fail the test.
        assert_eq!(pick(&none, tty, &h.env(), &mut typed(&[])), Ok(None), "{tty:?}");
    }
    // The run then refuses as before.
    let refusal = resolve_or_refuse(&none, &h.env()).unwrap_err();
    assert_eq!(refusal.code, 64);
    assert!(refusal.message.starts_with("missing destination"), "{}", refusal.message);
    // A destination, or no name to list: nothing is read either.
    let named = SshArgs { destination: Some("one".into()), ..SshArgs::default() };
    assert_eq!(pick(&named, BOTH, &h.env(), &mut typed(&[])), Ok(None));
    let empty = Home::new("empty");
    assert_eq!(pick(&none, BOTH, &empty.env(), &mut typed(&[])), Ok(None));
}

#[test]
fn the_names_are_the_literal_host_names_in_the_order_of_the_files() {
    let h = Home::new("names");
    h.file(".ssh/conf.d/extra", "Host extra1 extra?\n");
    h.file(
        ".ssh/config",
        "Include conf.d/*\nHost web1 web2\n    Port 2222\nHost *.example.org !bad.example.org\nHost db\n\
         Host web1\nHost inner\n    Include never/*\n",
    );
    assert_eq!(names(&SshArgs::default(), &h.env()).unwrap(), ["extra1", "web1", "web2", "db", "inner"]);
    // -F names the one file; none names none.
    let other = h.file("other", "Host only\n");
    let given = SshArgs { config: Some(other), ..SshArgs::default() };
    assert_eq!(names(&given, &h.env()).unwrap(), ["only"]);
    let nothing = SshArgs { config: Some("none".into()), ..SshArgs::default() };
    assert!(names(&nothing, &h.env()).unwrap().is_empty());
}

#[test]
fn a_number_picks_and_text_narrows_the_list() {
    let names: Vec<String> = ["web1", "web2", "db", "Web-old"].iter().map(|n| n.to_string()).collect();
    assert_eq!(choose(&names, &mut typed(&["2"])).unwrap(), "web2");
    let mut keys = typed(&["WEB", "9", "3"]);
    assert_eq!(choose(&names, &mut keys).unwrap(), "Web-old");
    assert!(keys.prompts[0].contains("   1  web1\n") && keys.prompts[0].contains("   4  Web-old\n"));
    assert!(!keys.prompts[1].contains("db") && keys.prompts[1].contains("   3  Web-old\n"), "{}", keys.prompts[1]);
    assert!(keys.prompts[2].contains("9 is not a number of the list"), "{}", keys.prompts[2]);
    let mut keys = typed(&["zzz", "1"]);
    assert_eq!(choose(&names, &mut keys).unwrap(), "web1");
    assert!(keys.prompts[1].contains("No host of the list holds zzz"), "{}", keys.prompts[1]);
    // An empty line (also Ctrl-D, the end of input), or a terminal that
    // fails: no host, and 64.
    let ends = [Ok(String::new()), Ok("  ".to_string()), Err(std::io::Error::other("no terminal"))];
    for end in ends {
        let mut keys = Typed { answers: vec![end], prompts: Vec::new() };
        let refusal = choose(&names, &mut keys).unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.starts_with("missing destination"), "{}", refusal.message);
    }
}

#[test]
fn the_name_picked_takes_the_path_of_a_typed_one() {
    let h = Home::new("pick");
    h.file(".ssh/config", "Host one\n    Port 2201\nHost two\n");
    let args = SshArgs { command: vec!["uptime".into()], ..SshArgs::default() };
    let picked = pick(&args, BOTH, &h.env(), &mut typed(&["2"])).unwrap().unwrap();
    assert_eq!((picked.destination.as_deref(), picked.command.clone()), (Some("two"), vec!["uptime".to_string()]));
    // Its Host block applies, as to a name that was typed.
    let picked = pick(&args, BOTH, &h.env(), &mut typed(&["1"])).unwrap().unwrap();
    assert_eq!(resolve(&picked, &h.env()).unwrap().options.destination.port, 2201);
}
