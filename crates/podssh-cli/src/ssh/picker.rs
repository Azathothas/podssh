//! A host picker (T-188): `podssh ssh` with no destination, when stdin and
//! stdout are both terminals, lists the literal `Host` names of ssh_config
//! (T-043) with a number each, and logs in to the one picked as if it were
//! typed. In each other case nothing is read, and the run refuses as before
//! (64): a script still gets its usage error. The list is never a guess: no
//! pattern, no negated name, and no name of `known_hosts`, whose names can
//! be hashed.

use podssh_ssh::Hop;

use super::args::SshArgs;
use super::config::{Context, Given};
use super::options::Settings;
use super::resolve::Env;
use crate::pager::Tty;
use crate::relay_settings::Refusal;

/// The refusal of a run with no destination, as the resolve words it.
const MISSING: &str = "missing destination: podssh ssh [user@]host [command]";
/// The most answers before the picker gives up.
const ROUNDS: usize = 20;

/// Who answers the picker: the terminal, or a test's answers.
pub trait Keys {
    /// One line typed after `prompt`, which shows the list.
    fn line(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// The controlling terminal, as podssh asks each question there, with the
/// answer echoed; with no terminal it fails, and picks nothing.
pub struct Terminal;

impl Keys for Terminal {
    fn line(&mut self, prompt: &str) -> std::io::Result<String> {
        podssh_ssh::terminal::read_line(prompt, true).map(|line| line.as_str().to_string())
    }
}

/// Whether the picker is shown: no destination, and stdin and stdout both
/// terminals, as a person is there to read the list and to answer it.
pub fn wanted(args: &SshArgs, tty: Tty) -> bool {
    args.destination.is_none() && tty.stdin && tty.stdout
}

/// The literal `Host` names of the ssh_config files of `args` and `env`:
/// `-F`, else `PODSSH_SSH_CONFIG`, else `~/.ssh/config` and the system's
/// file, with their `Include`s, in that order.
pub fn names(args: &SshArgs, env: &Env) -> Result<Vec<String>, String> {
    let source = super::config::file(args.config.as_deref(), env.ssh_config.as_deref(), env.home.as_deref());
    // No host is known yet: `%h` and `%n` of an `Include` are empty.
    let target = Hop { user: None, host: String::new(), port: 22, tls: false };
    let cli = Settings::default();
    let tokens = |file: &Settings| super::tokens::include_tokens(args, &cli, &target, env, file);
    let ctx = Context {
        host: "",
        home: env.home.as_deref(),
        system: env.system_config.as_deref(),
        tokens: &tokens,
        given: Given { local_user: env.user.as_deref(), ..Given::default() },
    };
    super::config::host_names(&source, &ctx)
}

/// `args` with the destination picked, when the picker is wanted and
/// ssh_config has names; `None` else, so that the run refuses as before.
/// Each end with no host picked is a refusal (64).
pub fn pick(args: &SshArgs, tty: Tty, env: &Env, keys: &mut dyn Keys) -> Result<Option<SshArgs>, Refusal> {
    if !wanted(args, tty) {
        return Ok(None);
    }
    let names =
        names(args, env).map_err(|why| Refusal::usage(format!("{MISSING}; no list of the Host names: {why}")))?;
    if names.is_empty() {
        return Ok(None);
    }
    let picked = choose(&names, keys)?;
    Ok(Some(SshArgs { destination: Some(picked), ..args.clone() }))
}

/// One name of `names`, as the person answers: a number of the list picks
/// that name, and other text narrows the list to the names that hold it,
/// case set aside. An empty line, the end of input (Ctrl-D) and a terminal
/// that fails pick none.
pub fn choose(names: &[String], keys: &mut dyn Keys) -> Result<String, Refusal> {
    let mut list: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut note = String::new();
    for _ in 0..ROUNDS {
        let mut prompt = String::new();
        for (i, name) in list.iter().enumerate() {
            prompt.push_str(&format!("{:>4}  {name}\n", i + 1));
        }
        let count = list.len();
        prompt.push_str(&format!("{note}Host to log in to, 1 to {count}, or text that narrows the list: "));
        let line = keys.line(&prompt).map_err(|e| Refusal::usage(format!("{MISSING}; the host picker: {e}")))?;
        let answer = line.trim();
        if answer.is_empty() {
            return Err(Refusal::usage(format!("{MISSING}; no host was picked")));
        }
        if let Ok(n) = answer.parse::<usize>() {
            if let Some(name) = n.checked_sub(1).and_then(|i| list.get(i)) {
                return Ok((*name).to_string());
            }
            note = format!("{answer} is not a number of the list.\n");
            continue;
        }
        let lower = answer.to_lowercase();
        let narrowed: Vec<&str> = list.iter().copied().filter(|name| name.to_lowercase().contains(&lower)).collect();
        if narrowed.is_empty() {
            note = format!("No host of the list holds {answer}.\n");
        } else {
            list = narrowed;
            note.clear();
        }
    }
    Err(Refusal::usage(format!("{MISSING}; no host was picked in {ROUNDS} answers")))
}
