//! `podssh ssh --install NAME -N -R ... --persist` (T-393): a reverse
//! tunnel to a standard sshd, made a service of this user by the same ways
//! as a node, as a server that only the tunnel reaches is locked out while
//! it is down. The service runs this binary with the words that the user
//! typed, but `--install NAME`, in the directory where they were typed, so
//! that each flag, and each relative path among them, means what it meant;
//! after the verb, the options that a service needs whatever ssh_config
//! says ([`SERVICE_OPTIONS`]), and `--env-file`. `--uninstall NAME` removes
//! it, and `--env-file FILE` sets the variables of FILE first and holds the
//! service's lock, as for a node.

use std::io::Write;
use std::path::Path;

use super::{Kind, Spec};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;

/// The options of each service of ssh, first on its command line, where a
/// value wins over a later one and over ssh_config, as OpenSSH keeps the
/// first: nobody is there to answer a prompt; `-f` or a control master
/// would end the process that the service manager watches, or tie it to
/// another; a forward that the server refuses is a tunnel that serves
/// nothing, which ends the run so that the next start asks again.
pub(super) const SERVICE_OPTIONS: &[&str] =
    &["BatchMode=yes", "ForkAfterAuthentication=no", "ControlPath=none", "ExitOnForwardFailure=yes"];

/// `podssh ssh`'s first step: `--env-file`, `--install` and `--uninstall`.
/// `Some(code)` ends the run.
pub(crate) fn first(args: &SshArgs, err: &mut dyn Write) -> Option<i32> {
    let service = args.install.is_some() || args.uninstall.is_some();
    if args.env_file.is_some() && service {
        let why = "--env-file is the file that --install writes for the service: give it to the service's run alone";
        return Some(Refusal::usage(why).report("ssh", err));
    }
    if args.install.is_some() && args.uninstall.is_some() {
        return Some(Refusal::usage("--install and --uninstall: give one").report("ssh", err));
    }
    if let Some(file) = &args.env_file {
        return super::env::apply(Path::new(file)).err().map(|refusal| refusal.report("ssh", err));
    }
    if let Some(name) = &args.uninstall {
        return Some(match checked(name, "--uninstall") {
            Ok(()) => super::uninstall(Kind::Ssh, name, err),
            Err(refusal) => refusal.report("ssh", err),
        });
    }
    let name = args.install.as_deref()?;
    Some(match prepare(args, name) {
        Ok((spec, notes)) => super::install(&spec, &notes, &mut std::io::stdout(), err),
        Err(refusal) => refusal.report("ssh", err),
    })
}

/// NAME as the name of a service: as a pair's label, which names files.
fn checked(name: &str, flag: &str) -> Result<(), Refusal> {
    podssh_ws::names::check_node_name(name).map_err(|_| {
        Refusal::usage(format!(
            "{flag} {name:?}: a name of letters, digits, '.', '-' and '_', 128 at most, that starts with neither \
             '.' nor '-'"
        ))
    })
}

/// The service's command and the notes on what it carries; the file of its
/// variables is written here, once the command line resolved as each start
/// will resolve it.
fn prepare(args: &SshArgs, name: &str) -> Result<(Spec, Vec<String>), Refusal> {
    checked(name, "--install")?;
    let refused = [
        (args.detach, "-f", "the service manager watches the run itself, which must stay in the foreground"),
        (args.stdio_forward.is_some(), "-W", "its stdin and stdout would be the stream, and a service has neither"),
        (args.print_config, "-G", "it connects to nothing"),
        (args.control_command.is_some(), "-O", "a service runs a tunnel, not a request to a master"),
        (args.attach.is_some(), "--attach", "a service runs a tunnel, with no shell"),
        (args.upgrade, "--upgrade", "the temporary node of --upgrade ends with its session"),
        (args.snippet.is_some(), "--snippet", "a service runs no command"),
    ];
    if let Some((_, flag, why)) = refused.iter().find(|(given, ..)| *given) {
        return Err(Refusal::usage(format!("--install with {flag}: {why}")));
    }
    if !args.no_command || !args.command.is_empty() {
        return Err(Refusal::usage("--install makes a tunnel a service: give -N and no command"));
    }
    if !args.persist {
        return Err(Refusal::usage(
            "--install needs --persist, which connects again after a lost link and asks for each -R again",
        ));
    }
    // Refused now, not at each start of the service.
    let env = crate::ssh::resolve::Env::from_process();
    crate::ssh::resolve::resolve_or_refuse(args, &env)?;
    let words = crate::detach::run_words()
        .ok_or_else(|| Refusal::config("--install: the words of this run were not kept"))?
        .iter()
        .map(|word| word.to_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()
        .ok_or_else(|| Refusal::usage("--install: a word that is not UTF-8 cannot go in a service's command"))?;
    let mut notes = Vec::new();
    let exe = super::this_binary()?;
    let env_file = super::env_file(Kind::Ssh, name, &mut notes)?;
    let words = service_words(&words, &env_file);
    super::text::one_line(&words)?;
    let dir = std::env::current_dir().ok();
    if let Some(dir) = &dir {
        super::text::one_line(&[dir.display().to_string()])?;
        notes.push(format!("it runs in {}, for the relative paths of its words", dir.display()));
    }
    notes.push(format!(
        "it logs in with {}: with a key that needs no passphrase and no agent, and a host key in known_hosts; \
         run the same command once in the foreground to see that it does",
        SERVICE_OPTIONS.join(", ")
    ));
    let spec = Spec { kind: Kind::Ssh, name: name.to_string(), exe, args: words, dir, env_file };
    Ok((spec, notes))
}

/// The words of the service, from those of this run (the verb first): the
/// verb, [`SERVICE_OPTIONS`], `--env-file FILE`, `--persist-forever` (T-391:
/// a tunnel that gives up after 5 minutes of outage would wait for the
/// service manager's next start), then the user's words but `--install
/// NAME`. A word after `--` is never a flag, and stays.
pub(super) fn service_words(words: &[String], env_file: &Path) -> Vec<String> {
    let mut out: Vec<String> = words.iter().take(1).cloned().collect();
    for option in SERVICE_OPTIONS {
        out.extend(["-o".to_string(), option.to_string()]);
    }
    out.extend(["--env-file".to_string(), env_file.display().to_string()]);
    let flags = words.iter().take_while(|w| *w != "--");
    if !flags.into_iter().any(|w| w == "--persist-forever") {
        out.push("--persist-forever".to_string());
    }
    let mut rest = words.iter().skip(1);
    while let Some(word) = rest.next() {
        if word == "--" {
            out.push(word.clone());
            out.extend(rest.by_ref().cloned());
            break;
        }
        if word == "--install" {
            rest.next();
        } else if !word.starts_with("--install=") {
            out.push(word.clone());
        }
    }
    out
}
