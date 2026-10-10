//! `podssh ssh --persist` (T-178): against a standard sshd, where only this
//! end runs podssh and the resumable layer cannot help, a lost link does not
//! end the work. The shell runs in tmux on the server; after a loss podssh
//! connects again and attaches the same tmux session, which kept running.
//! tmux is probed, never assumed: with none, podssh refuses rather than
//! start a shell that looks like the old one and lost its state.

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::io::{Input, QUEUE};
use podssh_ssh::persist::{self, Attempt};
use podssh_ssh::{Log, Options, Request, RequestTty, EXIT_FAILURE};

use super::args::SshArgs;
use super::resolve::{Resolved, Transport};
use super::transport;
use crate::relay_settings::Refusal;

/// The tmux session when `--persist-name` names none.
pub const DEFAULT_NAME: &str = "podssh";
/// New connections after one loss, at most ...
pub const ATTEMPTS: u32 = 10;
/// ... within this time from the loss.
pub const WITHIN: Duration = Duration::from_secs(300);
/// The longest name that `--persist-name` takes.
const NAME_MAX: usize = 32;

/// Check `--persist` against the rest of the command line, before anything
/// connects, and set its session: `tmux new-session -A -s NAME` with a pty,
/// as `-tt` asks for one.
pub fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    let name = match (args.persist, args.persist_name.as_deref()) {
        (false, None) => return Ok(()),
        (false, Some(_)) => return Err("--persist-name names the tmux session of --persist; give --persist too".into()),
        (true, name) => name.unwrap_or(DEFAULT_NAME),
    };
    let fits = !name.is_empty()
        && name.len() <= NAME_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !fits {
        return Err(format!("--persist-name {name}: letters, digits, _ and -, {NAME_MAX} at most").into());
    }
    let with = if args.stdio_forward.is_some() {
        Some("-W")
    } else if args.no_command {
        Some("-N")
    } else if args.subsystem {
        Some("-s")
    } else if !args.command.is_empty() {
        Some("a remote command")
    } else if resolved.options.request != Request::Shell {
        Some("RemoteCommand or SessionType")
    } else if resolved.options.request_tty == RequestTty::No {
        Some("-T or RequestTTY=no")
    } else {
        None
    };
    if let Some(with) = with {
        return Err(format!(
            "--persist runs tmux in the shell's place, with a pseudo-terminal; it cannot be combined with {with}"
        )
        .into());
    }
    if matches!(resolved.transport, Transport::Node { .. } | Transport::Iroh { .. }) {
        return Err(
            "--persist is for a standard sshd; a node:// or iroh: session survives a lost link on its own layer".into(),
        );
    }
    resolved.options.request = Request::Exec(persist::command(name));
    resolved.options.request_tty = RequestTty::Force;
    resolved.persist = Some(name.to_string());
    Ok(())
}

/// Run the session of `--persist` until it ends: its exit code.
pub async fn run(resolved: &Resolved, name: &str, log: Arc<Log>) -> i32 {
    let mut opts = resolved.options.clone();
    // A key that a passphrase opened, and a password that the server took,
    // log in again with no prompt (T-136).
    opts.remembered.get_or_insert_with(Default::default);
    let mut input = Input::new(opts.stdin_null);
    // Ctrl-C is podssh's own from the first wait on; before it, the first
    // login's prompts handle it as without --persist.
    let mut interrupt: Option<Interrupt> = None;
    let mut attached = false;
    // Since the last loss: when it came, and the connections tried since.
    let mut round = (Instant::now(), 0u32);
    loop {
        let attempt = tokio::select! {
            attempt = one(resolved, &opts, name, !attached, &mut input, &log) => attempt,
            _ = Interrupt::next(&mut interrupt) => {
                log.error("interrupted");
                return EXIT_FAILURE;
            }
        };
        let why = match attempt {
            Attempt::Ended(code) => return code,
            Attempt::Failed => return EXIT_FAILURE,
            Attempt::Lost { attached: true, why } => {
                attached = true;
                round = (Instant::now(), 0);
                why
            }
            Attempt::Lost { attached: false, why } => why,
        };
        let (since, tries) = &mut round;
        let spent = since.elapsed();
        if *tries >= ATTEMPTS || spent >= WITHIN {
            log.error(&format!("{why}; gave up after {tries} new connections in {} s", spent.as_secs()));
            return EXIT_FAILURE;
        }
        *tries += 1;
        let wait = podssh_relay::open::backoff(*tries).min(WITHIN - spent);
        log.info(&format!(
            "{why}; connecting again in {:.1} s (attempt {tries} of {ATTEMPTS}; Ctrl-C stops)",
            wait.as_secs_f64()
        ));
        // The input belongs to the session from the first attach on: a
        // prompt that read the terminal would race the task that reads it.
        opts.batch_mode = true;
        interrupt.get_or_insert_with(Interrupt::new);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = Interrupt::next(&mut interrupt) => {
                log.error("interrupted while connecting again");
                return EXIT_FAILURE;
            }
            _ = input.queue() => {}
        }
        let dropped = input.take_dropped();
        if dropped > 0 {
            log.info(&format!("{dropped} bytes typed meanwhile did not fit the queue of {} KiB", QUEUE / 1024));
        }
    }
}

/// One connection: the road, then the attempt. Before the first attach, a
/// failure is final, with the lines that `podssh ssh` gives without
/// `--persist`.
async fn one(
    resolved: &Resolved,
    opts: &Options,
    name: &str,
    first: bool,
    input: &mut Input,
    log: &Arc<Log>,
) -> Attempt {
    let hop = opts.jump.first().unwrap_or(&opts.destination);
    let target = podssh_ws::dial::authority(&hop.host, hop.port);
    let reached = match transport::reach(resolved, log).await {
        Ok(reached) => reached,
        Err(failure) if first => {
            for line in &failure.lines {
                log.error(line);
            }
            return Attempt::Failed;
        }
        Err(failure) => {
            // `--direct` logged each dial already.
            let why = failure.lines.first().cloned().unwrap_or_else(|| format!("could not connect to {target}"));
            return Attempt::Lost { attached: false, why };
        }
    };
    let relay = reached.relay.clone();
    match persist::attempt(reached.stream, opts, relay.as_ref(), name, first, input, log).await {
        Attempt::Lost { attached: false, why } if first => {
            for line in podssh_ssh::run::failure_lines(&why, relay.and_then(|r| r.get()).as_ref(), &target) {
                log.error(&line);
            }
            Attempt::Failed
        }
        attempt => attempt,
    }
}

/// Ctrl-C where the terminal is not raw: during the wait, and in a session
/// with no local terminal. In raw mode it is a key for the session.
struct Interrupt {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
    #[cfg(windows)]
    signal: Option<tokio::signal::windows::CtrlC>,
}

impl Interrupt {
    fn new() -> Self {
        #[cfg(unix)]
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
        #[cfg(windows)]
        let signal = tokio::signal::windows::ctrl_c().ok();
        Interrupt { signal }
    }

    /// The next Ctrl-C; never, with no handler.
    async fn next(interrupt: &mut Option<Interrupt>) {
        if let Some(signal) = interrupt.as_mut().and_then(|i| i.signal.as_mut()) {
            if signal.recv().await.is_some() {
                return;
            }
        }
        std::future::pending::<()>().await
    }
}
