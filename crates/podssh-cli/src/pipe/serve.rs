//! A pipe with a listening side (T-177). The listener binds before anything
//! else starts, so a refused bind costs no connection elsewhere; then each
//! client of this user is joined to a new instance of the other address,
//! which opens only then: a new relay session, a new program.
//!
//! One client by default: the listener closes, and its file goes, as soon
//! as the client connects, and the pipe ends with that session's status. A
//! listener that stays after its first use is a service that the user can
//! forget. With `--keep-listening`, each client in turn, 8 at once at most,
//! until SIGINT or SIGTERM. A signal removes the socket's file, then podssh
//! exits with 128 and the signal's number, as a shell gives it.

use std::io::Write;
use std::rc::Rc;
use std::time::Duration;

use super::address::Address;
use super::listen::Listener;
use super::{open, pump, remote, report};
use crate::exitmap::sysexits::EX_UNAVAILABLE;

/// The clients joined at once with `--keep-listening`.
pub const AT_ONCE: usize = 8;
/// Accepts that fail in a row before the listener is taken for dead.
const FAILED_ACCEPTS: u32 = 10;

/// What the pipe listens on, and what each client is joined to.
pub struct Serve<'a> {
    pub listening: &'a Address,
    pub other: &'a Address,
    /// The listening side is A: a client's bytes go to B.
    pub listener_is_a: bool,
    pub keep: bool,
    /// `-q`: no line of podssh's own but a failure's.
    pub quiet: bool,
}

/// Run the pipe; its exit code.
pub async fn run(serve: Serve<'_>, settings: &remote::Settings, err: &mut dyn Write) -> i32 {
    // Before the bind: a signal from then on still removes the file.
    let mut stop = Interrupt::new();
    let quiet = serve.quiet;
    let mut listener = {
        let mut say = |line: &str| {
            if !quiet {
                let _ = writeln!(err, "podssh pipe: {line}");
            }
        };
        match Listener::bind(serve.listening, &mut say).await {
            Ok(listener) => listener,
            Err((code, line)) => {
                let _ = writeln!(err, "podssh pipe: {line}");
                return code;
            }
        }
    };
    if serve.keep {
        return keep_listening(listener, &serve, settings, &mut stop).await;
    }
    let client = {
        let mut say = |line: &str| {
            if !quiet {
                let _ = writeln!(err, "podssh pipe: {line}");
            }
        };
        tokio::select! {
            client = listener.accept(&mut say) => client,
            signal = stop.next() => return signal,
        }
    };
    // One client: nobody else connects, and the file goes now.
    drop(listener);
    let client = match client {
        Ok(client) => client,
        Err(e) => {
            let _ = writeln!(err, "podssh pipe: the listener failed: {e}");
            return EX_UNAVAILABLE;
        }
    };
    let opened = tokio::select! {
        opened = open(serve.other, settings, err) => opened,
        signal = stop.next() => return signal,
    };
    let other = match opened {
        Ok(end) => end,
        Err(code) => return code,
    };
    let (a, b) = if serve.listener_is_a { (client, other) } else { (other, client) };
    let pumped = tokio::select! {
        pumped = pump::pump(a, b) => pumped,
        signal = stop.next() => return signal,
    };
    report(pumped, "podssh pipe", err).await
}

/// Each client in turn, 8 at once at most, each on a task of its own with a
/// new instance of the other address; each session's lines name its client.
async fn keep_listening(
    mut listener: Listener,
    serve: &Serve<'_>,
    settings: &remote::Settings,
    stop: &mut Interrupt,
) -> i32 {
    let (other, settings) = (Rc::new(serve.other.clone()), Rc::new(settings.clone()));
    let (listener_is_a, quiet) = (serve.listener_is_a, serve.quiet);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let mut running = tokio::task::JoinSet::new();
            let (mut clients, mut failed) = (0u64, 0u32);
            let mut say = |line: &str| {
                if !quiet {
                    eprintln!("podssh pipe: {line}");
                }
            };
            loop {
                tokio::select! {
                    client = listener.accept(&mut say), if running.len() < AT_ONCE => match client {
                        Ok(client) => {
                            failed = 0;
                            clients += 1;
                            let (other, settings) = (other.clone(), settings.clone());
                            running.spawn_local(session(clients, client, other, settings, listener_is_a));
                        }
                        Err(e) => {
                            failed += 1;
                            eprintln!("podssh pipe: an accept failed: {e}");
                            if failed >= FAILED_ACCEPTS {
                                return EX_UNAVAILABLE;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    },
                    Some(_) = running.join_next(), if !running.is_empty() => {}
                    signal = stop.next() => return signal,
                }
            }
        })
        .await
}

/// One client's session with its own instance of the other address.
async fn session(n: u64, client: pump::End, other: Rc<Address>, settings: Rc<remote::Settings>, listener_is_a: bool) {
    let mut err = std::io::stderr();
    let prefix = format!("podssh pipe: client {n}");
    let mut lines = Vec::new();
    let opened = open(&other, &settings, &mut lines).await;
    let _ = err.write_all(&lines);
    let other = match opened {
        Ok(end) => end,
        Err(code) => {
            let _ = writeln!(err, "{prefix}: ended with {code}");
            return;
        }
    };
    let (a, b) = if listener_is_a { (client, other) } else { (other, client) };
    let code = report(pump::pump(a, b).await, &prefix, &mut err).await;
    if code != 0 {
        let _ = writeln!(err, "{prefix}: ended with {code}");
    }
}

/// SIGINT and SIGTERM, or Ctrl-C on Windows: 128 and the signal's number.
struct Interrupt {
    #[cfg(unix)]
    signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
}

impl Interrupt {
    fn new() -> Interrupt {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Interrupt { signals: signal(SignalKind::interrupt()).ok().zip(signal(SignalKind::terminate()).ok()) }
        }
        #[cfg(windows)]
        {
            Interrupt { ctrl_c: tokio::signal::windows::ctrl_c().ok() }
        }
    }

    async fn next(&mut self) -> i32 {
        #[cfg(unix)]
        if let Some((int, term)) = self.signals.as_mut() {
            return tokio::select! {
                Some(()) = int.recv() => 130,
                Some(()) = term.recv() => 143,
                else => std::future::pending().await,
            };
        }
        #[cfg(windows)]
        if let Some(ctrl_c) = self.ctrl_c.as_mut() {
            if ctrl_c.recv().await.is_some() {
                return 130;
            }
        }
        std::future::pending().await
    }
}
