//! The iroh road's end of a pipe (T-175): `iroh:TICKET`, the TARGET of a
//! node of the iroh road, as `podssh ssh iroh:` reaches it: this client's
//! key, the ticket's relays first, and the resumable layer, carried to a
//! new link after each lost one. When the session ends, nothing more can
//! come. A build without the feature `iroh` refuses the address before
//! anything starts.

#[cfg(feature = "iroh")]
pub use built::open;
#[cfg(not(feature = "iroh"))]
pub use stub::open;

#[cfg(not(feature = "iroh"))]
mod stub {
    use podssh_ws::Trust;

    use super::super::pump::End;
    use crate::ssh::args::SshArgs;

    /// The address is refused before anything starts; this is the guard.
    pub async fn open(ticket: &str, _: &SshArgs, _: &Trust, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
        say(&crate::ssh::iroh::not_built(ticket));
        Err(crate::exit_codes::EXIT_NOT_IMPLEMENTED)
    }
}

#[cfg(feature = "iroh")]
mod built {
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    use podssh_iroh::Failure;
    use podssh_relay::session::resume::Note;
    use podssh_relay::session::Settings;
    use podssh_ssh::{Log, LogLevel};
    use podssh_ws::Trust;
    use tokio::task::JoinHandle;

    use super::super::pump::{End, Ending, Verdict};
    use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
    use crate::layered::Line;
    use crate::ssh::args::SshArgs;
    use crate::ssh::iroh::dial::{self, Prepared};

    /// The pipe in memory, each way.
    const PIPE: usize = 256 * 1024;
    /// How long the endpoint may take to close after the session.
    const CLOSE_LIMIT: Duration = Duration::from_secs(3);

    /// The session to the node of `ticket`: the end, or the exit code once
    /// `say` has the lines.
    pub async fn open(ticket: &str, args: &SshArgs, trust: &Trust, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
        let relays = crate::ssh::iroh::relays(args.iroh_relay.as_deref()).map_err(|refusal| {
            say(&refusal.message);
            refusal.code
        })?;
        let log = Log::new(LogLevel::from_flags(args.verbose, args.quiet));
        let Prepared { dialer, endpoint, shown, fingerprint } =
            dial::prepare(ticket, args.iroh_key.as_deref(), &relays, trust, &log).await.map_err(|why| {
                say(&why);
                EX_UNAVAILABLE
            })?;
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let task = tokio::spawn(async move {
            // The pipe's own bytes are on stdout: each line goes to stderr.
            let note = |note: Note| {
                if let Line::Always(text) = crate::layered::line_of(note) {
                    eprintln!("podssh pipe: {shown}: {text}");
                }
            };
            let settings = Settings { features: podssh_iroh::FEATURES, ..crate::layered::settings() };
            let carried = podssh_iroh::carry(&dialer, theirs, settings, note).await;
            dialer.close().await;
            let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
            let code = if matches!(carried, Err(Failure::Refused)) { EX_NOPERM } else { EX_UNAVAILABLE };
            dial::why_failed(carried, &fingerprint).map(|why| (code, vec![format!("{shown}: {why}")]))
        });
        let (read, write) = tokio::io::split(ours);
        Ok(End {
            read: Box::new(read),
            write: Box::new(write),
            child: None,
            last_word: true,
            ending: Some(Box::new(Session(task))),
        })
    }

    /// The session's task, and how it ended.
    struct Session(JoinHandle<Verdict>);

    impl Ending for Session {
        fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
            Box::pin(async move { self.0.await.unwrap_or(None) })
        }
    }
}
