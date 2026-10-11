//! Connection sharing (T-039): OpenSSH's control socket. A master serves
//! sessions, stdio forwards and forwards of other runs over its one
//! connection; a client asks it for them and passes its stdin, stdout and
//! stderr (SCM_RIGHTS, so Unix only). The protocol is OpenSSH's, so its
//! `ssh -O check` and its clients work with a podssh master, and podssh's
//! client with an OpenSSH master.

pub mod proto;

#[cfg(unix)]
mod afd;
#[cfg(unix)]
pub mod client;
#[cfg(unix)]
mod fwd;
#[cfg(unix)]
pub mod master;
#[cfg(unix)]
mod msession;
#[cfg(unix)]
pub mod wire;

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use russh::client::Handle;
    use tokio::sync::watch;

    use super::master::{self, Control, Served};
    use crate::handler::Client;
    use crate::log::Log;

    /// The control socket of a run, which the run that serves it takes once.
    #[derive(Clone)]
    pub struct ControlSlot(Arc<Mutex<Option<Control>>>);

    impl ControlSlot {
        pub fn new(control: Control) -> Self {
            ControlSlot(Arc::new(Mutex::new(Some(control))))
        }

        pub fn take(&self) -> Option<Control> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
        }
    }

    impl std::fmt::Debug for ControlSlot {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ControlSlot")
        }
    }

    /// How a run with a master ended.
    pub enum Mastered<T> {
        /// The run's own work ended, and then each client of the master.
        Done(T),
        /// `-O exit`, or `ControlPersist` with no client.
        Ended(Served),
    }

    /// `work`, with the master of `control` served on `handle` meanwhile.
    /// Once `work` ends, the master takes no new client and serves those it
    /// has to their end, as OpenSSH's master stays for its clients.
    pub async fn alongside<T>(
        handle: &Handle<Client>,
        control: Option<Control>,
        log: &Arc<Log>,
        work: impl Future<Output = T>,
    ) -> Mastered<T> {
        let Some(control) = control else { return Mastered::Done(work.await) };
        let (drain, draining) = watch::channel(false);
        let serving = master::serve(handle, control, draining, log);
        tokio::pin!(work, serving);
        tokio::select! {
            out = &mut work => {
                let _ = drain.send(true);
                let _ = serving.await;
                Mastered::Done(out)
            }
            served = &mut serving => match served {
                Served::Done => Mastered::Done(work.await),
                ended => Mastered::Ended(ended),
            },
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
#[path = "tests.rs"]
mod tests;
