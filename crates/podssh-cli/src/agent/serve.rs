//! The agent that serves (T-034): the probe and the bind of `podssh pipe`'s
//! listener (a socket of mode 0600 whose peers of another user are closed,
//! or on Windows a named pipe whose clients must run as this user), the line
//! of `SSH_AUTH_SOCK`, then russh's agent server until SIGINT, SIGTERM or
//! SIGHUP, which remove the socket and the directory that podssh made. In
//! front of russh's server, the store of passwords and passphrases answers
//! its own requests (T-228).

use std::future::Future;
use std::io::Write;
use std::sync::Arc;

use podssh_ssh::credential_store::{self, Store};
use podssh_ssh::russh::keys::agent::server::{self as agent_server, Agent};
use podssh_ssh::russh::keys::PrivateKey;
use tokio::io::DuplexStream;

use super::AgentArgs;
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_SOFTWARE};
use crate::pipe::address::Address;
use crate::pipe::listen::{self, Listener};
use crate::pipe::pump::End;

/// Serve the agent protocol: the exit code, 128 and the signal's number when
/// a signal ends it.
pub async fn serve(args: &AgentArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Err(refusal) = listen::allowed() {
        let _ = writeln!(err, "podssh agent: {}", refusal.message);
        return refusal.code;
    }
    let place = match Place::choose(args.socket.as_deref()) {
        Ok(place) => place,
        Err(line) => {
            let _ = writeln!(err, "podssh agent: {line}");
            return EX_CANTCREAT;
        }
    };
    let bound = Listener::bind(&Address::UnixListen(place.path.clone()), &mut |line: &str| {
        let _ = writeln!(err, "podssh agent: {line}");
    })
    .await;
    let listener = match bound {
        Ok(listener) => listener,
        Err((code, line)) => {
            let _ = writeln!(err, "podssh agent: {line}");
            let _ = writeln!(
                err,
                "podssh agent: with no agent, podssh ssh takes key files with -i, and an encrypted key asks its \
                 passphrase on the terminal or through SSH_ASKPASS"
            );
            return code;
        }
    };
    // As `ssh-agent -s` prints them, for a shell that sources the lines.
    let _ = writeln!(out, "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", place.path);
    let _ = writeln!(out, "echo Agent pid {};", std::process::id());
    let _ = out.flush();
    let store = Arc::new(Store::default());
    let connections = Box::pin(futures_util::stream::unfold(listener, move |mut listener| {
        let store = store.clone();
        async move {
            let mut said = |line: &str| eprintln!("podssh agent: {line}");
            let next = listener.accept(&mut said).await.map(|end| front(end, store));
            Some((next, listener))
        }
    }));
    let mut stop = Stop::new();
    let code = tokio::select! {
        served = agent_server::serve(connections, Keys) => match served {
            Ok(()) => 0,
            Err(e) => {
                let _ = writeln!(err, "podssh agent: the agent stopped: {e}");
                EX_SOFTWARE
            }
        },
        signal = stop.next() => signal,
    };
    // The listener, and with it the socket's file, went with the stream;
    // the directory goes with `place`.
    drop(place);
    code
}

/// Where the agent serves: the socket's path, and the directory that podssh
/// made for it, which goes at the end.
struct Place {
    path: String,
    made: Option<std::path::PathBuf>,
}

impl Place {
    /// `--socket`, else a new directory of mode 0700 in the user's runtime
    /// directory or the temporary directory, else on Windows a named pipe of
    /// this user and process.
    fn choose(given: Option<&str>) -> Result<Place, String> {
        if let Some(path) = given {
            return Ok(Place { path: path.to_string(), made: None });
        }
        #[cfg(windows)]
        {
            let user: String =
                std::env::var("USERNAME").unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            Ok(Place { path: format!(r"\\.\pipe\podssh-agent-{user}-{}", std::process::id()), made: None })
        }
        #[cfg(not(windows))]
        {
            let base = std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(std::env::temp_dir);
            let dir = agent_dir(base, std::process::id());
            private_dir(&dir)
                .map_err(|e| format!("{}: a directory of mode 0700 could not be made: {e}", dir.display()))?;
            Ok(Place { path: dir.join("agent.sock").display().to_string(), made: Some(dir) })
        }
    }
}

/// The agent's directory under `base`, or under /tmp where its socket's path
/// would not fit in `sun_path` with its NUL: 104 bytes on macOS and the BSDs,
/// 108 on Linux; a long TMPDIR (macOS's is under /var/folders) leaves too few.
#[cfg(unix)]
fn agent_dir(base: std::path::PathBuf, pid: u32) -> std::path::PathBuf {
    // SAFETY: a sockaddr_un of zeros is a valid value; only its size is read.
    let room = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }.sun_path.len();
    let name = format!("podssh-agent-{pid}");
    let fits = base.join(&name).join("agent.sock").as_os_str().len() < room;
    if fits { base } else { std::path::PathBuf::from("/tmp") }.join(name)
}

/// Where no sun_path bounds the path: the directory under `base`.
#[cfg(not(any(unix, windows)))]
fn agent_dir(base: std::path::PathBuf, pid: u32) -> std::path::PathBuf {
    base.join(format!("podssh-agent-{pid}"))
}

impl Drop for Place {
    fn drop(&mut self) {
        if let Some(dir) = &self.made {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// A new directory of mode 0700, of this user, never one that exists.
#[cfg(unix)]
fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    std::fs::DirBuilder::new().mode(0o700).create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: geteuid cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        let _ = std::fs::remove_dir(dir);
        let why = "it is not a private directory of this user";
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir(dir)
}

/// The agent's behaviour beyond the store of keys: a key added with a
/// confirmation of each use (`ssh-add -c`) is never used, as nobody here
/// can confirm one. russh 0.64.1's server never asks this, and signs with
/// such a key unasked, so the front refuses it as it is added (T-284); this
/// stays for a server that asks.
#[derive(Clone)]
struct Keys;

impl Agent for Keys {
    fn confirm(self, _key: Arc<PrivateKey>) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        eprintln!("podssh agent: refused a key added for a confirmation of each use (ssh-add -c): nobody can confirm");
        Box::new(std::future::ready((self, false)))
    }
}

/// One client: the store answers its own requests, and russh's server, at
/// the other end of the pipe returned, the others.
fn front(end: End, store: Arc<Store>) -> DuplexStream {
    let (ours, theirs) = tokio::io::duplex(credential_store::MAX_FRAME);
    let client = tokio::io::join(end.read, end.write);
    tokio::spawn(async move {
        let _ = credential_store::serve_client(client, ours, &store).await;
    });
    theirs
}

/// SIGINT, SIGTERM and SIGHUP, or Ctrl-C on Windows: 128 and the signal's
/// number. The session daemon of `podssh session` ends at them too (T-186).
pub(crate) struct Stop {
    #[cfg(unix)]
    signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
}

impl Stop {
    pub(crate) fn new() -> Stop {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let signals = match (
                signal(SignalKind::interrupt()),
                signal(SignalKind::terminate()),
                signal(SignalKind::hangup()),
            ) {
                (Ok(int), Ok(term), Ok(hup)) => Some((int, term, hup)),
                _ => None,
            };
            Stop { signals }
        }
        #[cfg(windows)]
        {
            Stop { ctrl_c: tokio::signal::windows::ctrl_c().ok() }
        }
    }

    pub(crate) async fn next(&mut self) -> i32 {
        #[cfg(unix)]
        if let Some((int, term, hup)) = self.signals.as_mut() {
            return tokio::select! {
                Some(()) = int.recv() => 130,
                Some(()) = term.recv() => 143,
                Some(()) = hup.recv() => 129,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket of a served agent is mode 0600 in a directory of mode 0700
    /// that podssh made, and both go when the agent ends (T-034).
    #[cfg(unix)]
    #[tokio::test]
    async fn agent_socket_is_private_and_goes_at_the_end() {
        use std::os::unix::fs::PermissionsExt;
        let place = Place::choose(None).expect("a place");
        let dir = place.made.clone().expect("a directory of its own");
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        let listener = Listener::bind(&Address::UnixListen(place.path.clone()), &mut |_: &str| {}).await.unwrap();
        let socket = std::path::PathBuf::from(&place.path);
        assert_eq!(mode(&socket), 0o600, "the socket");
        drop(listener);
        assert!(!socket.exists(), "the socket went with the listener");
        drop(place);
        assert!(!dir.exists(), "the directory went at the end");
    }

    /// A socket's path that would pass the bytes of sun_path goes under /tmp
    /// (macOS's TMPDIR, with a test's scratch directory in it, did, T-218);
    /// one that fits, by a byte, stays where it was asked for.
    #[cfg(unix)]
    #[test]
    fn a_long_temporary_directory_puts_the_socket_under_tmp() {
        let room = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }.sun_path.len();
        let tail = "/podssh-agent-4242/agent.sock".len();
        // A base whose socket's path is room - 1 bytes long, the most that fits.
        let base = |len: usize| std::path::PathBuf::from(format!("/{}", "x".repeat(len - tail - 1)));
        let most = base(room - 1);
        assert_eq!(agent_dir(most.clone(), 4242), most.join("podssh-agent-4242"));
        assert_eq!(agent_dir(base(room), 4242), std::path::PathBuf::from("/tmp/podssh-agent-4242"));
        let short = std::path::PathBuf::from("/run/user/1000");
        assert_eq!(agent_dir(short, 4242), std::path::PathBuf::from("/run/user/1000/podssh-agent-4242"));
    }

    /// On Windows the agent serves on a named pipe of this user and process.
    #[cfg(windows)]
    #[tokio::test]
    async fn agent_socket_is_a_pipe_of_this_user() {
        let place = Place::choose(None).expect("a place");
        assert!(place.path.starts_with(r"\\.\pipe\podssh-agent-"), "{}", place.path);
        assert!(place.path.ends_with(&format!("-{}", std::process::id())), "{}", place.path);
        let listener = Listener::bind(&Address::UnixListen(place.path.clone()), &mut |_: &str| {}).await.unwrap();
        drop(listener);
    }
}
