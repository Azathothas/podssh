//! An SSH server on the loopback for the tests of the roads (T-157, T-165,
//! T-203): a russh server in the test process that lets anyone in and runs
//! five commands: `greet` prints [`GREETING`]; `source N` sends N bytes;
//! `sink` prints `R` as it starts to read, reads stdin to its end, then
//! prints the count, as `sh -c 'echo R; wc -c'` does on a POSIX server;
//! `echo` sends stdin back as it comes. Each exits 0. `hold` and `quit` take
//! no input after their first bytes, so the client's window runs out; 2 s
//! later `hold` ends the connection with no word, and `quit` exits 3 and
//! closes its channel, as a command that reads no input (`head`, `true`)
//! does while a large file comes. A direct-tcpip channel (`-W`, `podssh pipe
//! ssh:`) reaches its HOST:PORT from the server, each way with its half-close.
//! The commands of `podssh ping` (T-053) run as a POSIX server runs them:
//! `cat` echoes, `head -c N /dev/zero` sends N zero bytes, and
//! `cat > /dev/null` reads to the end of its input, each then exiting 0;
//! for a user named `bare-...`, a host with neither, they exit 127, and for
//! `bare-early-...` the channel closes before the server's reply to the
//! command, an order that RFC 4254 does not forbid. For `late-...`, `cat`
//! echoes its first bytes 1 s late, as a shell that is still starting it.
//! For the users `sudo-...` and `su-...` (T-032), `sudo -S -k -p PROMPT --
//! sh -c '...'` and `su -c '...'` run as sudo and su run them, with the
//! password `secret`: the prompt, then the command's marker, then `0` and its
//! input echoed, as `id -u; cat` as root; `sudo-nopass-...` has a NOPASSWD
//! rule, and only `su-...` is granted a pty. `x11-probe` (T-037) opens an
//! `x11` channel to the client with the cookie of its `x11-req`, sends an X
//! client's first packet on it, and prints the X server's status and that
//! cookie. A direct-streamlocal channel to the socket `/echo` (T-040) sends
//! back what it gets; to another socket it is refused. `exit N` and `kill NAME` end as a
//! shell's do (T-054, `ends.rs`). `bytes HEX...` sends chosen bytes, and a
//! user named `pty-...` gets a pty, for `watch` (T-132, `console.rs`). The
//! subsystem `sftp` is OpenSSH's `sftp-server` in the directory of the host
//! key, when this machine has one (T-140, `sftp.rs`). On a server of
//! `start_podssh`, `podssh ...` runs the binary under test (T-167, `podssh.rs`).
//! `wait-signal PATH acts` and `wait-signal PATH deaf` write each `signal`
//! request into PATH, and end by it or run on (T-293, `interrupt.rs`).

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Sig};

mod console;
mod ends;
mod far;
mod forward;
mod interrupt;
pub mod podssh;
mod serve;
pub mod sftp;
mod sudo;
pub mod watch;
mod x11;

// Each test binary uses a part of it.
use far::Far;
#[allow(unused_imports)]
pub use serve::{start, start_counting, start_podssh, start_with};
use sudo::{elevation, Elevated};
use x11::x11_probe;

/// What `greet` prints.
pub const GREETING: &str = "hello over the iroh road\n";
/// The size of each block that `source` sends.
const BLOCK: usize = 32 * 1024;

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.kick = user == "kick";
        self.bare = user.starts_with("bare-");
        self.early = user.starts_with("bare-early-");
        self.late = user.starts_with("late-");
        self.su = user.starts_with("su-");
        self.nopass = user.starts_with("sudo-nopass-");
        self.pty = user.starts_with("pty-");
        self.evil = user.starts_with("evil-");
        if watch::refused(self.watch.as_deref(), user, &mut self.cut) {
            return Ok(Auth::reject());
        }
        // A user named key-...: a key is needed, as from an agent (T-034).
        if user.starts_with("key-") {
            return Ok(Auth::Reject {
                proceed_with_methods: Some(russh::MethodSet::from(&[russh::MethodKind::PublicKey][..])),
                partial_success: false,
            });
        }
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(&mut self, user: &str, _key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user.starts_with("key-") { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, _key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        // russh checked the signature first: whoever holds a key gets in.
        Ok(if user.starts_with("key-") { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if self.kick {
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ =
                    handle.disconnect(russh::Disconnect::ByApplication, "kicked by the test".into(), "en".into()).await;
            });
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        forward::tcpip(channel, host, port, reply).await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        forward::streamlocal(channel, socket_path, reply).await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(stdin) = sftp::start(name, self.sftp_root.as_deref(), self.evil, channel, session)? {
            self.sftps.insert(channel, stdin);
            watch::saw(self.watch.as_deref(), self.sftps.len());
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _px_width: u32,
        _px_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // No reply for the others, as before.
        if self.su || self.pty {
            session.channel_success(channel)?;
        }
        self.pty_size = (cols, rows);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _px_width: u32,
        _px_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty_size = (cols, rows);
        if self.watches.contains(&channel) {
            console::watch_size(self.pty_size, channel, session)?;
        }
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _protocol: &str,
        cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.x11_cookie = Some(cookie.to_string());
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        let program = command.split_whitespace().next().unwrap_or_default();
        if self.bare && matches!(program, "cat" | "head") {
            if !self.early {
                session.channel_success(channel)?;
            }
            session.extended_data(channel, 1, format!("sh: {program}: not found\n").into_bytes())?;
            session.exit_status_request(channel, 127)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        if let Some(ran) = podssh::run(self.podssh.as_ref(), &command, channel, session) {
            return ran;
        }
        if let Some((prompt, started)) = elevation(&command) {
            if self.nopass && prompt.is_some() {
                session.extended_data(channel, 1, started.into_bytes())?;
                session.data(channel, b"0\n".as_slice())?;
                self.echoes.push(channel);
                return Ok(());
            }
            match &prompt {
                Some(prompt) => session.extended_data(channel, 1, prompt.clone().into_bytes())?,
                None => session.data(channel, b"Password: ".as_slice())?,
            }
            self.elevated.insert(channel, Elevated { prompt, started, line: Vec::new() });
            return Ok(());
        }
        if let Some(ended) = ends::ended(&command, channel, session) {
            return ended;
        }
        if let Some(sent) = console::bytes(&command, channel, session) {
            return sent;
        }
        if let Some(wait) = interrupt::wait(&command, channel, session)? {
            self.waits.insert(channel, wait);
            return Ok(());
        }
        if command == "watch" && self.pty {
            self.watches.push(channel);
            return console::watch(channel, self.pty_size, session);
        }
        if command == "x11-probe" {
            let cookie = self.x11_cookie.clone().unwrap_or_default();
            let handle = session.handle();
            tokio::spawn(async move {
                let status = x11_probe(&handle, &cookie).await;
                let _ =
                    handle.data(channel, format!("x11 status {status}\nx11-req cookie {cookie}\n").into_bytes()).await;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            return Ok(());
        }
        if let Some(rest) = command.strip_prefix("append ") {
            // `append PATH STATUS DELAY`: a line in the file at once, then
            // the status after DELAY seconds (T-025). A command that ran twice
            // leaves two lines.
            let mut parts = rest.rsplitn(3, ' ');
            let delay: u64 = parts.next().and_then(|d| d.parse().ok()).unwrap_or(0);
            let status: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let path = parts.next().unwrap_or_default().to_string();
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = std::io::Write::write_all(&mut file, b"ran\n");
            }
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(delay)).await;
                let _ = handle.exit_status_request(channel, status).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            return Ok(());
        }
        if command == "cat" {
            self.echoes.push(channel);
            if self.late {
                self.late_echoes.push(channel);
            }
            return Ok(());
        }
        if command == "cat > /dev/null" {
            self.drains.push(channel);
            return Ok(());
        }
        let zeros = command.strip_prefix("head -c ").and_then(|r| r.strip_suffix(" /dev/zero"));
        let command = match zeros.and_then(|n| n.parse::<u64>().ok()) {
            Some(n) => format!("source {n} zero"),
            None => command,
        };
        let mut words = command.split_whitespace();
        match (words.next(), words.next().and_then(|n| n.parse::<u64>().ok())) {
            (Some("source"), Some(bytes)) => {
                // From a task: the session's loop must go on, to take the
                // client's window adjustments while the bytes go out.
                let handle = session.handle();
                let fill = if words.next() == Some("zero") { 0 } else { 0x5a_u8 };
                tokio::spawn(async move {
                    let block = vec![fill; BLOCK];
                    let mut left = bytes;
                    while left > 0 {
                        let n = left.min(BLOCK as u64) as usize;
                        if handle.data(channel, block[..n].to_vec()).await.is_err() {
                            return;
                        }
                        left -= n as u64;
                    }
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                });
            }
            (Some(spew @ ("spew" | "spew-mute")), _) => {
                // Bytes until the client's end of input; then `spew` gives
                // its status, and `spew-mute` none.
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                self.spews.insert(channel, (stop.clone(), spew == "spew"));
                let handle = session.handle();
                tokio::spawn(async move {
                    let block = vec![0x79_u8; BLOCK];
                    while !stop.load(Ordering::SeqCst) {
                        if handle.data(channel, block.clone()).await.is_err() {
                            return;
                        }
                    }
                });
            }
            (Some("sink"), _) => {
                self.sinks.insert(channel, 0);
                session.data(channel, b"R\n".as_slice())?;
            }
            (Some("echo"), _) => self.echoes.push(channel),
            (Some("hold"), _) => self.holds.push(channel),
            (Some("quit"), _) => self.quits.push(channel),
            _ => {
                session.data(channel, GREETING.as_bytes())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
        }
        Ok(())
    }

    async fn signal(&mut self, channel: ChannelId, signal: Sig, session: &mut Session) -> Result<(), Self::Error> {
        interrupt::received(self.waits.get(&channel), channel, signal, session)
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if let Some(stdin) = self.sftps.get_mut(&channel) {
            // A cut (T-297): the connection ends with no word.
            if watch::spend(&mut self.cut, data.len()) {
                return Err(russh::Error::Disconnect);
            }
            sftp::input(stdin, data).await;
            return Ok(());
        }
        if let Some(elevated) = self.elevated.remove(&channel) {
            match sudo::password(elevated, data, channel, session)? {
                sudo::Read::Waiting(elevated) => {
                    self.elevated.insert(channel, elevated);
                }
                sudo::Read::Started => self.echoes.push(channel),
                sudo::Read::Refused => {}
            }
            return Ok(());
        }
        if let Some(at) = self.watches.iter().position(|c| *c == channel) {
            if console::watch_input(data, channel, session)? {
                self.watches.remove(at);
            }
            return Ok(());
        }
        if self.holds.contains(&channel) {
            // The session's loop waits here: no window adjustment goes out.
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Err(russh::Error::Disconnect);
        }
        if let Some(at) = self.quits.iter().position(|c| *c == channel) {
            self.quits.remove(at);
            tokio::time::sleep(Duration::from_secs(2)).await;
            session.exit_status_request(channel, 3)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        if let Some(bytes) = self.sinks.get_mut(&channel) {
            *bytes += data.len() as u64;
        }
        if let Some(at) = self.late_echoes.iter().position(|c| *c == channel) {
            self.late_echoes.remove(at);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if self.echoes.contains(&channel) {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        // The server's stdin closes, and it ends.
        if self.sftps.remove(&channel).is_some() {
            return Ok(());
        }
        // sudo with no password to read: a refusal.
        if self.elevated.remove(&channel).is_some() {
            session.extended_data(channel, 1, b"sudo: 1 incorrect password attempt\n".to_vec())?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        if let Some((stop, status)) = self.spews.remove(&channel) {
            stop.store(true, Ordering::SeqCst);
            if status {
                session.exit_status_request(channel, 7)?;
            }
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }
        let echoed = self.echoes.iter().position(|c| *c == channel).map(|at| self.echoes.remove(at)).is_some();
        let drained = self.drains.iter().position(|c| *c == channel).map(|at| self.drains.remove(at)).is_some();
        if echoed || drained {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        if let Some(bytes) = self.sinks.remove(&channel) {
            session.data(channel, format!("{bytes}\n").into_bytes())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}
