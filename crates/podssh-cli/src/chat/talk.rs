//! The conversation's state as its loop drives it: the user's acts, the
//! peer's events, and the files. A file of the peer is written only once
//! the user accepts it (`/accept`, or `--accept-dir`).

use std::collections::HashMap;
use std::path::Path;

use podssh_core::chat::{Decoder, Event, Record};
use serde_json::json;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;

use super::converse::{Ended, Files, Once, Options, Sending, State, Summary};
use super::files::{self, Incoming};
use super::input::{self, Act};
use super::output::{safe, Output};

pub(super) struct Talk {
    session: State,
    control: mpsc::UnboundedSender<Record>,
    pub opts: Options,
    files: Files,
    /// The message or file of `--send` or `--file`, and whether it is done.
    once: Option<u64>,
    once_done: bool,
    /// Whether each file that ended was kept: the word to the peer says so,
    /// not only whether its digest matched.
    kept: HashMap<u64, bool>,
}

impl Talk {
    pub fn new(control: mpsc::UnboundedSender<Record>, opts: Options) -> Talk {
        Talk {
            session: State::new(),
            control,
            opts,
            files: Files::default(),
            once: None,
            once_done: false,
            kept: HashMap::new(),
        }
    }

    fn send(&self, record: Record) {
        // The writer gone, the loop learns it from the stream.
        let _ = self.control.send(record);
    }

    fn peer(&self) -> String {
        self.session.peer().unwrap_or("peer").to_string()
    }

    /// The greeting, and the one thing of `--send` or `--file`.
    pub async fn start<W: AsyncWrite + Unpin>(&mut self, out: &mut Output<W>) -> Result<(), String> {
        self.send(self.session.hello(&self.opts.nick));
        match self.opts.once.clone() {
            Once::No => {}
            Once::Send(text) => {
                let (id, record) = self.session.text(&text).map_err(|e| e.to_string())?;
                self.send(record);
                self.once = Some(id);
            }
            Once::File(path) => self.once = Some(self.offer(&path, out).await?),
        }
        Ok(())
    }

    /// The end, when it came: the one thing done, or stdin ended with each
    /// message acknowledged and each file gone.
    pub fn finished(&self, input_open: bool) -> Option<Ended> {
        if self.once.is_some() {
            return self.once_done.then_some(Ended::Done);
        }
        let idle = self.session.undelivered().is_empty()
            && self.files.ours.is_empty()
            && self.files.writing.is_empty()
            && self.files.sending.is_empty();
        (!input_open && idle).then_some(Ended::Done)
    }

    pub fn sending(&self) -> bool {
        !self.files.sending.is_empty()
    }

    /// The next chunk of the file that goes.
    pub async fn next_chunk(&mut self) -> Result<Record, String> {
        let front = self.files.sending.front_mut().ok_or("no file goes")?;
        let id = front.id;
        let data = front.read(self.session.left(id)).await?;
        let record = self.session.chunk(id, data).map_err(|e| e.to_string())?;
        if self.session.left(id) == 0 {
            self.files.sending.pop_front();
        }
        Ok(record)
    }

    /// A line of the user.
    pub async fn act<W: AsyncWrite + Unpin>(&mut self, line: &str, out: &mut Output<W>) -> Option<Ended> {
        let act = match input::parse(line) {
            Ok(act) => act,
            Err(why) => {
                out.notice("error", json!({ "error": why }), why.clone()).await;
                return None;
            }
        };
        let done = match act {
            Act::Nothing => Ok(()),
            Act::Quit => return Some(Ended::Done),
            Act::Say(text) => self.session.text(&text).map(|(_, record)| self.send(record)).map_err(|e| e.to_string()),
            Act::Offer(path) => self.offer(&path, out).await.map(|_| ()),
            Act::Accept { id, to } => self.accept(id, to.as_deref(), out).await,
            Act::Decline(id) => self
                .session
                .decline(id)
                .map(|record| {
                    self.files.offered.remove(&id);
                    self.send(record)
                })
                .map_err(|e| e.to_string()),
        };
        if let Err(why) = done {
            out.notice("error", json!({ "error": why }), why.clone()).await;
        }
        None
    }

    async fn offer<W: AsyncWrite + Unpin>(&mut self, path: &Path, out: &mut Output<W>) -> Result<u64, String> {
        let (size, sha256) = files::digest(path).await?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (id, record) = self.session.offer(&name, size, sha256);
        self.send(record);
        self.files.ours.insert(id, path.to_path_buf());
        let line = format!("offered {} ({size} bytes) as file {id}", safe(&name));
        out.notice("offered", json!({ "id": id, "name": name, "size": size }), line).await;
        Ok(id)
    }

    async fn accept<W: AsyncWrite + Unpin>(
        &mut self,
        id: u64,
        to: Option<&Path>,
        out: &mut Output<W>,
    ) -> Result<(), String> {
        let (name, size) =
            self.files.offered.get(&id).cloned().ok_or(format!("no file waits under the number {id}"))?;
        let dir = self.opts.accept_dir.clone().unwrap_or_else(|| self.opts.here.clone());
        // Until the session takes it, the file waits for an answer still.
        let incoming = Incoming::open(files::target(&name, to, &dir)?, id).await?;
        let (records, done) = match self.session.accept(id) {
            Ok(accepted) => accepted,
            Err(e) => {
                incoming.abandon();
                return Err(e.to_string());
            }
        };
        self.files.offered.remove(&id);
        let shown = incoming.path().display().to_string();
        let line = format!("taking {} ({size} bytes) into {shown}", safe(&name));
        out.notice("accepted", json!({ "id": id, "name": name, "path": shown }), line).await;
        match done {
            // A file of no bytes ends at its accept: kept first, then said.
            Some(Event::Received { whole, .. }) => {
                let kept = self.received(id, incoming, whole, out).await;
                self.kept.insert(id, kept);
            }
            _ => {
                self.files.writing.insert(id, incoming);
            }
        }
        for record in records {
            self.say_kept(record);
        }
        Ok(())
    }

    /// Send `record`; the word on a file says whether it was kept.
    fn say_kept(&mut self, record: Record) {
        let record = match record {
            Record::Done { id, whole } => Record::Done { id, whole: whole && self.kept.remove(&id).unwrap_or(true) },
            other => other,
        };
        self.send(record);
    }

    /// The end of a file that this side accepted: whether it was kept.
    async fn received<W: AsyncWrite + Unpin>(
        &mut self,
        id: u64,
        file: Incoming,
        whole: bool,
        out: &mut Output<W>,
    ) -> bool {
        match file.finish(whole).await {
            Ok(path) => {
                let shown = path.display().to_string();
                let line = format!("received file {id} into {shown}; its SHA-256 matched");
                out.notice("received", json!({ "id": id, "path": shown, "whole": true }), line).await;
                true
            }
            Err(why) => {
                let line = format!("file {id}: {why}");
                out.notice("received", json!({ "id": id, "whole": false, "error": why }), line).await;
                false
            }
        }
    }

    /// The records that came, each with its events and replies.
    pub async fn records<W: AsyncWrite + Unpin>(
        &mut self,
        decoder: &mut Decoder,
        out: &mut Output<W>,
    ) -> Option<Ended> {
        loop {
            let record = match decoder.next_record() {
                Ok(Some(record)) => record,
                Ok(None) => return None,
                Err(e) => return Some(Ended::Failed(format!("the peer sent {e}"))),
            };
            let (events, replies) = match self.session.receive(record) {
                Ok(done) => done,
                Err(e) => return Some(Ended::Failed(e.to_string())),
            };
            // The events first: a file is in its place before the peer hears
            // that it arrived.
            for event in events {
                if let Some(ended) = self.event(event, out).await {
                    return Some(ended);
                }
            }
            for reply in replies {
                self.say_kept(reply);
            }
        }
    }

    async fn event<W: AsyncWrite + Unpin>(&mut self, event: Event, out: &mut Output<W>) -> Option<Ended> {
        match event {
            Event::Peer { nick } => {
                out.notice("peer", json!({ "nick": nick }), format!("the peer is {}", safe(&nick))).await
            }
            Event::Message { id, text } => out.message(&self.peer(), id, &text).await,
            Event::Delivered { id } => {
                self.once_done |= self.once == Some(id) && matches!(self.opts.once, Once::Send(_));
                out.notice("delivered", json!({ "id": id }), String::new()).await;
            }
            Event::Offered { id, name, size } => {
                self.files.offered.insert(id, (name.clone(), size));
                if self.opts.accept_dir.is_some() {
                    if let Err(why) = self.accept(id, None, out).await {
                        let _ = self.session.decline(id).map(|record| self.send(record));
                        self.files.offered.remove(&id);
                        let line = format!("declined file {id}: {why}");
                        out.notice("declined", json!({ "id": id, "error": why }), line).await;
                    }
                    return None;
                }
                let line = format!(
                    "{} offers {} ({size} bytes) as file {id}: /accept {id} [PATH] or /decline {id}",
                    safe(&self.peer()),
                    safe(&name)
                );
                out.notice("offer", json!({ "id": id, "name": name, "size": size }), line).await;
            }
            Event::Accepted { id } => {
                let path = self.files.ours.get(&id).cloned()?;
                if self.session.left(id) > 0 {
                    match tokio::fs::File::open(&path).await {
                        Ok(file) => self.files.sending.push_back(Sending { id, file }),
                        Err(e) => return Some(Ended::Failed(format!("{}: {e}", path.display()))),
                    }
                }
                out.notice("taken", json!({ "id": id }), format!("{} takes file {id}", safe(&self.peer()))).await;
            }
            Event::Declined { id } => {
                self.files.ours.remove(&id);
                out.notice("declined", json!({ "id": id }), format!("{} declined file {id}", safe(&self.peer()))).await;
                if self.once == Some(id) {
                    return Some(Ended::Refused("the peer declined the file".into()));
                }
            }
            Event::Bytes { id, data, .. } => {
                let file = self.files.writing.get_mut(&id)?;
                if let Err(why) = file.write(&data).await {
                    return Some(Ended::Failed(why));
                }
            }
            Event::Received { id, whole } => {
                let file = self.files.writing.remove(&id)?;
                let kept = self.received(id, file, whole, out).await;
                self.kept.insert(id, kept);
            }
            Event::Sent { id, whole } => {
                self.files.ours.remove(&id);
                let line = if whole {
                    format!("file {id} arrived whole")
                } else {
                    format!("file {id} arrived with another SHA-256, and was not kept")
                };
                out.notice("sent", json!({ "id": id, "whole": whole }), line).await;
                if self.once == Some(id) {
                    if !whole {
                        return Some(Ended::Refused("the file arrived damaged".into()));
                    }
                    self.once_done = true;
                }
            }
            Event::Busy => return Some(Ended::Busy),
        }
        None
    }

    /// The peer ended the stream.
    pub fn peer_ended(&self) -> Ended {
        Ended::PeerLeft
    }

    /// The summary: files half written go, and the messages with no
    /// acknowledgement are listed.
    pub fn end(self, ended: Ended) -> Summary {
        for (_, file) in self.files.writing {
            file.abandon();
        }
        let undelivered = self.session.undelivered().into_iter().map(|(_, text)| text.to_string()).collect();
        Summary { ended, undelivered }
    }
}
