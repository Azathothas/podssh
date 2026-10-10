//! The files of a chat over IRC (T-252). The offer goes to the channel; the
//! transfer then runs between two nicks alone, in T-097's chunks, each line
//! paced as T-275 says, so that a server's rate limit does not close the
//! link. A file goes only once its receiver accepted it; it is written under a
//! temporary name, checked against the SHA-256 that its sender sends at the
//! end, and kept only whole, never over a file that is there. One file goes
//! at a time; another accept meanwhile is told that this side is busy.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use podssh_core::irc::isupport::Isupport;
use podssh_core::irc::transfer::{as_privmsg, chunk_bytes, deny, Accept, Done, Line, Offer, Pace, Receiver, Sender};
use podssh_core::irc::{Message, TransferLimits};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time::Instant;

use crate::chat::files::{self, Incoming};

/// What the conversation hears from a transfer line.
pub(super) enum Heard {
    /// A notice for the user: its event, its fields, its words.
    Notice(&'static str, Value, String),
    /// A peer's offer, waiting under this number.
    Offered(u64),
    /// This side's file arrived whole.
    Arrived(u64),
    /// This side's file arrived with another SHA-256, and was not kept.
    Damaged(u64),
}

fn notice(event: &'static str, fields: Value, line: String) -> Heard {
    Heard::Notice(event, fields, line)
}

/// An offer of this side, with its digest.
struct Ours {
    path: PathBuf,
    sender: Sender,
    sha256: String,
    transfer_id: String,
}

/// The file that goes now.
struct Going {
    id: u64,
    to: String,
    ours: Ours,
    file: tokio::fs::File,
}

/// A peer's offer, waiting for the user.
struct Offered {
    from: String,
    offer: Offer,
}

/// A file that comes.
struct Coming {
    id: u64,
    receiver: Receiver,
    incoming: Incoming,
}

pub(super) struct Files {
    tag: String,
    next_id: u64,
    ours: HashMap<u64, Ours>,
    going: Option<Going>,
    offered: HashMap<u64, Offered>,
    /// By the sender's nick and the transfer's id.
    coming: HashMap<(String, String), Coming>,
    paced: VecDeque<Message>,
    pace: Pace,
}

impl Files {
    pub fn new() -> Files {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let tag = format!("{:06x}", (nanos ^ std::process::id().rotate_left(13)) & 0xff_ffff);
        Files {
            tag,
            next_id: 0,
            ours: HashMap::new(),
            going: None,
            offered: HashMap::new(),
            coming: HashMap::new(),
            paced: VecDeque::new(),
            pace: Pace::default(),
        }
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Whether a transfer line waits for its turn.
    pub fn paced(&self) -> bool {
        !self.paced.is_empty()
    }

    /// When the next paced line may go.
    pub fn next_at(&self, now: Instant) -> Instant {
        now + self.pace.wait(now.into_std())
    }

    /// The next paced line, now that its turn came.
    pub fn take_paced(&mut self, now: Instant) -> Option<Message> {
        let message = self.paced.pop_front()?;
        self.pace.sent(now.into_std());
        Some(message)
    }

    /// Offer the file at `path` to `channel`: its number and the offer.
    pub async fn offer(&mut self, path: &Path, channel: &str, isupport: &Isupport) -> Result<(u64, Message), String> {
        let (size, digest) = files::digest(path).await?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let id = self.id();
        let transfer_id = format!("{}{id}", self.tag);
        // The chunks go to one nick; the room for them is sized for the
        // longer of the channel and a nick.
        let target = "x".repeat(channel.len().max(isupport.nicklen()));
        let chunk = chunk_bytes(isupport, &target, &transfer_id, size)?;
        let limits = TransferLimits { chunk_bytes: chunk, ..TransferLimits::default() };
        let sender = Sender::new(transfer_id.clone(), name, size, limits).map_err(|e| e.to_string())?;
        let message = sender.offer(channel);
        let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
        self.ours.insert(id, Ours { path: path.to_path_buf(), sender, sha256, transfer_id });
        Ok((id, message))
    }

    /// The user's accept of the peer's file `id`, into `to` or `dir`: the
    /// accept line to its sender.
    pub async fn accept(&mut self, id: u64, to: Option<&Path>, dir: &Path) -> Result<(String, Message), String> {
        let waiting = self.offered.get(&id).ok_or(format!("no file waits under the number {id}"))?;
        let receiver = Receiver::from_offer(&waiting.offer)?;
        let incoming = Incoming::open(files::target(receiver.name(), to, dir)?, id).await?;
        let Offered { from, offer } = self.offered.remove(&id).ok_or("no such file")?;
        let shown = incoming.path().display().to_string();
        let line = Line::Accept(Accept { transfer_id: offer.transfer_id.clone(), from_chunk: 0 });
        self.coming.insert((from.clone(), offer.transfer_id), Coming { id, receiver, incoming });
        Ok((shown, as_privmsg(&from, &line)))
    }

    /// The user's decline of the peer's file `id`.
    pub fn decline(&mut self, id: u64) -> Result<Message, String> {
        let Offered { from, offer } = self.offered.remove(&id).ok_or(format!("no file waits under the number {id}"))?;
        deny(&from, &offer.transfer_id, "declined").map_err(|e| e.to_string())
    }

    /// The name and size of the peer's offer `id`.
    pub fn described(&self, id: u64) -> Option<(String, String, u64)> {
        self.offered.get(&id).map(|o| (o.from.clone(), o.offer.name.clone(), o.offer.total))
    }

    /// A transfer line of `from`.
    pub async fn heard(&mut self, from: &str, line: Line) -> Vec<Heard> {
        match line {
            Line::Offer(offer) => match Receiver::from_offer(&offer) {
                Ok(_) => {
                    let id = self.id();
                    self.offered.insert(id, Offered { from: from.to_string(), offer });
                    vec![Heard::Offered(id)]
                }
                Err(why) => vec![notice(
                    "refused",
                    json!({ "from": from, "error": why }),
                    format!("an offer of {from} was refused: {why}"),
                )],
            },
            Line::Accept(accept) => self.accepted(from, &accept.transfer_id).await,
            Line::Chunk(chunk) => {
                let key = (from.to_string(), chunk.transfer_id.clone());
                let Some(coming) = self.coming.get_mut(&key) else { return Vec::new() };
                let written = match coming.receiver.accept(&chunk) {
                    Ok(bytes) => coming.incoming.write(&bytes).await,
                    Err(why) => Err(why),
                };
                match written {
                    Ok(()) => {
                        self.paced.push_back(coming.receiver.ack(from));
                        Vec::new()
                    }
                    Err(why) => self.lost(key, &why),
                }
            }
            Line::Ack(ack) => self.acked(from, &ack.transfer_id, ack.index).await,
            Line::Digest(digest) => {
                let key = (from.to_string(), digest.transfer_id.clone());
                let Some(Coming { id, receiver, incoming }) = self.coming.remove(&key) else { return Vec::new() };
                let whole = receiver.is_complete() && receiver.finish().is_ok() && receiver.verify(&digest.sha256);
                match incoming.finish(whole).await {
                    Ok(path) => {
                        self.paced.push_back(as_privmsg(from, &Line::Done(Done { transfer_id: digest.transfer_id })));
                        let shown = path.display().to_string();
                        let line = format!("received file {id} into {shown}; its SHA-256 matched");
                        vec![notice("received", json!({ "id": id, "path": shown, "whole": true }), line)]
                    }
                    Err(why) => {
                        if let Ok(denied) = deny(from, &digest.transfer_id, "damaged") {
                            self.paced.push_back(denied);
                        }
                        vec![notice(
                            "received",
                            json!({ "id": id, "whole": false, "error": why }),
                            format!("file {id}: {why}"),
                        )]
                    }
                }
            }
            Line::Done(done) => match self.going.take() {
                Some(going) if going.to == from && going.ours.transfer_id == done.transfer_id => {
                    vec![Heard::Arrived(going.id)]
                }
                other => {
                    self.going = other;
                    Vec::new()
                }
            },
            // A line of a later podssh: said, and nothing changes.
            Line::Unknown { verb, .. } => {
                let line = format!("{from} sent a transfer line that this podssh does not know: {verb}");
                vec![notice("protocol", json!({ "from": from, "verb": verb }), line)]
            }
            Line::Deny(denied) => {
                if self.going.as_ref().is_some_and(|g| g.to == from && g.ours.transfer_id == denied.transfer_id) {
                    let going = self.going.take().expect("checked");
                    if denied.reason == "damaged" {
                        return vec![Heard::Damaged(going.id)];
                    }
                    let line = format!("{from} stopped file {}: {}", going.id, denied.reason);
                    return vec![notice(
                        "declined",
                        json!({ "id": going.id, "from": from, "reason": denied.reason }),
                        line,
                    )];
                }
                let id = self.ours.iter().find(|(_, o)| o.transfer_id == denied.transfer_id).map(|(id, _)| *id);
                let Some(id) = id else { return Vec::new() };
                let line = format!("{from} declined file {id}: {}", denied.reason);
                vec![notice("declined", json!({ "id": id, "from": from, "reason": denied.reason }), line)]
            }
        }
    }

    /// `from` takes this side's file: it goes, unless another goes now.
    async fn accepted(&mut self, from: &str, transfer_id: &str) -> Vec<Heard> {
        let Some(id) = self.ours.iter().find(|(_, o)| o.transfer_id == transfer_id).map(|(id, _)| *id) else {
            return Vec::new();
        };
        if self.going.is_some() {
            if let Ok(busy) = deny(from, transfer_id, "busy: another file goes; offer again later") {
                self.paced.push_back(busy);
            }
            return vec![notice(
                "busy",
                json!({ "id": id, "from": from }),
                format!("{from} asked for file {id} while another goes; told busy"),
            )];
        }
        let ours = self.ours.remove(&id).expect("found");
        let file = match tokio::fs::File::open(&ours.path).await {
            Ok(file) => file,
            Err(e) => {
                return vec![notice(
                    "error",
                    json!({ "error": e.to_string() }),
                    format!("{}: {e}", ours.path.display()),
                )]
            }
        };
        self.going = Some(Going { id, to: from.to_string(), ours, file });
        let mut heard = vec![notice("taken", json!({ "id": id, "by": from }), format!("{from} takes file {id}"))];
        heard.extend(self.next_chunk().await);
        heard
    }

    /// The ack of a chunk: the next one, or the digest after the last.
    async fn acked(&mut self, from: &str, transfer_id: &str, index: u64) -> Vec<Heard> {
        let Some(going) = self.going.as_mut().filter(|g| g.to == from && g.ours.transfer_id == transfer_id) else {
            return Vec::new();
        };
        if !going.ours.sender.acknowledge(index) {
            return Vec::new();
        }
        if going.ours.sender.is_complete() {
            let digest = going.ours.sender.digest(&going.to, &going.ours.sha256);
            self.paced.push_back(digest);
            return Vec::new();
        }
        self.next_chunk().await
    }

    /// The next chunk of the file that goes, into its turn.
    async fn next_chunk(&mut self) -> Vec<Heard> {
        let Some(going) = self.going.as_mut() else { return Vec::new() };
        let Some((offset, len)) = going.ours.sender.next_range() else {
            let digest = going.ours.sender.digest(&going.to, &going.ours.sha256);
            self.paced.push_back(digest);
            return Vec::new();
        };
        let mut bytes = vec![0u8; len];
        let read = async {
            going.file.seek(std::io::SeekFrom::Start(offset)).await?;
            going.file.read_exact(&mut bytes).await
        };
        if let Err(e) = read.await {
            let why = format!("{}: {e}", going.ours.path.display());
            self.going = None;
            return vec![notice("error", json!({ "error": why }), why.clone())];
        }
        match going.ours.sender.next_chunk_message(&going.to, &bytes) {
            Ok(chunk) => {
                self.paced.push_back(chunk);
                Vec::new()
            }
            Err(why) => {
                self.going = None;
                vec![notice("error", json!({ "error": why }), why.clone())]
            }
        }
    }

    /// A file that cannot go on: its temporary file goes, and its sender
    /// hears why.
    fn lost(&mut self, key: (String, String), why: &str) -> Vec<Heard> {
        let Some(coming) = self.coming.remove(&key) else { return Vec::new() };
        let id = coming.id;
        coming.incoming.abandon();
        if let Ok(denied) = deny(&key.0, &key.1, "damaged") {
            self.paced.push_back(denied);
        }
        vec![notice("received", json!({ "id": id, "whole": false, "error": why }), format!("file {id}: {why}"))]
    }

    /// The end of the conversation: each file half written goes.
    pub fn abandon(&mut self) {
        for (_, coming) in self.coming.drain() {
            coming.incoming.abandon();
        }
    }
}
