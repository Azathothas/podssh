//! One conversation (T-099): the ids of the messages and their
//! acknowledgements, and the files offered each way. It turns the user's
//! acts into records, and each record of the peer into events for the user
//! and records to send back. A file's bytes reach the caller only once this
//! side accepted it, in order and within its size, and its SHA-256 is
//! checked at its end; a chunk of a file that was not accepted ends the
//! conversation.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use super::record::{Record, MAX_NICK, MAX_TEXT, VERSION};

/// What the user's act cannot be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// A message longer than a record holds.
    TooLong,
    /// No file of the peer has this id, or it is past its offer.
    NoOffer(u64),
    /// This side's file of this id is not accepted, or all its bytes went.
    NotSending(u64),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::TooLong => write!(f, "a message is at most {MAX_TEXT} bytes"),
            Refused::NoOffer(id) => write!(f, "no file waits for an answer under the number {id}"),
            Refused::NotSending(id) => write!(f, "the file {id} is not accepted, or all of it went"),
        }
    }
}

/// A record of the peer that breaks the protocol: the conversation ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// A greeting of another version.
    Version(u8),
    /// A record before the greeting.
    NoHello,
    /// A record that names an id that this side never gave or got.
    UnknownId(u64),
    /// A chunk of a file that this side did not accept.
    NotAccepted(u64),
    /// A chunk at another offset than the next byte.
    OutOfOrder { id: u64, expected: u64, got: u64 },
    /// More bytes than the offer said.
    TooMuch(u64),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Version(v) => write!(f, "the peer speaks version {v} of chat, this side {VERSION}"),
            ProtocolError::NoHello => f.write_str("the peer sent a record before its greeting"),
            ProtocolError::UnknownId(id) => write!(f, "the peer named the id {id}, which nothing has"),
            ProtocolError::NotAccepted(id) => write!(f, "the peer sent bytes of the file {id}, which was not accepted"),
            ProtocolError::OutOfOrder { id, expected, got } => {
                write!(f, "the peer sent bytes of the file {id} at {got}, not at {expected}")
            }
            ProtocolError::TooMuch(id) => write!(f, "the peer sent more of the file {id} than it offered"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// What a record of the peer means for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The peer's greeting, with its nick.
    Peer {
        nick: String,
    },
    Message {
        id: u64,
        text: String,
    },
    /// The peer has this side's message of this id.
    Delivered {
        id: u64,
    },
    /// The peer offers a file; the user accepts or declines it.
    Offered {
        id: u64,
        name: String,
        size: u64,
    },
    /// The peer accepted this side's file: its bytes may go.
    Accepted {
        id: u64,
    },
    Declined {
        id: u64,
    },
    /// Bytes of a file that this side accepted, at their offset, in order.
    Bytes {
        id: u64,
        offset: u64,
        data: Vec<u8>,
    },
    /// A file that this side accepted ended: whole when its SHA-256 matched.
    Received {
        id: u64,
        whole: bool,
    },
    /// A file that this side sent arrived: whole when the peer's SHA-256
    /// matched.
    Sent {
        id: u64,
        whole: bool,
    },
    /// The side that waits has another peer.
    Busy,
}

enum Incoming {
    Offered { size: u64, sha256: [u8; 32] },
    Accepted { size: u64, sha256: [u8; 32], received: u64, hasher: Sha256 },
    Over,
}

enum Outgoing {
    Offered { size: u64 },
    Sending { size: u64, sent: u64 },
    Over,
}

/// One conversation's state.
#[derive(Default)]
pub struct Session {
    peer: Option<String>,
    next_id: u64,
    unacked: BTreeMap<u64, String>,
    outgoing: HashMap<u64, Outgoing>,
    incoming: HashMap<u64, Incoming>,
}

impl Session {
    pub fn new() -> Session {
        Session::default()
    }

    /// This side's greeting; a nick past its limit is cut.
    pub fn hello(&self, nick: &str) -> Record {
        let mut cut = nick.len().min(MAX_NICK);
        while !nick.is_char_boundary(cut) {
            cut -= 1;
        }
        Record::Hello { version: VERSION, nick: nick[..cut].to_string() }
    }

    /// The peer's nick, once it greeted.
    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// A message: its id, and its record.
    pub fn text(&mut self, text: &str) -> Result<(u64, Record), Refused> {
        if text.len() > MAX_TEXT {
            return Err(Refused::TooLong);
        }
        let id = self.id();
        self.unacked.insert(id, text.to_string());
        Ok((id, Record::Text { id, text: text.to_string() }))
    }

    /// An offer of a file: its id, and its record.
    pub fn offer(&mut self, name: &str, size: u64, sha256: [u8; 32]) -> (u64, Record) {
        let id = self.id();
        self.outgoing.insert(id, Outgoing::Offered { size });
        (id, Record::Offer { id, size, sha256, name: name.to_string() })
    }

    /// Accept the peer's file `id`: the records to send, and, for a file of
    /// no bytes, its end at once.
    pub fn accept(&mut self, id: u64) -> Result<(Vec<Record>, Option<Event>), Refused> {
        let Some(Incoming::Offered { size, sha256 }) = self.incoming.get(&id) else {
            return Err(Refused::NoOffer(id));
        };
        let (size, sha256) = (*size, *sha256);
        let mut records = vec![Record::Accept { id }];
        if size == 0 {
            let whole = Sha256::digest([]).as_slice() == sha256;
            self.incoming.insert(id, Incoming::Over);
            records.push(Record::Done { id, whole });
            return Ok((records, Some(Event::Received { id, whole })));
        }
        self.incoming.insert(id, Incoming::Accepted { size, sha256, received: 0, hasher: Sha256::new() });
        Ok((records, None))
    }

    /// Decline the peer's file `id`.
    pub fn decline(&mut self, id: u64) -> Result<Record, Refused> {
        match self.incoming.get(&id) {
            Some(Incoming::Offered { .. }) => {
                self.incoming.insert(id, Incoming::Over);
                Ok(Record::Decline { id })
            }
            _ => Err(Refused::NoOffer(id)),
        }
    }

    /// The next bytes of this side's accepted file `id`, as a record: they
    /// go at the offset after the last.
    pub fn chunk(&mut self, id: u64, data: Vec<u8>) -> Result<Record, Refused> {
        let Some(Outgoing::Sending { size, sent }) = self.outgoing.get_mut(&id) else {
            return Err(Refused::NotSending(id));
        };
        let end = sent.saturating_add(data.len() as u64);
        if end > *size {
            return Err(Refused::NotSending(id));
        }
        let offset = *sent;
        *sent = end;
        Ok(Record::Chunk { id, offset, data })
    }

    /// The bytes of this side's file `id` that are still to go.
    pub fn left(&self, id: u64) -> u64 {
        match self.outgoing.get(&id) {
            Some(Outgoing::Sending { size, sent }) => size - sent,
            _ => 0,
        }
    }

    /// The messages that the peer has not acknowledged, in order.
    pub fn undelivered(&self) -> Vec<(u64, &str)> {
        self.unacked.iter().map(|(id, text)| (*id, text.as_str())).collect()
    }

    /// What a record of the peer means: the events for the user, and the
    /// records to send back.
    pub fn receive(&mut self, record: Record) -> Result<(Vec<Event>, Vec<Record>), ProtocolError> {
        if self.peer.is_none() && !matches!(record, Record::Hello { .. } | Record::Busy) {
            return Err(ProtocolError::NoHello);
        }
        let event = |e: Event| Ok((vec![e], Vec::new()));
        match record {
            Record::Hello { version, nick } => {
                if version != VERSION {
                    return Err(ProtocolError::Version(version));
                }
                self.peer = Some(nick.clone());
                event(Event::Peer { nick })
            }
            Record::Busy => event(Event::Busy),
            Record::Text { id, text } => Ok((vec![Event::Message { id, text }], vec![Record::Ack { id }])),
            Record::Ack { id } => match self.unacked.remove(&id) {
                Some(_) => event(Event::Delivered { id }),
                None => Err(ProtocolError::UnknownId(id)),
            },
            Record::Offer { id, size, sha256, name } => {
                if self.incoming.contains_key(&id) {
                    return Err(ProtocolError::UnknownId(id));
                }
                self.incoming.insert(id, Incoming::Offered { size, sha256 });
                event(Event::Offered { id, name, size })
            }
            Record::Accept { id } => match self.outgoing.get(&id) {
                Some(Outgoing::Offered { size }) => {
                    let size = *size;
                    self.outgoing.insert(id, Outgoing::Sending { size, sent: 0 });
                    event(Event::Accepted { id })
                }
                _ => Err(ProtocolError::UnknownId(id)),
            },
            Record::Decline { id } => match self.outgoing.get(&id) {
                Some(Outgoing::Offered { .. }) => {
                    self.outgoing.insert(id, Outgoing::Over);
                    event(Event::Declined { id })
                }
                _ => Err(ProtocolError::UnknownId(id)),
            },
            Record::Chunk { id, offset, data } => self.bytes(id, offset, data),
            Record::Done { id, whole } => match self.outgoing.get(&id) {
                Some(Outgoing::Sending { .. }) | Some(Outgoing::Offered { .. }) => {
                    self.outgoing.insert(id, Outgoing::Over);
                    event(Event::Sent { id, whole })
                }
                _ => Err(ProtocolError::UnknownId(id)),
            },
        }
    }

    /// A chunk of the peer's file `id`: in order, within its size, and only
    /// once this side accepted it.
    fn bytes(&mut self, id: u64, offset: u64, data: Vec<u8>) -> Result<(Vec<Event>, Vec<Record>), ProtocolError> {
        let Some(Incoming::Accepted { size, sha256, received, hasher }) = self.incoming.get_mut(&id) else {
            return Err(ProtocolError::NotAccepted(id));
        };
        if offset != *received {
            return Err(ProtocolError::OutOfOrder { id, expected: *received, got: offset });
        }
        let end = received.saturating_add(data.len() as u64);
        if end > *size {
            return Err(ProtocolError::TooMuch(id));
        }
        hasher.update(&data);
        *received = end;
        let mut events = vec![Event::Bytes { id, offset, data }];
        let mut replies = Vec::new();
        if end == *size {
            let whole = std::mem::take(hasher).finalize().as_slice() == sha256;
            self.incoming.insert(id, Incoming::Over);
            events.push(Event::Received { id, whole });
            replies.push(Record::Done { id, whole });
        }
        Ok((events, replies))
    }
}
