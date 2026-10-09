//! The handshake of one link, at each end: a new session or a resume.
//!
//! The far end sends `GREETING` at once, and the client `OPEN`; neither
//! record waits for the other side's, so each carries a fresh nonce of its
//! own. (On the reverse road the client sends `OPEN` only after `GREETING`,
//! to tell a far end with no layer by its first byte.)
//!
//! - A new session: `OPEN` carries the client's X25519 public key, and
//!   `ACCEPT` the far end's with the session's id. Each side derives the
//!   secret from the shared value and both nonces ([`super::secret::derive`]).
//! - A resume: `OPEN` names the session; once the client has the far end's
//!   nonce, `PROOF` carries its received offset and an HMAC over both nonces
//!   and that offset. The far end checks it, and its `ACCEPT` carries its own
//!   received offset and proof, which the client checks. A `PROOF` of an
//!   earlier link names that link's nonce, so a relay that replays one fails.
//!
//! An active relay can still put itself in the middle of a new session's
//! exchange, as it can break any session today; SSH, above the layer, keeps
//! the bytes secret and whole. What the layer refuses is a passive reader of
//! the relay's logs taking a session over.

use std::fmt;

use super::record::{Acceptance, Hello, Opening, Record, RefuseCode, Role, VERSION};
use super::secret::{
    derive, prove, verify, Claim, Entropy, Exchange, KeyPair, NoRandom, Nonce, Prover, Secret, SessionId, ID_LEN,
};
use super::sessions::Sessions;

/// Why a handshake failed at this end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The peer refused, with its code and its reason.
    Refused { code: RefuseCode, reason: String },
    /// The peer ended the session before it was established.
    Closed(String),
    /// A record that the handshake does not expect at this point.
    Unexpected(&'static str),
    /// The peer speaks no version that this side speaks.
    Version(u8),
    /// The peer has a role that cannot be at its end.
    Role(Role),
    /// The far end's proof is not the proof of this session.
    BadProof,
    /// A public key of low order: the exchange would give no secret.
    WeakKey,
    /// The system gave no random bytes.
    NoRandom,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::Refused { code, reason } if reason.is_empty() => write!(f, "refused ({code})"),
            HandshakeError::Refused { code, reason } => {
                write!(f, "refused ({code}): {}", podssh_ws::text::one_line(reason))
            }
            HandshakeError::Closed(reason) if reason.is_empty() => f.write_str("the far end ended the session"),
            HandshakeError::Closed(reason) => {
                write!(f, "the far end ended the session: {}", podssh_ws::text::one_line(reason))
            }
            HandshakeError::Unexpected(what) => write!(f, "{what} where the handshake did not expect it"),
            HandshakeError::Version(v) => write!(f, "the peer speaks version {v} of the layer, and this side 1"),
            HandshakeError::Role(role) => write!(f, "the peer is {role}, which cannot be at that end"),
            HandshakeError::BadProof => f.write_str("the far end's proof of the session is wrong"),
            HandshakeError::WeakKey => f.write_str("a public key of low order, which gives no secret"),
            HandshakeError::NoRandom => NoRandom.fmt(f),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<NoRandom> for HandshakeError {
    fn from(_: NoRandom) -> Self {
        HandshakeError::NoRandom
    }
}

/// A link that carries its session from here.
#[derive(Debug)]
pub struct Established {
    pub id: SessionId,
    pub secret: Secret,
    /// This side's received offset: the peer sends from there. 0 for a new
    /// session.
    pub received: u64,
    /// The peer's received offset: this side sends from there. 0 for a new
    /// session.
    pub peer_received: u64,
    /// The version that the session speaks.
    pub version: u8,
    pub peer_role: Role,
    /// The features that both sides named.
    pub features: Vec<String>,
    /// Whether the link resumed a session.
    pub resumed: bool,
}

/// What the client asks for.
pub enum Ask {
    New,
    /// The session `id`, whose secret is `secret`, and whose client has each
    /// byte below `received`.
    Resume {
        id: SessionId,
        secret: Secret,
        received: u64,
    },
}

/// What a step of a handshake asks of the link.
#[derive(Debug)]
pub enum Step {
    /// Send this record, then wait for the next.
    Send(Record),
    /// Wait for the next record.
    Wait,
    /// The link carries the session; the far end sends the record first.
    Established(Option<Record>, Box<Established>),
    /// Send this `REFUSE`, then end the link (the far end only).
    Refuse(Record, HandshakeError),
}

/// The common part of the features of both sides, in the order of `ours`.
fn common(ours: &[String], theirs: &[String]) -> Vec<String> {
    ours.iter().filter(|name| theirs.contains(name)).cloned().collect()
}

fn names(features: &[&str]) -> Vec<String> {
    features.iter().map(|name| name.to_string()).collect()
}

/// The client's end of one link.
pub struct ClientHandshake {
    ours: Hello,
    key: Option<KeyPair>,
    resume: Option<(SessionId, Secret, u64)>,
    far: Option<Hello>,
    done: bool,
}

impl ClientHandshake {
    /// The handshake and its `OPEN`: a new session or a resume.
    pub fn start(ask: Ask, features: &[&str], entropy: &mut dyn Entropy) -> Result<(Self, Record), HandshakeError> {
        let nonce = Nonce::fresh(entropy)?;
        let ours = Hello { version: VERSION, role: Role::CLIENT, nonce, features: names(features) };
        let (key, resume, opening) = match ask {
            Ask::New => {
                let key = KeyPair::fresh(entropy)?;
                let opening = Opening::New { public: key.public };
                (Some(key), None, opening)
            }
            Ask::Resume { id, secret, received } => (None, Some((id, secret, received)), Opening::Resume { id }),
        };
        let open = Record::Open { hello: ours.clone(), opening };
        Ok((ClientHandshake { ours, key, resume, far: None, done: false }, open))
    }

    /// The next record from the far end.
    pub fn handle(&mut self, record: Record) -> Result<Step, HandshakeError> {
        if self.done {
            return Err(HandshakeError::Unexpected("a record after the handshake"));
        }
        let step = self.step(record);
        if !matches!(step, Ok(Step::Send(_) | Step::Wait)) {
            self.done = true;
        }
        step
    }

    fn step(&mut self, record: Record) -> Result<Step, HandshakeError> {
        match record {
            Record::Greeting(_) if self.far.is_some() => Err(HandshakeError::Unexpected("a second GREETING")),
            Record::Greeting(hello) => {
                if hello.version == 0 {
                    return Err(HandshakeError::Version(hello.version));
                }
                if !hello.role.is_far() {
                    return Err(HandshakeError::Role(hello.role));
                }
                let step = match &self.resume {
                    Some((id, secret, received)) => {
                        let claim = Claim {
                            prover: Prover::Client,
                            id,
                            far_nonce: &hello.nonce,
                            client_nonce: &self.ours.nonce,
                            offset: *received,
                        };
                        Step::Send(Record::Proof { offset: *received, proof: prove(secret, &claim) })
                    }
                    None => Step::Wait,
                };
                self.far = Some(hello);
                Ok(step)
            }
            Record::Refuse { code, reason } => Err(HandshakeError::Refused { code, reason }),
            Record::Close { reason } => Err(HandshakeError::Closed(reason)),
            Record::Accept(acceptance) => {
                let Some(far) = self.far.take() else {
                    return Err(HandshakeError::Unexpected("ACCEPT before GREETING"));
                };
                accepted(&self.ours, &far, acceptance, self.key.take(), self.resume.take())
            }
            other => Err(HandshakeError::Unexpected(other.name())),
        }
    }
}

/// The client's end of an `ACCEPT`: the secret of a new session, or the
/// check of the far end's proof on a resume.
fn accepted(
    ours: &Hello,
    far: &Hello,
    acceptance: Acceptance,
    key: Option<KeyPair>,
    resume: Option<(SessionId, Secret, u64)>,
) -> Result<Step, HandshakeError> {
    let version = VERSION.min(far.version);
    let features = common(&ours.features, &far.features);
    match (acceptance, key, resume) {
        (Acceptance::New { id, public }, Some(key), None) => {
            let shared = key.shared(&public).ok_or(HandshakeError::WeakKey)?;
            let secret = derive(&Exchange {
                shared: &shared,
                far_nonce: &far.nonce,
                client_nonce: &ours.nonce,
                id: &id,
                client_public: &key.public,
                far_public: &public,
            });
            let session = Established {
                id,
                secret,
                received: 0,
                peer_received: 0,
                version,
                peer_role: far.role,
                features,
                resumed: false,
            };
            Ok(Step::Established(None, Box::new(session)))
        }
        (Acceptance::Resume { offset, proof }, None, Some((id, secret, received))) => {
            let claim =
                Claim { prover: Prover::Far, id: &id, far_nonce: &far.nonce, client_nonce: &ours.nonce, offset };
            if !verify(&secret, &claim, &proof) {
                return Err(HandshakeError::BadProof);
            }
            let session = Established {
                id,
                secret,
                received,
                peer_received: offset,
                version,
                peer_role: far.role,
                features,
                resumed: true,
            };
            Ok(Step::Established(None, Box::new(session)))
        }
        (Acceptance::New { .. }, ..) => Err(HandshakeError::Unexpected("a new session's ACCEPT to a resume")),
        (Acceptance::Resume { .. }, ..) => Err(HandshakeError::Unexpected("a resume's ACCEPT to a new session")),
    }
}

enum FarState {
    /// `GREETING` is out; waiting for `OPEN`.
    Greeted,
    /// A resume of `id`: waiting for its `PROOF`.
    Proving {
        id: SessionId,
        client: Hello,
    },
    Done,
}

/// The far end of one link.
pub struct FarHandshake {
    ours: Hello,
    state: FarState,
}

fn refuse(code: RefuseCode, reason: &str, error: HandshakeError) -> Step {
    Step::Refuse(Record::Refuse { code, reason: reason.to_string() }, error)
}

impl FarHandshake {
    /// The handshake and its `GREETING`.
    pub fn start(role: Role, features: &[&str], entropy: &mut dyn Entropy) -> Result<(Self, Record), HandshakeError> {
        let ours = Hello { version: VERSION, role, nonce: Nonce::fresh(entropy)?, features: names(features) };
        let greeting = Record::Greeting(ours.clone());
        Ok((FarHandshake { ours, state: FarState::Greeted }, greeting))
    }

    /// The next record from the client. A new session is added to
    /// `sessions`; a resume is checked against it.
    pub fn handle(
        &mut self,
        record: Record,
        sessions: &mut Sessions,
        entropy: &mut dyn Entropy,
    ) -> Result<Step, HandshakeError> {
        let state = std::mem::replace(&mut self.state, FarState::Done);
        match (state, record) {
            (FarState::Greeted, Record::Open { hello, opening }) => {
                if hello.version == 0 {
                    let error = HandshakeError::Version(hello.version);
                    return Ok(refuse(RefuseCode::VERSION, "this far end speaks version 1", error));
                }
                if hello.role != Role::CLIENT {
                    let error = HandshakeError::Role(hello.role);
                    return Ok(refuse(RefuseCode::ROLE, "only a client opens a session", error));
                }
                match opening {
                    Opening::New { public } => self.new_session(hello, public, sessions, entropy),
                    Opening::Resume { id } if sessions.contains(&id) => {
                        self.state = FarState::Proving { id, client: hello };
                        Ok(Step::Wait)
                    }
                    Opening::Resume { .. } => Ok(refuse(
                        RefuseCode::UNKNOWN_SESSION,
                        "no such session here",
                        HandshakeError::Unexpected("a resume of an unknown session"),
                    )),
                }
            }
            (FarState::Proving { id, client }, Record::Proof { offset, proof }) => {
                let (Some(secret), Some(received)) = (sessions.secret(&id), sessions.received(&id)) else {
                    let error = HandshakeError::Unexpected("a resume of a session that ended");
                    return Ok(refuse(RefuseCode::UNKNOWN_SESSION, "no such session here", error));
                };
                let claim = Claim {
                    prover: Prover::Client,
                    id: &id,
                    far_nonce: &self.ours.nonce,
                    client_nonce: &client.nonce,
                    offset,
                };
                if !verify(secret, &claim, &proof) {
                    return Ok(refuse(RefuseCode::BAD_PROOF, "wrong proof", HandshakeError::BadProof));
                }
                let ours = Claim { prover: Prover::Far, offset: received, ..claim };
                let accept = Record::Accept(Acceptance::Resume { offset: received, proof: prove(secret, &ours) });
                let session = Established {
                    id,
                    secret: Secret::from_bytes(*secret.bytes()),
                    received,
                    peer_received: offset,
                    version: VERSION.min(client.version),
                    peer_role: client.role,
                    features: common(&self.ours.features, &client.features),
                    resumed: true,
                };
                Ok(Step::Established(Some(accept), Box::new(session)))
            }
            (_, Record::Close { reason }) => Err(HandshakeError::Closed(reason)),
            (FarState::Done, _) => Err(HandshakeError::Unexpected("a record after the handshake")),
            (_, other) => {
                let error = HandshakeError::Unexpected(other.name());
                Ok(refuse(RefuseCode::PROTOCOL, "a record that the handshake did not expect", error))
            }
        }
    }

    fn new_session(
        &mut self,
        client: Hello,
        public: [u8; 32],
        sessions: &mut Sessions,
        entropy: &mut dyn Entropy,
    ) -> Result<Step, HandshakeError> {
        let key = KeyPair::fresh(entropy)?;
        let Some(shared) = key.shared(&public) else {
            return Ok(refuse(RefuseCode::PROTOCOL, "a public key of low order", HandshakeError::WeakKey));
        };
        // 128 random bits do not repeat; a draw that names a kept session
        // anyway is drawn again, and a source that gives only those is broken.
        let mut id = SessionId([0; ID_LEN]);
        for _ in 0..8 {
            entropy.fill(&mut id.0)?;
            if !sessions.contains(&id) {
                break;
            }
        }
        if sessions.contains(&id) {
            return Err(HandshakeError::NoRandom);
        }
        let exchange = Exchange {
            shared: &shared,
            far_nonce: &self.ours.nonce,
            client_nonce: &client.nonce,
            id: &id,
            client_public: &public,
            far_public: &key.public,
        };
        let secret = derive(&exchange);
        sessions.insert(id, Secret::from_bytes(*secret.bytes()));
        let session = Established {
            id,
            secret,
            received: 0,
            peer_received: 0,
            version: VERSION.min(client.version),
            peer_role: client.role,
            features: common(&self.ours.features, &client.features),
            resumed: false,
        };
        let accept = Record::Accept(Acceptance::New { id, public: key.public });
        Ok(Step::Established(Some(accept), Box::new(session)))
    }
}
