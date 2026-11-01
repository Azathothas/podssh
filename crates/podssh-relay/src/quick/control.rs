//! The control stream of a quick tunnel's connection (T-300), sans-IO: the
//! registration and its end, as cloudflared's `controlStream` runs them
//! (`connection/control.go`). The edge opens the stream; the connector asks
//! for the edge's bootstrap capability and calls `registerConnection` on its
//! promised answer at once, finishes each answer once it is read, and calls
//! `unregisterConnection` on the same capability when it stops. The stream's
//! bytes are frames of Cap'n Proto both ways; a frame may come in pieces.

use super::capnp::{self, Malformed, Message, CONTROL_BUDGET, MAX_FRAME};
use super::register::{
    read_results, Registered, Registration, REGISTER_CONNECTION, REGISTER_PARAMS, REGISTRATION_SERVER,
    UNREGISTER_CONNECTION, UNREGISTER_PARAMS,
};
use super::rpc::{self, Incoming, Outcome};

/// This end's questions: the bootstrap, kept until the end, as each call
/// goes to its promised answer; the registration; the unregistration.
const BOOTSTRAP: u32 = 0;
const REGISTER: u32 = 1;
const UNREGISTER: u32 = 2;

/// What the edge's bytes brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The answer of the registration.
    Registered(Registered),
    /// The edge took the end of the connection.
    Unregistered,
}

/// Why the control stream cannot go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The edge's bytes do not read as the RPC.
    Malformed(Malformed),
    /// The edge answered a question with an exception: which, and why.
    Exception { question: u32, why: String },
    /// The edge ended the RPC, with its reason.
    Aborted(String),
    /// The edge ended the control stream: the connection is no longer
    /// registered.
    Ended,
}

impl From<Malformed> for Failure {
    fn from(e: Malformed) -> Self {
        Failure::Malformed(e)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Malformed(e) => write!(f, "{e}"),
            Failure::Exception { question: REGISTER, why } => write!(f, "the edge refused the registration: {why}"),
            Failure::Exception { why, .. } => write!(f, "the edge answered with an error: {why}"),
            Failure::Aborted(why) => write!(f, "the edge ended the control stream: {why}"),
            Failure::Ended => write!(f, "the edge closed the control stream"),
        }
    }
}

/// The control stream of one connection.
pub struct Control {
    inbox: Vec<u8>,
}

impl Control {
    /// The stream, and its first bytes: the bootstrap, and the call of
    /// `registerConnection` with `registration`.
    pub fn register(registration: &Registration<'_>) -> (Control, Vec<u8>) {
        let mut out = rpc::bootstrap(BOOTSTRAP);
        out.extend(rpc::call(
            REGISTER,
            BOOTSTRAP,
            REGISTRATION_SERVER,
            REGISTER_CONNECTION,
            REGISTER_PARAMS,
            |b, at| registration.write(b, at),
        ));
        (Control { inbox: Vec::new() }, out)
    }

    /// The bytes of the end: the call of `unregisterConnection`.
    pub fn unregister(&self) -> Vec<u8> {
        rpc::call(UNREGISTER, BOOTSTRAP, REGISTRATION_SERVER, UNREGISTER_CONNECTION, UNREGISTER_PARAMS, |_, _| {})
    }

    /// Bytes from the edge: the events of each whole frame among them, and
    /// the bytes to send back.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(Vec<Event>, Vec<u8>), Failure> {
        if self.inbox.len() + bytes.len() > MAX_FRAME + 64 {
            return Err(Failure::Malformed(Malformed("a frame larger than the limit")));
        }
        self.inbox.extend_from_slice(bytes);
        let (mut events, mut out) = (Vec::new(), Vec::new());
        while let Some(len) = capnp::frame_len(&self.inbox)? {
            if self.inbox.len() < len {
                break;
            }
            let frame: Vec<u8> = self.inbox.drain(..len).collect();
            // The edge's messages here are some hundreds of bytes: a smaller
            // budget than capnp's ends a hostile one sooner (T-403).
            let message = Message::read_within(&frame, CONTROL_BUDGET)?;
            match rpc::read(&message)? {
                Incoming::Return { answer, outcome } => {
                    if let Some(event) = answered(answer, outcome, &mut out)? {
                        events.push(event);
                    }
                }
                Incoming::Abort(why) => return Err(Failure::Aborted(why)),
                Incoming::Asked(question) => {
                    out.extend(rpc::unimplemented(question, "podssh exports no capability"));
                }
                // A release, a resolve or another kind that a client of one
                // capability neither needs nor answers.
                Incoming::Other(_) => {}
            }
        }
        Ok((events, out))
    }
}

/// The answer to one of this end's questions.
fn answered(answer: u32, outcome: Outcome<'_>, out: &mut Vec<u8>) -> Result<Option<Event>, Failure> {
    let results = match outcome {
        Outcome::Results(payload) => payload,
        Outcome::Exception(why) => return Err(Failure::Exception { question: answer, why }),
        Outcome::Other(_) => {
            return Err(Failure::Exception { question: answer, why: "the question was canceled".into() })
        }
    };
    match answer {
        // The capability, which the calls reached through its promise.
        BOOTSTRAP => Ok(None),
        REGISTER => {
            out.extend(rpc::finish(REGISTER));
            Ok(Some(Event::Registered(read_results(rpc::content(results)?)?)))
        }
        UNREGISTER => {
            out.extend(rpc::finish(UNREGISTER));
            out.extend(rpc::finish(BOOTSTRAP));
            Ok(Some(Event::Unregistered))
        }
        // An answer to no question of this end's.
        _ => Ok(None),
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
