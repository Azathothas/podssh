//! The messages of Cap'n Proto's RPC that a client of one capability needs
//! (T-300), as `rpc.capnp` of capnproto2 v2.18.0, the version cloudflared
//! pins, lays them out: a `Bootstrap`, a `Call` on the capability that the
//! bootstrap's answer holds (its promised answer: no wait for the answer
//! first), a `Finish` once an answer is read; and, from the other end,
//! `Return` (results or an exception) and `Abort`. Each message is one frame
//! of the stream, as cloudflared's `rpc.StreamTransport` writes it.

use super::capnp::{At, Builder, Malformed, Message, Struct};

/// The sizes of the structs: data words and pointers.
const MESSAGE: (u16, u16) = (1, 1);
const BOOTSTRAP: (u16, u16) = (1, 1);
const CALL: (u16, u16) = (3, 3);
const TARGET: (u16, u16) = (1, 1);
const PROMISED: (u16, u16) = (1, 1);
const PAYLOAD: (u16, u16) = (0, 2);
const FINISH: (u16, u16) = (1, 0);
const RETURN: (u16, u16) = (2, 1);
const EXCEPTION: (u16, u16) = (1, 1);
/// The kind of an exception for a method that is not there.
const UNIMPLEMENTED: u16 = 3;

/// The members of the union of `Message`.
const IS_ABORT: u16 = 1;
const IS_CALL: u16 = 2;
const IS_RETURN: u16 = 3;
const IS_FINISH: u16 = 4;
const IS_BOOTSTRAP: u16 = 8;

fn message(kind: u16, size: (u16, u16)) -> (Builder, At) {
    let (mut b, root) = Builder::new(MESSAGE.0, MESSAGE.1);
    b.set_u16(root, 0, kind);
    let body = b.init_struct(root, 0, size.0, size.1);
    (b, body)
}

/// Ask for the other end's bootstrap capability, as `question`.
pub fn bootstrap(question: u32) -> Vec<u8> {
    let (mut b, boot) = message(IS_BOOTSTRAP, BOOTSTRAP);
    b.set_u32(boot, 0, question);
    b.frame()
}

/// Call `method` of `interface`, as `question`, on the capability that the
/// answer of the question `bootstrap` holds; `fill` writes the parameters,
/// a struct of `size`.
pub fn call(
    question: u32,
    bootstrap: u32,
    interface: u64,
    method: u16,
    size: (u16, u16),
    fill: impl FnOnce(&mut Builder, At),
) -> Vec<u8> {
    let (mut b, call) = message(IS_CALL, CALL);
    b.set_u32(call, 0, question);
    let target = b.init_struct(call, 0, TARGET.0, TARGET.1);
    // The target is the promised answer of the bootstrap, with no transform.
    b.set_u16(target, 4, 1);
    let promised = b.init_struct(target, 0, PROMISED.0, PROMISED.1);
    b.set_u32(promised, 0, bootstrap);
    b.set_u64(call, 8, interface);
    b.set_u16(call, 4, method);
    let payload = b.init_struct(call, 1, PAYLOAD.0, PAYLOAD.1);
    let params = b.init_struct(payload, 0, size.0, size.1);
    fill(&mut b, params);
    b.frame()
}

/// Done with the answer of `question`; capabilities in it are released,
/// the default of `releaseResultCaps`.
pub fn finish(question: u32) -> Vec<u8> {
    let (mut b, finish) = message(IS_FINISH, FINISH);
    b.set_u32(finish, 0, question);
    b.frame()
}

/// The answer to the other end's `question`: an exception of the kind
/// unimplemented, with `reason`, as a client of one capability exports none.
pub fn unimplemented(question: u32, reason: &str) -> Vec<u8> {
    let (mut b, ret) = message(IS_RETURN, RETURN);
    b.set_u32(ret, 0, question);
    b.set_u16(ret, 6, 1);
    let exception = b.init_struct(ret, 0, EXCEPTION.0, EXCEPTION.1);
    b.set_text(exception, 0, reason);
    b.set_u16(exception, 4, UNIMPLEMENTED);
    b.frame()
}

/// A message of the other end.
pub enum Incoming<'a> {
    /// The answer to `answer`, one of this end's questions.
    Return { answer: u32, outcome: Outcome<'a> },
    /// The other end ends the connection, with its reason.
    Abort(String),
    /// The other end asks this end for its bootstrap capability, or calls
    /// one: its question.
    Asked(u32),
    /// A kind of message that a client of one capability neither needs nor
    /// answers: its member of the union.
    Other(u16),
}

/// How a question was answered.
pub enum Outcome<'a> {
    /// Results: the payload, whose content the caller reads as the method's
    /// results, or as a capability for a bootstrap.
    Results(Struct<'a>),
    /// An exception, with its reason.
    Exception(String),
    /// The question was canceled, or its answer went elsewhere.
    Other(u16),
}

/// The reason of an `Exception`, its first pointer.
fn reason(exception: Option<Struct<'_>>) -> String {
    exception.and_then(|e| e.get_text(0).ok().flatten()).unwrap_or("no reason given").to_string()
}

/// Read the message of one frame.
pub fn read<'a>(message: &'a Message<'a>) -> Result<Incoming<'a>, Malformed> {
    let root = message.root()?;
    match root.u16(0) {
        IS_RETURN => {
            let ret = root.get_struct(0)?.ok_or(Malformed("a return with no body"))?;
            let answer = ret.u32(0);
            let outcome = match ret.u16(6) {
                0 => Outcome::Results(ret.get_struct(0)?.ok_or(Malformed("results with no payload"))?),
                1 => Outcome::Exception(reason(ret.get_struct(0)?)),
                other => Outcome::Other(other),
            };
            Ok(Incoming::Return { answer, outcome })
        }
        IS_ABORT => Ok(Incoming::Abort(reason(root.get_struct(0)?))),
        IS_BOOTSTRAP | IS_CALL => {
            let asked = root.get_struct(0)?.ok_or(Malformed("a question with no body"))?;
            Ok(Incoming::Asked(asked.u32(0)))
        }
        other => Ok(Incoming::Other(other)),
    }
}

/// The content of a payload, read as a struct: a method's results.
pub fn content<'a>(payload: Struct<'a>) -> Result<Struct<'a>, Malformed> {
    payload.get_struct(0)?.ok_or(Malformed("a payload with no content"))
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
