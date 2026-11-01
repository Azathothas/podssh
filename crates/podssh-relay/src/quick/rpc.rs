//! The messages of Cap'n Proto's RPC that a client of one capability needs
//! (T-300), as `rpc.capnp` of capnproto2 v2.18.0, the version cloudflared
//! pins, lays them out: a `Bootstrap`, a `Call` on the capability that the
//! bootstrap's answer holds (its promised answer: no wait for the answer
//! first), a `Finish` once an answer is read; and, from the other end,
//! `Return` (results or an exception) and `Abort`. Each message is one frame
//! of the stream, as cloudflared's `rpc.StreamTransport` writes it.
//!
//! And for a server of one capability, on an RPC stream of the edge over
//! QUIC (T-411): the other end's `Bootstrap`, `Call` and `Finish` read, and
//! a `Return` that holds the capability, or a method's results.

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
const CAP_DESCRIPTOR: (u16, u16) = (1, 1);
/// The kind of an exception for a method that is not there.
const UNIMPLEMENTED: u16 = 3;
/// The member of `CapDescriptor`'s union for a capability that the sender
/// of the message hosts: its id of export.
const SENDER_HOSTED: u16 = 1;

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

/// The answer to the other end's bootstrap, `answer`: results whose content
/// is the capability that this end exports as `export`, the one entry of
/// their table, as capnproto2's server writes it (T-411).
pub fn capability(answer: u32, export: u32) -> Vec<u8> {
    let (mut b, ret) = message(IS_RETURN, RETURN);
    b.set_u32(ret, 0, answer);
    let payload = b.init_struct(ret, 0, PAYLOAD.0, PAYLOAD.1);
    b.set_capability(payload, 0, 0);
    let table = b.init_struct_list(payload, 1, 1, CAP_DESCRIPTOR.0, CAP_DESCRIPTOR.1);
    b.set_u16(table[0], 0, SENDER_HOSTED);
    b.set_u32(table[0], 4, export);
    b.frame()
}

/// The answer to the other end's call, `answer`: results whose content is
/// a struct of `size`, which `fill` writes (T-411).
pub fn results(answer: u32, size: (u16, u16), fill: impl FnOnce(&mut Builder, At)) -> Vec<u8> {
    let (mut b, ret) = message(IS_RETURN, RETURN);
    b.set_u32(ret, 0, answer);
    let payload = b.init_struct(ret, 0, PAYLOAD.0, PAYLOAD.1);
    let content = b.init_struct(payload, 0, size.0, size.1);
    fill(&mut b, content);
    b.frame()
}

/// A message of the other end.
pub enum Incoming<'a> {
    /// The answer to `answer`, one of this end's questions.
    Return { answer: u32, outcome: Outcome<'a> },
    /// The other end ends the connection, with its reason.
    Abort(String),
    /// The other end asks this end for its bootstrap capability: its
    /// question.
    Bootstrap(u32),
    /// The other end calls a capability of this end's.
    Call(Call<'a>),
    /// The other end is done with the answer to its question.
    Finish(u32),
    /// A kind of message that neither end here answers, a release among
    /// them: its member of the union.
    Other(u16),
}

/// A call of the other end's.
pub struct Call<'a> {
    pub question: u32,
    pub target: Target,
    pub interface: u64,
    pub method: u16,
    /// The parameters: the content of the call's payload, if it is set.
    pub params: Option<Struct<'a>>,
}

/// Which capability of this end's a call is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The one that this end exported with this id.
    Imported(u32),
    /// The one that the answer to this question of the other end's holds,
    /// whole: a bootstrap's, before its answer came or was finished.
    Promised(u32),
    /// A part of an answer, or a kind of target that this end does not read.
    Other,
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

/// The reason of an `Exception`, its first pointer: the other end's text,
/// which reaches a line, so one line with no control character.
fn reason(exception: Option<Struct<'_>>) -> String {
    podssh_ws::text::one_line(exception.and_then(|e| e.get_text(0).ok().flatten()).unwrap_or("no reason given"))
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
        IS_BOOTSTRAP => Ok(Incoming::Bootstrap(body(root)?.u32(0))),
        IS_CALL => Ok(Incoming::Call(read_call(body(root)?))),
        IS_FINISH => Ok(Incoming::Finish(body(root)?.u32(0))),
        other => Ok(Incoming::Other(other)),
    }
}

/// The body of a message: its member of the union, a struct.
fn body(root: Struct<'_>) -> Result<Struct<'_>, Malformed> {
    root.get_struct(0)?.ok_or(Malformed("a message with no body"))
}

/// A `Call`: its question (data bytes 0 to 3), method (4 and 5) and
/// interface (8 to 15); its target (pointer 0), whose union says at bytes 4
/// and 5 which of an import (bytes 0 to 3) or a promised answer (pointer 0)
/// it is; its payload (pointer 1). A target or parameters that do not read
/// are none: the call is still answered, with an exception if it is no push.
fn read_call(call: Struct<'_>) -> Call<'_> {
    let target = match call.get_struct(0).ok().flatten() {
        Some(target) if target.u16(4) == 0 => Target::Imported(target.u32(0)),
        Some(target) if target.u16(4) == 1 => match target.get_struct(0).ok().flatten() {
            // A transform reaches into the answer: only its whole is a
            // capability of this end's. capnproto2 writes an empty list.
            Some(promised) if promised.get_struct_list(0).is_ok_and(|ops| ops.is_empty()) => {
                Target::Promised(promised.u32(0))
            }
            _ => Target::Other,
        },
        _ => Target::Other,
    };
    let params = call.get_struct(1).ok().flatten().and_then(|payload| payload.get_struct(0).ok().flatten());
    Call { question: call.u32(0), target, interface: call.u64(8), method: call.u16(4), params }
}

/// The content of a payload, read as a struct: a method's results.
pub fn content<'a>(payload: Struct<'a>) -> Result<Struct<'a>, Malformed> {
    payload.get_struct(0)?.ok_or(Malformed("a payload with no content"))
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
