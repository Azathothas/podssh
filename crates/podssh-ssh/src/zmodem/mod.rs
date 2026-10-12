//! ZMODEM inside a terminal session (T-148): lrzsz's `sz` and `rz` on the
//! server, and podssh as the other end, for a server that gives a shell and
//! nothing else (no SFTP, and exec refused). The protocol is Chuck
//! Forsberg's "The ZMODEM Inter Application File Transfer Protocol" (Omen
//! Technology, revision of 1988-10-14), "the spec" in these files; a number
//! such as 8.1 is its section. podssh has the part that one file each way
//! needs: hex headers and binary headers with CRC-16 and CRC-32, the ZDLE
//! escapes, ZFILE, ZDATA, ZEOF and ZFIN, and the abort by CAN.
//!
//! Each part is sans-IO: bytes and the time go in, and bytes and acts come
//! out. [`Zmodem`] joins them to a session: it watches the server's output
//! only in a session with a pty and a local terminal, asks on the terminal
//! before a file comes or goes, and writes a file that comes as T-134
//! writes a copy (a temporary name beside it, the checks, then the rename).

use std::time::Duration;

pub mod ask;
pub mod detect;
pub mod files;
mod read;
pub mod receive;
pub mod send;
mod session;
pub mod wire;

pub use session::{Taken, Zmodem};

/// The limit of each wait for a frame: the spec's response time (8.1:
/// "default 10 second").
pub const WAIT: Duration = Duration::from_secs(10);

/// The waits for one answer, the first one included. The spec sends a
/// header again at each response time, "40 seconds total" (8.1); then the
/// transfer ends, and the session goes on.
pub const TRIES: u32 = 4;

/// The data of one subpacket that podssh sends: 1024 bytes, which each
/// receiver takes.
pub const SUBPACKET: usize = 1024;

/// The cancel sequence (8.4): "eight CAN characters and ten backspace
/// characters". Five CAN end a session (7.2); the other three are
/// "insurance", and the backspaces erase them from a command line.
pub const CANCEL: &[u8] = &[0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];

/// What a side of the protocol asks of its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    /// Bytes for the server.
    Send(Vec<u8>),
    /// The server offers a file; [`receive::Receiver::decide`] answers.
    Offer(receive::Offer),
    /// The next bytes of the file that comes.
    Write(Vec<u8>),
    /// The whole file came, or went: this many bytes.
    Close(u64),
    /// The server skipped the file that podssh offered.
    Skipped,
    /// The bytes of the file so far.
    Progress(u64),
    /// The transfer is over. `rest` is the server's output after its end,
    /// for the terminal.
    End { ended: Ended, rest: Vec<u8> },
}

/// How a transfer ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    Done,
    /// Cancelled, refused or out of time, and why.
    Stopped(String),
}

/// The acts of a transfer that stops here: the cancel sequence, then the end.
pub(crate) fn stop(why: String) -> Vec<Act> {
    vec![Act::Send(CANCEL.to_vec()), Act::End { ended: Ended::Stopped(why), rest: Vec::new() }]
}
