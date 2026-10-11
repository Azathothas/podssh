//! OpenSSH's control protocol, `PROTOCOL.mux` version 4 (T-039): the
//! messages between a client and its master, as OpenSSH 10.3p1 writes them.
//! Read from the bytes of its own client and master (the tests hold them):
//! each `bool` of the document is a `uint32`, and the port of a stdio
//! forward is a `uint32`, not the string that the document says. Each
//! message is a packet: a `uint32` length, then its body.

/// The version of the protocol that both sides speak.
pub const VERSION: u32 = 4;
/// The largest packet taken: OpenSSH's own limit.
pub const MAX_PACKET: usize = 256 * 1024;
/// The escape character "none".
pub const NO_ESCAPE: u32 = 0xffff_ffff;
/// A port that makes its host a socket path.
pub const PORT_STREAMLOCAL: u32 = 0xffff_fffe;

/// The type of each message.
pub mod kind {
    pub const HELLO: u32 = 0x0000_0001;
    pub const NEW_SESSION: u32 = 0x1000_0002;
    pub const ALIVE_CHECK: u32 = 0x1000_0004;
    pub const TERMINATE: u32 = 0x1000_0005;
    pub const OPEN_FWD: u32 = 0x1000_0006;
    pub const CLOSE_FWD: u32 = 0x1000_0007;
    pub const NEW_STDIO_FWD: u32 = 0x1000_0008;
    pub const STOP_LISTENING: u32 = 0x1000_0009;
    pub const PROXY: u32 = 0x1000_000f;
    pub const OK: u32 = 0x8000_0001;
    pub const PERMISSION_DENIED: u32 = 0x8000_0002;
    pub const FAILURE: u32 = 0x8000_0003;
    pub const EXIT_MESSAGE: u32 = 0x8000_0004;
    pub const ALIVE: u32 = 0x8000_0005;
    pub const SESSION_OPENED: u32 = 0x8000_0006;
    pub const REMOTE_PORT: u32 = 0x8000_0007;
    pub const TTY_ALLOC_FAIL: u32 = 0x8000_0008;
}

/// The kind of a forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwdKind {
    Local,
    Remote,
    Dynamic,
}

impl FwdKind {
    fn code(self) -> u32 {
        match self {
            FwdKind::Local => 1,
            FwdKind::Remote => 2,
            FwdKind::Dynamic => 3,
        }
    }
}

/// A forward of `-O forward` and `-O cancel`: a dynamic one connects to
/// `socks`, port 0; a port of [`PORT_STREAMLOCAL`] makes its host a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fwd {
    pub kind: FwdKind,
    pub listen_host: String,
    pub listen_port: u32,
    pub connect_host: String,
    pub connect_port: u32,
}

/// A session that a client asks its master for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NewSession {
    pub rid: u32,
    pub tty: bool,
    pub x11: bool,
    pub agent: bool,
    pub subsystem: bool,
    /// The escape character, or [`NO_ESCAPE`].
    pub escape: u32,
    pub term: String,
    pub command: Vec<u8>,
    /// `NAME=value`, each.
    pub env: Vec<String>,
}

/// One message, either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello {
        version: u32,
        extensions: Vec<(String, String)>,
    },
    NewSession(NewSession),
    AliveCheck {
        rid: u32,
    },
    Terminate {
        rid: u32,
    },
    OpenFwd {
        rid: u32,
        fwd: Fwd,
    },
    CloseFwd {
        rid: u32,
        fwd: Fwd,
    },
    NewStdioFwd {
        rid: u32,
        host: String,
        port: u32,
    },
    StopListening {
        rid: u32,
    },
    Proxy {
        rid: u32,
    },
    Ok {
        rid: u32,
    },
    PermissionDenied {
        rid: u32,
        reason: String,
    },
    Failure {
        rid: u32,
        reason: String,
    },
    ExitMessage {
        sid: u32,
        code: u32,
    },
    Alive {
        rid: u32,
        pid: u32,
    },
    SessionOpened {
        rid: u32,
        sid: u32,
    },
    RemotePort {
        rid: u32,
        port: u32,
    },
    TtyAllocFail {
        sid: u32,
    },
    /// A type that podssh does not know, and the request id that follows
    /// it, which a failure answers.
    Unknown {
        kind: u32,
        rid: Option<u32>,
    },
}

struct Writer(Vec<u8>);

impl Writer {
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        self.0.extend_from_slice(v);
        self
    }
    fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }
    fn fwd(&mut self, rid: u32, f: &Fwd) -> &mut Self {
        self.u32(rid).u32(f.kind.code()).str(&f.listen_host).u32(f.listen_port).str(&f.connect_host).u32(f.connect_port)
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u32(&mut self) -> Result<u32, String> {
        let (head, rest) = self.0.split_first_chunk::<4>().ok_or("a message that ends in a number")?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*head))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = usize::try_from(self.u32()?).map_err(|_| "a string too long")?;
        if len > self.0.len() {
            return Err("a message that ends in a string".into());
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head.to_vec())
    }
    fn str(&mut self) -> Result<String, String> {
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }
    fn bool(&mut self) -> Result<bool, String> {
        Ok(self.u32()? != 0)
    }
    fn fwd(&mut self) -> Result<Fwd, String> {
        let kind = match self.u32()? {
            1 => FwdKind::Local,
            2 => FwdKind::Remote,
            3 => FwdKind::Dynamic,
            other => return Err(format!("a forward of type {other}")),
        };
        Ok(Fwd {
            kind,
            listen_host: self.str()?,
            listen_port: self.u32()?,
            connect_host: self.str()?,
            connect_port: self.u32()?,
        })
    }
}

impl Message {
    /// The body: the type and the fields, with no length.
    pub fn body(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        match self {
            Message::Hello { version, extensions } => {
                w.u32(kind::HELLO).u32(*version);
                for (name, value) in extensions {
                    w.str(name).str(value);
                }
            }
            Message::NewSession(s) => {
                w.u32(kind::NEW_SESSION).u32(s.rid).str("");
                w.u32(s.tty.into()).u32(s.x11.into()).u32(s.agent.into()).u32(s.subsystem.into());
                w.u32(s.escape).str(&s.term).bytes(&s.command);
                for entry in &s.env {
                    w.str(entry);
                }
            }
            Message::AliveCheck { rid } => _ = w.u32(kind::ALIVE_CHECK).u32(*rid),
            Message::Terminate { rid } => _ = w.u32(kind::TERMINATE).u32(*rid),
            Message::OpenFwd { rid, fwd } => _ = w.u32(kind::OPEN_FWD).fwd(*rid, fwd),
            Message::CloseFwd { rid, fwd } => _ = w.u32(kind::CLOSE_FWD).fwd(*rid, fwd),
            Message::NewStdioFwd { rid, host, port } => {
                _ = w.u32(kind::NEW_STDIO_FWD).u32(*rid).str("").str(host).u32(*port)
            }
            Message::StopListening { rid } => _ = w.u32(kind::STOP_LISTENING).u32(*rid),
            Message::Proxy { rid } => _ = w.u32(kind::PROXY).u32(*rid),
            Message::Ok { rid } => _ = w.u32(kind::OK).u32(*rid),
            Message::PermissionDenied { rid, reason } => _ = w.u32(kind::PERMISSION_DENIED).u32(*rid).str(reason),
            Message::Failure { rid, reason } => _ = w.u32(kind::FAILURE).u32(*rid).str(reason),
            Message::ExitMessage { sid, code } => _ = w.u32(kind::EXIT_MESSAGE).u32(*sid).u32(*code),
            Message::Alive { rid, pid } => _ = w.u32(kind::ALIVE).u32(*rid).u32(*pid),
            Message::SessionOpened { rid, sid } => _ = w.u32(kind::SESSION_OPENED).u32(*rid).u32(*sid),
            Message::RemotePort { rid, port } => _ = w.u32(kind::REMOTE_PORT).u32(*rid).u32(*port),
            Message::TtyAllocFail { sid } => _ = w.u32(kind::TTY_ALLOC_FAIL).u32(*sid),
            Message::Unknown { kind, rid } => {
                w.u32(*kind);
                if let Some(rid) = rid {
                    w.u32(*rid);
                }
            }
        }
        w.0
    }

    /// The packet: the body's length, then the body.
    pub fn packet(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(body.len() + 4);
        out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// A body read back.
    pub fn parse(body: &[u8]) -> Result<Message, String> {
        let mut r = Reader(body);
        let message = match r.u32()? {
            kind::HELLO => {
                let version = r.u32()?;
                let mut extensions = Vec::new();
                while !r.0.is_empty() {
                    extensions.push((r.str()?, r.str()?));
                }
                Message::Hello { version, extensions }
            }
            kind::NEW_SESSION => {
                let rid = r.u32()?;
                let _reserved = r.bytes()?;
                let mut s = NewSession {
                    rid,
                    tty: r.bool()?,
                    x11: r.bool()?,
                    agent: r.bool()?,
                    subsystem: r.bool()?,
                    escape: r.u32()?,
                    term: r.str()?,
                    command: r.bytes()?,
                    env: Vec::new(),
                };
                while !r.0.is_empty() {
                    s.env.push(r.str()?);
                }
                Message::NewSession(s)
            }
            kind::ALIVE_CHECK => Message::AliveCheck { rid: r.u32()? },
            kind::TERMINATE => Message::Terminate { rid: r.u32()? },
            kind::OPEN_FWD => Message::OpenFwd { rid: r.u32()?, fwd: r.fwd()? },
            kind::CLOSE_FWD => Message::CloseFwd { rid: r.u32()?, fwd: r.fwd()? },
            kind::NEW_STDIO_FWD => {
                let rid = r.u32()?;
                let _reserved = r.bytes()?;
                Message::NewStdioFwd { rid, host: r.str()?, port: r.u32()? }
            }
            kind::STOP_LISTENING => Message::StopListening { rid: r.u32()? },
            kind::PROXY => Message::Proxy { rid: r.u32()? },
            kind::OK => Message::Ok { rid: r.u32()? },
            kind::PERMISSION_DENIED => Message::PermissionDenied { rid: r.u32()?, reason: r.str()? },
            kind::FAILURE => Message::Failure { rid: r.u32()?, reason: r.str()? },
            kind::EXIT_MESSAGE => Message::ExitMessage { sid: r.u32()?, code: r.u32()? },
            kind::ALIVE => Message::Alive { rid: r.u32()?, pid: r.u32()? },
            kind::SESSION_OPENED => Message::SessionOpened { rid: r.u32()?, sid: r.u32()? },
            kind::REMOTE_PORT => Message::RemotePort { rid: r.u32()?, port: r.u32()? },
            kind::TTY_ALLOC_FAIL => Message::TtyAllocFail { sid: r.u32()? },
            other => Message::Unknown { kind: other, rid: r.u32().ok() },
        };
        Ok(message)
    }
}

#[cfg(test)]
#[path = "proto_tests.rs"]
mod tests;
