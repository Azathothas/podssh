//! The end-to-end channel in each end of `podssh` (T-088), with the keys of
//! T-087: a node's key and allowlist; this client's key; and the check of a
//! node's key against `--node-key`, an iroh ticket, or the pins. On by
//! default between two podssh ends; `--no-e2e`, given at both ends, carries
//! each session's bytes as they are.

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use podssh_relay::e2e::{self, ends, Refusal as NodeRefusal};
use podssh_relay::identity::{allow, file, pins, Identity, KeyName, PublicKey};
use podssh_relay::reverse::{Handler, Opening, SessionId};
use podssh_relay::session::OsEntropy;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

use crate::exitmap::Fault;
use crate::relay_settings::Refusal;

/// Each direction of the pipe of a node's session.
const PIPE: usize = 256 * 1024;

/// A byte stream of a session, with the channel or without it.
pub trait Bytes: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Bytes for T {}

/// The channel's part of an operator's session, run beside the layer: the
/// node's key, or why the channel failed.
pub type Session = Pin<Box<dyn Future<Output = Result<PublicKey, e2e::Error>> + Send>>;

/// How an operator checks the node's key, before it proves its own.
#[derive(Debug, Clone)]
pub enum Expect {
    /// `--node-key`: this key, and the pins are neither read nor written.
    Named(KeyName),
    /// The key that an iroh ticket names: the node that the user dials.
    Ticket(PublicKey),
    /// The pins of this label: the first sight pins, a changed key refuses.
    Pinned(String),
}

/// An operator's channel: its key, and how it checks the node's.
pub struct Operator {
    pub identity: Arc<Identity>,
    pub expect: Expect,
}

/// The channel of a client, as its command line asks it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ask {
    /// This client's key file: `--client-key`, or `--iroh-key` by its
    /// earlier name.
    pub client_key: Option<String>,
    /// `--node-key`.
    pub node_key: Option<KeyName>,
    /// `--no-e2e`.
    pub off: bool,
}

impl Ask {
    /// The flags, checked: one name for the key file, a key or fingerprint
    /// for `--node-key`, and nothing of the channel's with `--no-e2e`.
    pub fn of(
        client_key: Option<&str>,
        iroh_key: Option<&str>,
        node_key: Option<&str>,
        off: bool,
    ) -> Result<Ask, String> {
        if client_key.is_some() && iroh_key.is_some() {
            return Err("--client-key and --iroh-key are one flag by two names: give one".into());
        }
        let node_key = match node_key {
            Some(text) => Some(KeyName::parse(text).ok_or_else(|| {
                format!(
                    "--node-key {text:?}: not a key (64 hex digits, or iroh's base32) nor a fingerprint (SHA256:...)"
                )
            })?),
            None => None,
        };
        if off && node_key.is_some() {
            return Err("--node-key checks the node's key in the end-to-end channel, which --no-e2e turns off".into());
        }
        Ok(Ask { client_key: client_key.or(iroh_key).map(str::to_string), node_key, off })
    }

    /// The operator's channel with this client's key `identity`, loaded by the
    /// caller, and the node's key as `--node-key` names it, else as
    /// `fallback` does. `None` with `--no-e2e`.
    pub fn with(&self, identity: Arc<Identity>, fallback: Expect) -> Option<Operator> {
        let expect = self.node_key.clone().map_or(fallback, Expect::Named);
        (!self.off).then_some(Operator { identity, expect })
    }

    /// The operator's channel: this client's key, loaded or made, and the
    /// node's key as `--node-key` names it, else as `fallback` does (the
    /// pins of a label, or a ticket's key). `None` with `--no-e2e`.
    pub fn operator(&self, fallback: Expect, say: &dyn Fn(String)) -> Result<Option<Operator>, String> {
        if self.off {
            return Ok(None);
        }
        let identity = client_identity(self.client_key.as_deref(), say)?;
        let expect = self.node_key.clone().map_or(fallback, Expect::Named);
        Ok(Some(Operator { identity, expect }))
    }
}

/// This client's key: the file named, else `client.key` in the cache (or
/// `iroh-client.key` of an earlier podssh). A new key is said with its
/// fingerprint, the line that a node's allowlist takes.
pub fn client_identity(named: Option<&str>, say: &dyn Fn(String)) -> Result<Arc<Identity>, String> {
    let place = named.map_or_else(file::client_place, |path| file::Place::File(path.into()));
    let key = file::load(&place, &mut OsEntropy).map_err(|why| format!("this client's key: {why}"))?;
    if key.made {
        let kept = key.path.as_deref().map(|p| format!(", in {}", p.display())).unwrap_or_default();
        say(format!(
            "a new key for this client{kept}: {}; a node with an allowlist lets it in once the list holds it",
            key.identity.public()
        ));
    }
    Ok(Arc::new(key.identity))
}

/// The check of a node's key by `expect`; `say` gets the line of a new pin.
pub fn check(
    expect: Expect,
    say: impl Fn(String) + Send + 'static,
) -> impl FnOnce(&PublicKey) -> Result<(), String> + Send + 'static {
    move |key: &PublicKey| match expect {
        Expect::Named(name) if name.matches(key) => Ok(()),
        Expect::Named(name) => Err(format!("the node has the key {key}, not {name}, which --node-key names")),
        Expect::Ticket(named) if named == *key => Ok(()),
        Expect::Ticket(named) => Err(format!("the node has the key {key}, not {named}, which its ticket names")),
        Expect::Pinned(label) => match pins::check(&label, key) {
            Ok(pins::Seen::Known) => Ok(()),
            Ok(pins::Seen::Pinned(path)) => {
                say(format!("the node's key {key} is pinned at its first sight, in {}", path.display()));
                Ok(())
            }
            Ok(pins::Seen::NotPinned(why)) => {
                say(format!("the node's key {key} could not be pinned: {why}"));
                Ok(())
            }
            Err(pins::PinError::Changed { pinned, path, line }) => Err(format!(
                "the node {label} has the key {key}, but line {line} of {} pins {pinned}. If the node's key \
                 changed on purpose, remove that line or add one for the new key; else something on the way \
                 may stand in the middle",
                path.display()
            )),
            Err(pins::PinError::Unreadable(why)) => Err(format!("the pins cannot be trusted: {why}")),
        },
    }
}

/// The stream that the layer, or the relay's leg, carries for `app`: with a
/// channel, the channel's end, and its session to run beside; with none,
/// `app` itself.
pub fn around<A: Bytes + 'static>(
    app: A,
    channel: Option<Operator>,
    say: impl Fn(String) + Send + 'static,
) -> (Box<dyn Bytes>, Option<Session>) {
    let Some(Operator { identity, expect }) = channel else { return (Box::new(app), None) };
    let (cipher, session) = ends::operator(app, identity, check(expect, say));
    (Box::new(cipher), Some(Box::pin(session)))
}

/// What a failed channel says, when it says more than the layer: its fault
/// and its line. A cut, or a failed stream, leaves the word to the layer and
/// the relay's close.
pub fn judged(e: &e2e::Error, me: Option<&Identity>) -> Option<(Fault, String)> {
    let mine = me.map(|identity| format!(" {}", identity.public())).unwrap_or_default();
    Some(match e {
        e2e::Error::NodeKey(why) => (Fault::Auth, format!("refused the node: {why}")),
        e2e::Error::Refused(NodeRefusal::NotAllowed) => (
            Fault::Auth,
            format!(
                "the node refused this client's key{mine}: it is not in the node's allowlist; the node's \
                 operator adds the key to the file of --allow"
            ),
        ),
        e2e::Error::Refused(NodeRefusal::NoTarget(why)) => {
            (Fault::SessionFault, format!("the node could not reach its target: {why}"))
        }
        e2e::Error::Refused(NodeRefusal::Other(why)) => (Fault::SessionFault, format!("the node refused: {why}")),
        e2e::Error::Timeout(_) => (Fault::RelayUnreachable, e.to_string()),
        e2e::Error::NotChannel(_) | e2e::Error::Handshake(_) | e2e::Error::Tampered | e2e::Error::Malformed(_) => {
            (Fault::SessionFault, e.to_string())
        }
        e2e::Error::Cut | e2e::Error::Io(_) => return None,
    })
}

/// Where a node's key is: the file named, `--ephemeral-key`, else
/// `node-NAME.key` in the cache.
pub fn node_place(label: &str, named: Option<&str>, ephemeral: bool) -> Result<file::Place, Refusal> {
    match (named, ephemeral) {
        (Some(_), true) => Err(Refusal::usage("--ephemeral-key keeps the key in no file, and --key names one")),
        (Some(path), false) => Ok(file::Place::File(path.into())),
        (None, true) => Ok(file::Place::Ephemeral),
        (None, false) => Ok(file::node_place(label)),
    }
}

/// The node's key at `place`, made when missing; a key that cannot be used
/// is a fault of this host's set-up.
pub fn load_node_key(place: &file::Place) -> Result<file::Key, Refusal> {
    file::load(place, &mut OsEntropy).map_err(|why| Refusal::config(format!("the node's key: {why}")))
}

/// A node's channel, with its start lines on `err`: its key, and who may
/// come in. Its later lines go to stderr.
pub fn node(label: &str, key: file::Key, allow: Option<PathBuf>, err: &mut dyn Write) -> ends::Node {
    let kept = match (&key.path, key.made) {
        (None, _) => "a key for this run only".to_string(),
        (Some(path), true) => format!("a new key, in {}", path.display()),
        (Some(path), false) => format!("in {}", path.display()),
    };
    let _ = writeln!(err, "podssh node: {label}: key {} ({kept})", key.identity.public());
    let _ = writeln!(err, "podssh node: {label}: {}", who_may(allow.as_deref()));
    node_end(label, key.identity, admit_of(allow))
}

/// A node's channel with this identity and admission, whose lines go to
/// stderr under `label`.
pub fn node_end(label: &str, identity: Identity, admit: Arc<ends::Admit>) -> ends::Node {
    let shown = label.to_string();
    let say = Arc::new(move |line: String| eprintln!("podssh node: {shown}: {line}"));
    ends::Node { identity: Arc::new(identity), admit, say }
}

/// Who may come in through the channel: the keys of the allowlist at
/// `allow`, read again for each session; with none, each operator, as the
/// relay's connect token decided who reaches the node.
pub fn admit_of(allow: Option<PathBuf>) -> Arc<ends::Admit> {
    match allow {
        Some(path) => Arc::new(move |key: &PublicKey| allow::admits(&path, key)),
        None => Arc::new(|_: &PublicKey| Ok(())),
    }
}

/// Who may come in, as the node starts.
pub fn who_may(allow: Option<&Path>) -> String {
    let Some(path) = allow else {
        return "each operator with the pair's connect token may come in, and its key is said".into();
    };
    match allow::Allowlist::read(path) {
        Ok(list) if list.bad_lines().is_empty() => {
            format!("{} operator keys may come in ({})", list.len(), path.display())
        }
        Ok(list) => format!(
            "{} operator keys may come in ({}); lines {:?} are not keys",
            list.len(),
            path.display(),
            list.bad_lines()
        ),
        Err(why) => format!("no operator may come in yet: {why}"),
    }
}

/// A node's session as a pipe, so that both roads of a node keep one kind of
/// session (T-164): with the channel, the pipe's far end answers its
/// handshake and reaches the target once the operator's key is let in; with
/// none, the target is reached first, and the pipe carries its bytes.
pub async fn piped<A, O, F>(channel: Option<ends::Node>, open: O) -> Result<DuplexStream, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: FnOnce() -> F + Send + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    let Some(node) = channel else {
        let mut target = open().await?;
        let (ours, mut theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut theirs, &mut target).await;
        });
        return Ok(ours);
    };
    let (ours, theirs) = tokio::io::duplex(PIPE);
    tokio::spawn(async move { ends::serve_node(theirs, &node, open).await });
    Ok(ours)
}

/// A node's handler whose every session is [`piped`].
pub struct Piped<H: Handler> {
    pub inner: Arc<H>,
    pub channel: Option<ends::Node>,
}

impl<H: Handler> Handler for Piped<H> {
    type Stream = DuplexStream;

    fn open(&self, id: SessionId) -> Opening<DuplexStream> {
        let (inner, channel) = (self.inner.clone(), self.channel.clone());
        Box::pin(async move { piped(channel, move || inner.open(id)).await })
    }

    fn queue_bytes(&self) -> usize {
        self.inner.queue_bytes()
    }
}
