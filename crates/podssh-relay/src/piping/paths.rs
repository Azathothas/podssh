//! The paths of the road, from the pair's secret. A Piping Server joins a
//! sender and a receiver by their path alone, so a path is the road's only
//! meeting point: each comes from a key that the pair's two ends alone hold,
//! the HMAC of the connect token over the pair's name, and a path names
//! neither. The node waits at its door; a client's hello there names a
//! random link id, and the two ways of that link have paths of their own,
//! so that two clients, or a link and the next, never meet on one path.
//! Each way begins with a mark of its link and its way, which the receiver
//! checks before the layer reads a byte: a stranger's bytes, or an end that
//! took the other way's path, end the link there.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::session::{Entropy, NoRandom};

const KEY_LABEL: &[u8] = b"podssh piping v1 key";
const DOOR_LABEL: &[u8] = b"podssh piping v1 door";
const UP_LABEL: &[u8] = b"podssh piping v1 up";
const DOWN_LABEL: &[u8] = b"podssh piping v1 down";
const UP_MARK_LABEL: &[u8] = b"podssh piping v1 mark up";
const DOWN_MARK_LABEL: &[u8] = b"podssh piping v1 mark down";
const HELLO_LABEL: &[u8] = b"podssh piping v1 hello";
/// The first word of a hello.
pub const HELLO_WORD: &str = "podssh-piping";
/// The version of the hello, the paths and the marks.
pub const VERSION: &str = "1";
/// A path's word: 128 bits of a MAC, as hex.
const PATH_BYTES: usize = 16;
/// The mark that begins each way.
pub const MARK_BYTES: usize = 16;
/// The tag of a hello.
const TAG_BYTES: usize = 16;
/// The longest hello that a node reads.
pub const HELLO_MAX: usize = 256;

/// A way of a link: up from the client to the node, or down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    Up,
    Down,
}

/// How a link carries its bytes: one streamed request each way, or a
/// numbered request for each piece ([`super::numbered`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Streamed,
    Numbered,
}

impl Mode {
    fn word(self) -> &'static str {
        match self {
            Mode::Streamed => "stream",
            Mode::Numbered => "numbered",
        }
    }

    fn of_word(word: &str) -> Option<Mode> {
        [Mode::Streamed, Mode::Numbered].into_iter().find(|mode| mode.word() == word)
    }
}

/// A link's id, which a client draws for each link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinkId(pub [u8; 16]);

impl LinkId {
    pub fn random(entropy: &mut dyn Entropy) -> Result<LinkId, NoRandom> {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes)?;
        Ok(LinkId(bytes))
    }

    /// Its first 8 hex digits, for a line.
    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

impl fmt::Debug for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkId({})", self.short())
    }
}

/// The road's key for one pair. Never shown.
pub struct Secret(Zeroizing<[u8; 32]>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// The key of the pair `name`, whose two ends hold `connect_token`: the
    /// node has the whole pair, an operator its part. The token keys the MAC,
    /// so that nothing derived from it shows it.
    pub fn of_pair(name: &str, connect_token: &str) -> Secret {
        Secret(Zeroizing::new(mac(connect_token.as_bytes(), KEY_LABEL, &[name.as_bytes()])))
    }

    /// A key of these bytes, for a test.
    pub fn from_bytes(bytes: [u8; 32]) -> Secret {
        Secret(Zeroizing::new(bytes))
    }

    fn mac(&self, label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        mac(&self.0[..], label, parts)
    }

    /// The word of the node's door.
    pub fn door(&self) -> String {
        hex(&self.mac(DOOR_LABEL, &[])[..PATH_BYTES])
    }

    /// The word of `way` of `link`.
    pub fn path(&self, way: Way, link: &LinkId) -> String {
        let label = match way {
            Way::Up => UP_LABEL,
            Way::Down => DOWN_LABEL,
        };
        hex(&self.mac(label, &[&link.0])[..PATH_BYTES])
    }

    /// The mark that begins `way` of `link`.
    pub fn mark(&self, way: Way, link: &LinkId) -> [u8; MARK_BYTES] {
        let label = match way {
            Way::Up => UP_MARK_LABEL,
            Way::Down => DOWN_MARK_LABEL,
        };
        let mut mark = [0u8; MARK_BYTES];
        mark.copy_from_slice(&self.mac(label, &[&link.0])[..MARK_BYTES]);
        mark
    }

    fn tag(&self, mode: Mode, link: &LinkId) -> [u8; 32] {
        self.mac(HELLO_LABEL, &[mode.word().as_bytes(), &link.0])
    }

    /// A client's hello at the door: a line of the version, the mode, the
    /// link's id and a tag of the key, so that the node opens no link for a
    /// hello that is not this pair's.
    pub fn hello(&self, mode: Mode, link: &LinkId) -> String {
        let tag = self.tag(mode, link);
        format!("{HELLO_WORD} {VERSION} {} {} {}\n", mode.word(), hex(&link.0), hex(&tag[..TAG_BYTES]))
    }

    /// The mode and the link of a hello that this key's [`Secret::hello`]
    /// wrote; else why not.
    pub fn read_hello(&self, text: &[u8]) -> Result<(Mode, LinkId), String> {
        if text.len() > HELLO_MAX {
            return Err(format!("a hello of {} bytes", text.len()));
        }
        let text = std::str::from_utf8(text).map_err(|_| "a hello that is not text".to_string())?;
        let words: Vec<&str> = text.split_ascii_whitespace().collect();
        let &[word, version, mode, link, tag] = words.as_slice() else {
            return Err(format!("a hello of {} words, not 5", words.len()));
        };
        if word != HELLO_WORD {
            return Err("not a hello of podssh".into());
        }
        if version != VERSION {
            return Err(format!("a hello of version {}, which this podssh does not read", one_word(version)));
        }
        let mode = Mode::of_word(mode).ok_or_else(|| format!("a hello of the mode {}", one_word(mode)))?;
        let link = unhex(link).filter(|b| b.len() == 16).ok_or("a hello whose link is not 32 hex digits")?;
        let tag = unhex(tag).filter(|b| b.len() == TAG_BYTES).ok_or("a hello whose tag is not 32 hex digits")?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&link);
        let id = LinkId(id);
        if !same(&self.tag(mode, &id)[..TAG_BYTES], &tag) {
            return Err("a hello of another key: another pair's client, or a stranger's".into());
        }
        Ok((mode, id))
    }
}

/// What one end of a link sends and reads: the words of its POST's path and
/// of its GET's, the mark that it sends first, and the one that it must read
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ends {
    pub send: String,
    pub recv: String,
    pub mine: [u8; MARK_BYTES],
    pub theirs: [u8; MARK_BYTES],
}

impl Ends {
    /// The client's: it sends up, and reads down.
    pub fn client(secret: &Secret, link: &LinkId) -> Ends {
        Ends::of(secret, link, Way::Up, Way::Down)
    }

    /// The node's: it sends down, and reads up.
    pub fn node(secret: &Secret, link: &LinkId) -> Ends {
        Ends::of(secret, link, Way::Down, Way::Up)
    }

    fn of(secret: &Secret, link: &LinkId, send: Way, recv: Way) -> Ends {
        Ends {
            send: secret.path(send, link),
            recv: secret.path(recv, link),
            mine: secret.mark(send, link),
            theirs: secret.mark(recv, link),
        }
    }
}

/// HMAC-SHA256 under `key` of `label`, a 0 byte, and each part after its
/// length, so that two lists of parts never give one input.
fn mac(key: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC takes a key of each length, so `new_from_slice` cannot fail.
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => <Hmac<Sha256> as KeyInit>::new(&Default::default()),
    };
    mac.update(label);
    mac.update(&[0]);
    for part in parts {
        mac.update(&(part.len() as u32).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Whether two tags are equal, in a time that does not depend on where they
/// differ.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

/// The bytes of hex in either case; `None` for another character or an odd
/// length.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    text.as_bytes().chunks(2).map(|pair| Some((digit(pair[0])? << 4) | digit(pair[1])?)).collect()
}

/// A word of a peer's for a line: short, and one line.
fn one_word(word: &str) -> String {
    podssh_ws::text::one_line(&word.chars().take(16).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr";
    const LINK: LinkId = LinkId([7; 16]);

    fn secret() -> Secret {
        Secret::of_pair("relay-pair-name", TOKEN)
    }

    #[test]
    fn the_client_sends_where_the_node_reads_and_reads_where_the_node_sends() {
        let (client, node) = (Ends::client(&secret(), &LINK), Ends::node(&secret(), &LINK));
        assert_eq!(client.send, node.recv, "the up way: the client's POST is the node's GET");
        assert_eq!(client.recv, node.send, "the down way: the node's POST is the client's GET");
        assert_eq!(client.mine, node.theirs);
        assert_eq!(client.theirs, node.mine);
        assert_eq!(client.send, secret().path(Way::Up, &LINK), "the client sends up");
        assert_ne!(client.send, client.recv, "the two ways never share a path");
        assert_ne!(client.mine, client.theirs, "nor a mark");
    }

    #[test]
    fn each_path_is_32_hex_digits_that_depend_on_the_pair_and_the_link() {
        let door = secret().door();
        assert_eq!(door.len(), 32);
        assert!(door.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{door}");
        assert_eq!(door, secret().door(), "a node and a client find one door");
        assert_ne!(door, Secret::of_pair("relay-pair-name", "another token").door());
        assert_ne!(door, Secret::of_pair("another-pair", TOKEN).door());
        let other = LinkId([8; 16]);
        assert_ne!(secret().path(Way::Up, &LINK), secret().path(Way::Up, &other));
        assert_ne!(secret().path(Way::Up, &LINK), door);
        assert!(!door.contains(&TOKEN[..8]) && !door.contains("relay"), "a path names neither the token nor the pair");
    }

    #[test]
    fn a_hello_comes_back_as_it_went_and_one_of_another_key_or_shape_is_refused() {
        for mode in [Mode::Streamed, Mode::Numbered] {
            let hello = secret().hello(mode, &LINK);
            assert!(hello.len() <= HELLO_MAX && hello.ends_with('\n'), "{hello}");
            assert_eq!(secret().read_hello(hello.as_bytes()), Ok((mode, LINK)));
            // Hex in either case.
            let (head, tail) = hello.split_at(hello.len() - 66);
            let upper = format!("{head}{}", tail.to_uppercase());
            assert_eq!(secret().read_hello(upper.as_bytes()), Ok((mode, LINK)), "{upper}");
        }
        let hello = secret().hello(Mode::Streamed, &LINK);
        let stranger = Secret::from_bytes([1; 32]);
        assert!(stranger.read_hello(hello.as_bytes()).unwrap_err().contains("another key"));
        let numbered = hello.replace(" stream ", " numbered ");
        assert!(secret().read_hello(numbered.as_bytes()).is_err(), "the tag covers the mode");
        assert!(secret().read_hello(hello.replace(" 1 ", " 2 ").as_bytes()).unwrap_err().contains("version 2"));
        for bad in ["", "podssh-piping 1 stream", "GET / HTTP/1.1", "podssh-piping 1 stream zz 00"] {
            assert!(secret().read_hello(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(secret().read_hello(&[b'a'; HELLO_MAX + 1]).is_err());
        assert!(secret().read_hello(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn hex_comes_back_and_same_compares_whole_tags() {
        assert_eq!(hex(&[0x00, 0x7f, 0xff]), "007fff");
        assert_eq!(unhex("007FfF"), Some(vec![0x00, 0x7f, 0xff]));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
        assert_eq!(format!("{:?}", secret()), "Secret(<redacted>)");
    }
}
