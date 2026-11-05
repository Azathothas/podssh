//! The names that the owner of a relay role publishes to nodes (T-649,
//! GitHub #147): `podssh relay serve --publish NAME=PAIR`. Before the role's
//! own TLS, the listener peeks at a connection's ClientHello
//! ([`super::sni`]), within [`WAIT`] and [`super::sni::MOST`] bytes; a name of
//! the table goes to the node of its pair with each byte untouched
//! ([`super::reverse::publish`]), so that the node's own TLS answers it with
//! its own certificate and the role holds no key of that name. Each other
//! connection goes on as before: a client by address, another name, a record
//! cut short or too long, and what is no TLS. A CA's validation of a
//! published name (`acme-tls/1`) goes to the node too, so that the node can
//! prove the name for a certificate of its own; the role's own `--acme` name
//! is never one of the table, so its validations stay the role's. A name is
//! matched as DNS matches one, with no case (RFC 4343) and no trailing dot.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use super::sni::{self, Read};

/// How long a ClientHello has to come whole: a client sends it at once, in
/// one segment or a few.
pub const WAIT: Duration = Duration::from_secs(10);
/// How long a peek that saw a part waits before it looks again: the bytes
/// stay in the socket, so a peek at once would see the same.
const PEEK_AGAIN: Duration = Duration::from_millis(20);
/// The most names of a table: each is one row of a command line.
pub const MOST_NAMES: usize = 256;

/// Each published name, lower-cased, and the name of its pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Published {
    names: BTreeMap<String, String>,
    /// [`WAIT`], or a test's.
    wait: Option<Duration>,
}

/// A connection that the table sends to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routed {
    /// The name as the table holds it.
    pub name: String,
    /// Its pair's name, `p-...`.
    pub pair: String,
    /// A CA's validation, which offers `acme-tls/1` alone.
    pub acme: bool,
}

impl Published {
    /// The table of `rows`, each `NAME=PAIR`: NAME a DNS name of two labels
    /// at least, with no wildcard and no address, PAIR a pair's name of the
    /// role. A row out of shape, a name given twice and more than
    /// [`MOST_NAMES`] rows are refused, with why.
    pub fn of<S: AsRef<str>>(rows: &[S]) -> Result<Published, String> {
        if rows.len() > MOST_NAMES {
            return Err(format!("{} names to publish, past the {MOST_NAMES} of a role", rows.len()));
        }
        let mut names = BTreeMap::new();
        for row in rows {
            let row = row.as_ref();
            let Some((name, pair)) = row.split_once('=') else {
                return Err(format!("{row:?}: NAME=PAIR, a DNS name and the name of a pair of this relay"));
            };
            let name = dns_name(name).ok_or_else(|| {
                format!("{row:?}: {name:?} is no DNS name of two labels or more, with no wildcard and no address")
            })?;
            crate::relay::check_node_name(pair).map_err(|why| format!("{row:?}: the pair {pair:?}: {why}"))?;
            if names.insert(name.clone(), pair.to_string()).is_some() {
                return Err(format!("{name} is published twice"));
            }
        }
        Ok(Published { names, wait: None })
    }

    /// The same table, which waits `wait` for a ClientHello: a test's.
    pub fn waiting(self, wait: Duration) -> Published {
        Published { wait: Some(wait), ..self }
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Each name and its pair, in the order of the names.
    pub fn rows(&self) -> impl Iterator<Item = (&str, &str)> {
        self.names.iter().map(|(name, pair)| (name.as_str(), pair.as_str()))
    }

    /// Whether `name`, a DNS name of the owner's, is published: the role's
    /// own `--acme` name may not be.
    pub fn holds(&self, name: &str) -> bool {
        self.route(name).is_some()
    }

    /// The name of the table and its pair for `name`, a server name as a
    /// client wrote it: its case and a trailing dot do not matter, as in DNS.
    pub fn route(&self, name: &str) -> Option<(&str, &str)> {
        let folded = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        self.names.get_key_value(&folded).map(|(name, pair)| (name.as_str(), pair.as_str()))
    }

    /// Where the ClientHello at the start of `tcp` goes: the node of its
    /// name's pair, or none for each other start, the role's own path. The
    /// bytes are peeked, never taken, within [`WAIT`]: a hello that has not
    /// come whole by then is none, and the role's TLS reads what came.
    pub async fn peek(&self, tcp: &TcpStream) -> Option<Routed> {
        if self.is_empty() {
            return None;
        }
        let deadline = Instant::now() + self.wait.unwrap_or(WAIT);
        let mut buf = vec![0u8; sni::MOST];
        let look = async {
            loop {
                let n = match tcp.peek(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    // Its end, or an error: no hello comes.
                    _ => return None,
                };
                match sni::read(&buf[..n]) {
                    Read::More => tokio::time::sleep(PEEK_AGAIN).await,
                    Read::Not => return None,
                    Read::Hello(hello) => return self.routed(hello),
                }
            }
        };
        tokio::time::timeout_at(deadline, look).await.ok().flatten()
    }

    /// The route of a whole ClientHello: none with no name, or another.
    fn routed(&self, hello: sni::Hello) -> Option<Routed> {
        let (name, pair) = self.route(hello.name.as_deref()?)?;
        Some(Routed { name: name.to_string(), pair: pair.to_string(), acme: hello.acme })
    }
}

/// `text` as a published name, lower-cased with no trailing dot: labels of
/// letters, digits and `-`, 63 bytes at most each, not first or last `-`; two
/// labels or more, 253 bytes in all; no label `*`, and a last label that is
/// not all digits, so that no address is one.
pub fn dns_name(text: &str) -> Option<String> {
    let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let labels: Vec<&str> = name.split('.').collect();
    let numeric = labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    (name.len() <= 253 && labels.len() >= 2 && labels.iter().all(|l| label(l)) && !numeric).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-649: a table of rows, each name lower-cased; a row out of shape and
    /// a name twice are refused with why.
    #[test]
    fn a_table_holds_each_name_once_lower_cased() {
        let table = Published::of(&["Site.Example.ORG=p-0123abcd", "api.example.org.=p-4567"]).unwrap();
        let rows: Vec<(&str, &str)> = table.rows().collect();
        assert_eq!(rows, [("api.example.org", "p-4567"), ("site.example.org", "p-0123abcd")]);
        assert_eq!(table.len(), 2);
        assert!(Published::of::<&str>(&[]).unwrap().is_empty());
        let refused = [
            ("site.example.org", "NAME=PAIR"),
            ("*.example.org=p-1", "no DNS name"),
            ("example=p-1", "no DNS name"),
            ("192.0.2.7=p-1", "no DNS name"),
            ("-site.example.org=p-1", "no DNS name"),
            ("site.example.org=", "the pair"),
            ("site.example.org=p/1", "the pair"),
        ];
        for (row, says) in refused {
            let why = Published::of(&[row]).unwrap_err();
            assert!(why.contains(says), "{row}: {why}");
        }
        let twice = Published::of(&["site.example.org=p-1", "SITE.example.org=p-2"]).unwrap_err();
        assert_eq!(twice, "site.example.org is published twice");
        let many: Vec<String> = (0..=MOST_NAMES).map(|i| format!("n{i}.example.org=p-{i}")).collect();
        assert!(Published::of(&many).unwrap_err().contains("past the 256"));
    }

    /// T-649: a client's name in another case, or with a trailing dot, is
    /// the table's name; another name, and a longer one, are not.
    #[test]
    fn a_name_in_another_case_is_its_route() {
        let table = Published::of(&["site.example.org=p-0123abcd"]).unwrap();
        for asked in ["site.example.org", "SITE.Example.Org", "site.example.org."] {
            assert_eq!(table.route(asked), Some(("site.example.org", "p-0123abcd")), "{asked}");
        }
        for other in ["example.org", "www.site.example.org", "site.example.org.evil", "site-example.org", ""] {
            assert_eq!(table.route(other), None, "{other}");
        }
        assert!(table.holds("Site.Example.Org") && !table.holds("relay.example.org"));
    }
}
