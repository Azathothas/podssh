//! The client of the OpenTunnel road: for each link, a TCP stream to the
//! node's name on port 443 through `HTTPS_PROXY`, then TLS by that name,
//! verified with the host's trust as each name is: the service sends the
//! bytes on to the node, which ends TLS with the tunnel's certificate. No
//! upgrade and no account, so a proxy that refuses the WebSocket upgrade
//! passes it, and so does one that ends TLS itself, whose CA the host trusts,
//! as the node's certificate is a public one. After each lost link, a new
//! one. TLS proves the name only: the node's identity is the end-to-end
//! channel's to check, above the layer.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use podssh_ws::Trust;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::dial::{BoxIo, Visit, CONNECT_LIMIT};
use super::wire;
use super::Say;
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ask, Ended, Hearing, OsEntropy, Settings};

/// A node's name: its route under its tunnel's name,
/// `ROUTE.<id>.opentunnel.xyz`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    pub route: String,
    pub hostname: String,
}

impl Name {
    /// `ROUTE.ID.DOMAIN`, a domain of two labels or more, each a label of
    /// `[a-z0-9-]`; case does not matter.
    pub fn parse(text: &str) -> Result<Name, String> {
        let text = text.trim().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = text.split('.').collect();
        let whole = labels.len() >= 4 && labels.iter().all(|label| wire::is_route(label) && *label != wire::ROOT_ROUTE);
        if !whole {
            return Err("a node's name at OpenTunnel is ROUTE.ID.DOMAIN, as the node says it, such as \
                        ROUTE.abcdefghijkl.opentunnel.xyz"
                .into());
        }
        let (route, hostname) = text.split_once('.').unwrap_or_default();
        Ok(Name { route: route.to_string(), hostname: hostname.to_string() })
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.route, self.hostname)
    }
}

/// A link to the node: TLS by its name, over the service.
pub struct Link(BoxIo);

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("opentunnel::Link(..)")
    }
}

/// The links of one client to one node.
pub struct Dialer {
    name: Name,
    visit: Visit,
    trust: Trust,
    say: Say,
}

impl Dialer {
    /// The dialer of the node of `name`, through `visit`, whose TLS is
    /// checked with `trust`.
    pub fn new(name: Name, visit: Visit, trust: Trust, say: Say) -> Dialer {
        Dialer { name, visit, trust, say }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    /// A new link to the node, once its TLS passed; else why there is none.
    pub async fn link(&self) -> Result<Link, String> {
        let name = self.name.to_string();
        let tcp = (self.visit)(&name).await?;
        match podssh_ws::tls_over(tcp, &name, &self.trust, CONNECT_LIMIT).await {
            Ok(tls) => Ok(Link(Box::new(tls))),
            // The service closes a visitor whose route no bridge holds: no
            // node is attached, or its route is another.
            Err(podssh_ws::ConnectError::Tls(why)) => {
                (self.say)(format!("TLS with {name} failed: {why}"));
                Err(format!(
                    "TLS with {name} failed ({why}): no node holds the name at OpenTunnel now, or a proxy ended it"
                ))
            }
            Err(e) => Err(format!("{name}: {e}")),
        }
    }
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    carry_heard(dialer, app, settings, note, Arc::default()).await
}

/// [`carry`], with the session's `hearing`, which a notice of the far end's
/// silence reads.
pub async fn carry_heard<A, N>(
    dialer: &Dialer,
    app: A,
    settings: Settings,
    note: N,
    hearing: Arc<Hearing>,
) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.map_err(|e| e.to_string())?;
    let client = client.with_hearing(hearing);
    let connect = |_: &Ended| async move {
        match dialer.link().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    };
    // On the heap: the layer's future is larger than a small thread's stack
    // in a debug build.
    Ok(Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await)
}

impl AsyncRead for Link {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_a_route_under_a_tunnel_s_name() {
        let name = Name::parse("R7k2qmx4.ABCDEFGHIJKL.opentunnel.xyz.").unwrap();
        assert_eq!(name, Name { route: "r7k2qmx4".into(), hostname: "abcdefghijkl.opentunnel.xyz".into() });
        assert_eq!(name.to_string(), "r7k2qmx4.abcdefghijkl.opentunnel.xyz");
        for bad in
            ["abcdefghijkl.opentunnel.xyz", "@.abc.opentunnel.xyz", "a_b.abc.opentunnel.xyz", "a..opentunnel.xyz", ""]
        {
            assert!(Name::parse(bad).is_err(), "{bad}");
        }
    }
}
