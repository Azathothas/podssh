//! podssh's name resolution for iroh: the relay's name and the proxy's go
//! through the same chain as on the other roads (an IP literal, the pinned
//! addresses of `--relay-addr`, the system resolver, then DNS over HTTPS), not
//! through iroh's own resolver, which knows no pins and no fallback.
//!
//! Through a proxy, the relay's name is not resolved here at all: the proxy
//! gets it in `CONNECT`. iroh asks for a TXT record only for address lookup,
//! which podssh turns off, so that answer is a refusal.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::time::Duration;

use iroh::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
use n0_error::{e, AnyError};
use tokio::time::Instant;

/// The bound on one lookup: the system resolver, then each DNS-over-HTTPS
/// resolver within what is left.
const LOOKUP_LIMIT: Duration = Duration::from_secs(15);

type Lookup<T> = Pin<Box<dyn Future<Output = Result<BoxIter<T>, DnsError>> + Send>>;

/// The resolver that iroh gets in place of its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct Podssh;

/// Each address of `host` that podssh's chain finds, of one family.
async fn addresses(host: String) -> Result<Vec<IpAddr>, DnsError> {
    let deadline = Instant::now() + LOOKUP_LIMIT;
    match podssh_ws::resolve::resolve(&host, 0, deadline).await {
        Ok(found) => Ok(found.into_iter().map(|addr| addr.ip()).collect()),
        Err(why) => Err(e!(DnsError::Resolve, AnyError::from_string(format!("could not resolve {host}: {why}")))),
    }
}

impl Resolver for Podssh {
    fn lookup_ipv4(&self, host: String) -> Lookup<Ipv4Addr> {
        Box::pin(async move {
            let v4: Vec<Ipv4Addr> = addresses(host)
                .await?
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect();
            Ok(Box::new(v4.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> Lookup<Ipv6Addr> {
        Box::pin(async move {
            let v6: Vec<Ipv6Addr> = addresses(host)
                .await?
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    IpAddr::V4(_) => None,
                })
                .collect();
            Ok(Box::new(v6.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, _host: String) -> Lookup<TxtRecordData> {
        // Address lookup is off: no TXT record is ever needed.
        Box::pin(async { Err(e!(DnsError::NoResponse)) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(Podssh)
    }
}
