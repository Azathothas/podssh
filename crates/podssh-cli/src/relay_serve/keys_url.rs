//! A list of keys at an `https://` URL, for `--mint keys:URL` and
//! `net,keys:URL` (T-646, GitHub #144), so that a role run from an image with
//! no writable volume changes whom it mints for with no rebuild. The list is
//! fetched through the host's proxy with the trust of `--ca-file`, 1 MiB at
//! most, within 20 s, through three redirects to `https://` alone, as a
//! subscription of Shadowsocks is (`crate::shadowsocks::subscription`):
//! once before the role takes a connection, which stops the start (78) when
//! it fails, then again each `--list-ttl SECS` (300); a copy older than that
//! and `--list-stale SECS` (3600) lets no key mint
//! (`podssh_relay::serve::keys::list`). Its trust is TLS alone: `--mint net`,
//! whose document its owner signs, is the stronger way. The URL's path and
//! query may hold a secret of its server: a line names its host alone.

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::serve::keys::list::{self, Fetch, Fetched, Fetching, List, Say};
use podssh_relay::serve::Mint;
use podssh_ws::{ConnectError, ProxyChoice, Trust};
use zeroize::Zeroizing;

use super::ServeArgs;
use crate::relay_settings::Refusal;

/// The largest list fetched.
pub const LIST_MOST: usize = 1 << 20;
/// Bound on a fetch, its TLS and its answer.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// The redirects followed, each to another `https://` URL.
const REDIRECTS: usize = 3;
/// The bounds of `--list-ttl` and `--list-stale`, in seconds.
const TTL_MOST: u64 = 86_400;
const STALE_MOST: u64 = 7 * 86_400;

/// How a list of a URL is read: fetched each TTL, its copy read for its
/// stale window past it while its server fails, with this trust.
#[derive(Clone)]
pub(crate) struct Lists {
    pub ttl: Duration,
    pub stale: Duration,
    pub trust: Trust,
}

impl Default for Lists {
    fn default() -> Lists {
        Lists { ttl: list::TTL, stale: list::STALE, trust: Trust::Default }
    }
}

impl Lists {
    /// `--list-ttl` and `--list-stale` of `s`, and the trust of `--ca-file`;
    /// either flag with no list of a URL is a usage error (64).
    pub(crate) fn of(s: &ServeArgs, ca_file: Option<&str>) -> Result<Lists, Refusal> {
        let ttl = seconds("--list-ttl", s.list_ttl.as_deref(), 1, TTL_MOST, list::TTL)?;
        let stale = seconds("--list-stale", s.list_stale.as_deref(), 0, STALE_MOST, list::STALE)?;
        if (s.list_ttl.is_some() || s.list_stale.is_some()) && !named(s.mint.as_deref()) {
            return Err(Refusal::usage("--list-ttl and --list-stale go with --mint keys:https://..., a list of a URL"));
        }
        Ok(Lists { ttl, stale, trust: crate::pairs::trust(ca_file) })
    }
}

/// `text` of `flag` as whole seconds from `least` to `most`; `default` with
/// none.
fn seconds(flag: &str, text: Option<&str>, least: u64, most: u64, default: Duration) -> Result<Duration, Refusal> {
    let Some(text) = text else { return Ok(default) };
    match text.parse::<u64>() {
        Ok(n) if (least..=most).contains(&n) => Ok(Duration::from_secs(n)),
        _ => Err(Refusal::usage(format!("{flag} {text:?}: seconds, from {least} to {most}"))),
    }
}

/// Whether `--mint WORD` names a list of a URL.
pub(crate) fn named(mint: Option<&str>) -> bool {
    mint.is_some_and(|word| word.to_ascii_lowercase().contains("keys:https://"))
}

/// The list of `rest`, the words after `keys:`: the copy of an `https://`
/// URL's; an `http://` URL is refused (64), as its list would come in
/// cleartext and a hop could add a key; any other rest is a file, as before.
pub(crate) fn list_of(rest: &str, lists: &Lists) -> Result<List, Refusal> {
    let scheme = rest.get(..8).unwrap_or(rest).to_ascii_lowercase();
    if scheme.starts_with("http://") {
        return Err(Refusal::usage("--mint keys: a list of keys is fetched over TLS alone: give its https:// URL"));
    }
    if scheme != "https://" {
        return Ok(List::File(rest.into()));
    }
    let url = Url::parse(rest).map_err(|why| Refusal::usage(format!("--mint keys: {why}")))?;
    let from = Https { url, trust: lists.trust.clone() };
    Ok(List::Fetched(Arc::new(Fetched::new(Box::new(from), lists.ttl, lists.stale))))
}

/// The copy of a URL's list that `mint` names, if any.
fn fetched(mint: &Mint) -> Option<&Arc<Fetched>> {
    match mint {
        Mint::Keys(list) | Mint::Net(_, Some(list)) => list.fetched(),
        _ => None,
    }
}

/// The first copy of the list of a URL that `mint` names, fetched now, on a
/// runtime of its own whose threads end before the role's starts, and
/// before the role takes a connection: a fetch that fails stops the start
/// (78), as a file that cannot be read does. The words of the first line,
/// after whom it mints for; none for a file.
pub(crate) fn first(mint: &Mint) -> Result<String, Refusal> {
    let Some(copy) = fetched(mint) else { return Ok(String::new()) };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Refusal::config(format!("could not start the async runtime: {e}")))?;
    let came = runtime.block_on(copy.refresh());
    runtime.shutdown_timeout(FETCH_TIMEOUT);
    let list = came.map_err(|why| Refusal::config(format!("--mint keys:{}: {why}", copy.shown())))?;
    let bad = match list.bad_lines() {
        [] => String::new(),
        lines => format!("; lines {lines:?} hold no key, and let nobody in"),
    };
    let (ttl, stale) = (copy.ttl().as_secs(), copy.stale().as_secs());
    let read = format!("fetched again each {ttl} s, and read {stale} s more while its server fails");
    Ok(format!(" ({} now{bad}; {read})", list::count(list.len())))
}

/// The list of a URL that `mint` names fetched again each TTL, in the
/// runtime that runs the role, each of its lines to `say`.
pub(crate) fn start(mint: &Mint, say: Say) {
    if let Some(copy) = fetched(mint) {
        copy.start(Some(say));
    }
}

/// A list's URL: `https://HOST[:PORT]/PATH?QUERY`.
struct Url {
    host: String,
    port: u16,
    /// The path and its query, as the request line carries them: they may
    /// hold a secret of the server's.
    target: Zeroizing<String>,
}

impl Url {
    fn parse(url: &str) -> Result<Url, String> {
        let rest = url.get(8..).ok_or("a list's URL is https://HOST/PATH")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("a list's URL takes no user and no password".into());
        }
        let (host, port) = host_port(authority)?;
        let tail = tail.split('#').next().unwrap_or_default();
        let target = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
        if target.bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return Err("a list's URL holds a space, a control character or a byte past ASCII; write it %XX".into());
        }
        Ok(Url { host, port, target: Zeroizing::new(target) })
    }

    /// `https://HOST/...`: its host alone.
    fn shown(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            443 => format!("https://{host}/..."),
            port => format!("https://{host}:{port}/..."),
        }
    }
}

/// `HOST`, `HOST:PORT`, `[IPV6]` or `[IPV6]:PORT`; 443 with no port.
fn host_port(authority: &str) -> Result<(String, u16), String> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or("a list's host has a [ and no ]")?;
            match after {
                "" => (host, None),
                _ => (host, Some(after.strip_prefix(':').ok_or("a list's URL has text after ]")?)),
            }
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    podssh_ws::names::check_target(host).map_err(|why| format!("a list's host: {why}"))?;
    let port = match port {
        None => 443,
        Some(text) => text.parse::<u16>().ok().filter(|p| *p != 0).ok_or("a list's port is not a port")?,
    };
    Ok((host.to_string(), port))
}

/// A list's server, through the host's proxy, with the role's trust.
struct Https {
    url: Url,
    trust: Trust,
}

impl Fetch for Https {
    fn fetch(&self) -> Fetching<'_> {
        Box::pin(get(&self.url, &self.trust))
    }

    fn shown(&self) -> String {
        self.url.shown()
    }
}

/// The body at `url`, after at most [`REDIRECTS`] redirects, each to
/// `https://`; `Err` names the host, never the path.
async fn get(url: &Url, trust: &Trust) -> Result<Vec<u8>, String> {
    let mut at = Url { host: url.host.clone(), port: url.port, target: url.target.clone() };
    for _ in 0..=REDIRECTS {
        let proxy = ProxyChoice::FromEnvironment;
        let answer = podssh_ws::client::https_get_accepting(
            &at.host,
            at.port,
            &at.target,
            "text/plain, */*",
            LIST_MOST,
            trust,
            &proxy,
            FETCH_TIMEOUT,
        )
        .await
        .map_err(|e| failed(&e, &at.host))?;
        match answer.status {
            200 => return Ok(answer.body),
            301 | 302 | 303 | 307 | 308 => {
                let to = answer.header("location").ok_or("a redirect with no Location")?;
                at = match to.strip_prefix('/') {
                    Some(_) if !to.starts_with("//") => Url { target: Zeroizing::new(to.to_string()), ..at },
                    _ if to.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) => {
                        Url::parse(to).map_err(|why| format!("a redirect: {why}"))?
                    }
                    _ => return Err("a redirect to a URL that is not https://".into()),
                };
            }
            status => return Err(format!("HTTP {status} {}", answer.reason)),
        }
    }
    Err(format!("more than {REDIRECTS} redirects"))
}

/// A fetch's failure, its host named and never its path.
fn failed(e: &ConnectError, host: &str) -> String {
    match e {
        ConnectError::Tls(why) => format!("TLS with {host} failed: {why}"),
        ConnectError::Http(why) => format!("the HTTPS request to {host} failed: {why}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_of_https_is_a_copy_by_its_host_another_rest_a_file_and_http_is_refused() {
        let lists = Lists::default();
        let copy = list_of("https://keys.example/owners/SECRET-PATH?token=SECRET", &lists).unwrap();
        assert_eq!(copy.shown(), "https://keys.example/...");
        assert!(copy.fetched().is_some() && !format!("{copy:?}").contains("SECRET"), "{copy:?}");
        let other = list_of("HTTPS://[2001:db8::2]:8443", &lists).unwrap();
        assert_eq!(other.shown(), "https://[2001:db8::2]:8443/...");
        for file in ["owners.txt", "/etc/podssh/owners", "https-owners", "./https:/x"] {
            assert!(matches!(list_of(file, &lists).unwrap(), List::File(_)), "{file}");
        }
        let http = list_of("http://keys.example/owners", &lists).unwrap_err();
        assert!(http.code == crate::exit_codes::EXIT_USAGE && http.message.contains("https://"), "{http}");
        let user = ["https://owner", ":pw", "@keys.example/x"].concat();
        assert!(list_of(&user, &lists).unwrap_err().message.contains("no user"));
        assert!(list_of("https://keys.example/a b", &lists).unwrap_err().message.contains("a space"));
        assert!(named(Some("net,keys:HTTPS://keys.example/x")) && !named(Some("keys:owners")) && !named(None));
    }

    #[test]
    fn the_ttl_and_the_stale_window_are_bounded_and_need_a_list_of_a_url() {
        let url = Some("keys:https://keys.example/owners".to_string());
        let s = ServeArgs { mint: url.clone(), list_ttl: Some("60".into()), ..ServeArgs::default() };
        let lists = Lists::of(&s, None).unwrap();
        assert_eq!((lists.ttl, lists.stale), (Duration::from_secs(60), list::STALE));
        for (ttl, stale) in [(Some("0"), None), (Some("86401"), None), (None, Some("604801")), (Some("soon"), None)] {
            let (list_ttl, list_stale) = (ttl.map(String::from), stale.map(String::from));
            let s = ServeArgs { mint: url.clone(), list_ttl, list_stale, ..ServeArgs::default() };
            let code = Lists::of(&s, None).err().map(|r| r.code);
            assert_eq!(code, Some(crate::exit_codes::EXIT_USAGE), "{ttl:?} {stale:?}");
        }
        let file = ServeArgs { mint: Some("keys:owners".into()), list_stale: Some("0".into()), ..ServeArgs::default() };
        assert!(matches!(Lists::of(&file, None), Err(e) if e.message.contains("go with --mint keys:https://")));
    }
}
