//! A meek_lite bridge's arguments, as lyrebird reads them: `url=` and
//! `front=`, or `targets=URL|FRONT+FRONT,URL|FRONT` for several; `utls=`
//! read and left. Each pair of a URL and a front goes in at a place chosen at
//! random, as lyrebird spreads its fronts; a failure moves to the next.

use crate::pt::{get, host_port, HttpUrl};

/// One URL, and the front that carries it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Front {
    pub url: HttpUrl,
    /// The front's host, and its port when it names one.
    pub front: Option<(String, Option<u16>)>,
}

impl Front {
    /// Where the connection goes, and the name that TLS sends and checks:
    /// the front, with the scheme's port unless it names one (Go's URL
    /// takes the front as its whole host), else the URL's host and port.
    pub fn dial(&self) -> (String, u16) {
        match &self.front {
            Some((host, port)) => (host.clone(), port.unwrap_or(if self.url.tls { 443 } else { 80 })),
            None => (self.url.host.clone(), self.url.port),
        }
    }

    /// The value of `Host`: the URL's own host and port, as written.
    pub fn host_header(&self) -> &str {
        &self.url.authority
    }

    /// The URL with no query, and the front, for a line.
    pub fn shown(&self) -> String {
        match &self.front {
            Some((host, _)) => format!("{} through {host}", self.url.shown()),
            None => self.url.shown(),
        }
    }
}

/// A bridge's arguments: one front at least.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub fronts: Vec<Front>,
}

impl Args {
    /// The arguments of a bridge line, or why they are not meek_lite's.
    pub fn parse(settings: &[(String, String)]) -> Result<Args, String> {
        let pairs = match get(settings, "targets") {
            Some(targets) => targets_of(targets)?,
            None => {
                let url = get(settings, "url").ok_or("a meek_lite bridge line needs url= (or targets=)")?;
                vec![(url.to_string(), get(settings, "front").unwrap_or_default().to_string())]
            }
        };
        let mut fronts = Vec::with_capacity(pairs.len());
        for (url, front) in pairs {
            let url = HttpUrl::parse(&url)?;
            let front = match front.trim() {
                "" => None,
                text => {
                    let (host, port) = host_port(text, 0).map_err(|why| format!("front={text}: {why}"))?;
                    Some((host, (port != 0).then_some(port)))
                }
            };
            let at = random_below(fronts.len() + 1);
            fronts.insert(at, Front { url, front });
        }
        Ok(Args { fronts })
    }
}

/// `URL|F1+F2,URL2|F3` as pairs of a URL and a front, as lyrebird splits it:
/// the URL up to the first `|`, its fronts up to the next `,`.
fn targets_of(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        let (url, after) = rest.split_once('|').ok_or("targets= is URL|FRONT[+FRONT][,URL|FRONT]: a '|' is missing")?;
        let (fronts, more) = match after.split_once(',') {
            Some((fronts, more)) => (fronts, Some(more)),
            None => (after, None),
        };
        for front in fronts.split('+') {
            out.push((url.to_string(), front.to_string()));
        }
        match more {
            Some(more) => rest = more,
            None => return Ok(out),
        }
    }
}

/// A number below `n` from the system's source; 0 when it gives none, as the
/// order of the fronts spreads load and guards nothing.
fn random_below(n: usize) -> usize {
    let mut bytes = [0u8; 8];
    use rustls::crypto::SecureRandom as _;
    match crate::crypto::random::OsRandom.fill(&mut bytes) {
        Ok(()) if n > 0 => (u64::from_le_bytes(bytes) % n as u64) as usize,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn url_and_front_give_one_front_that_dials_the_front_and_names_the_url_s_host() {
        let args = Args::parse(&settings(&[
            ("url", "https://1603026938.rsc.cdn77.org"),
            ("front", "www.phpmyadmin.net"),
            ("utls", "HelloRandomizedALPN"),
        ]))
        .unwrap();
        let [front] = args.fronts.as_slice() else { panic!("{args:?}") };
        assert_eq!(front.dial(), ("www.phpmyadmin.net".to_string(), 443));
        assert_eq!(front.host_header(), "1603026938.rsc.cdn77.org");
        assert_eq!(front.shown(), "https://1603026938.rsc.cdn77.org/ through www.phpmyadmin.net");
    }

    #[test]
    fn with_no_front_the_url_is_dialled_with_its_port() {
        let args = Args::parse(&settings(&[("url", "http://192.0.2.9:7002/")])).unwrap();
        assert_eq!(args.fronts[0].dial(), ("192.0.2.9".to_string(), 7002));
        assert_eq!(args.fronts[0].host_header(), "192.0.2.9:7002");
        let fronted = settings(&[("url", "https://real.test:8443/"), ("front", "cdn.test:9443")]);
        let fronted = Args::parse(&fronted).unwrap();
        assert_eq!(fronted.fronts[0].dial(), ("cdn.test".to_string(), 9443));
        assert_eq!(fronted.fronts[0].host_header(), "real.test:8443");
    }

    #[test]
    fn targets_give_each_pair_of_a_url_and_a_front() {
        let targets = "https://a.test/|f1.test+f2.test,https://b.test/|f3.test";
        let args = Args::parse(&settings(&[("targets", targets)])).unwrap();
        let mut pairs: Vec<(String, String)> = args.fronts.iter().map(|f| (f.url.host.clone(), f.dial().0)).collect();
        pairs.sort();
        let want = [("a.test", "f1.test"), ("a.test", "f2.test"), ("b.test", "f3.test")];
        assert_eq!(pairs, want.map(|(u, f)| (u.to_string(), f.to_string())));
    }

    #[test]
    fn a_line_with_no_url_or_a_bad_one_is_refused() {
        for bad in [
            settings(&[("front", "cdn.test")]),
            settings(&[("url", "ftp://x.test/")]),
            settings(&[("url", "https://x.test/"), ("front", "a b")]),
            settings(&[("targets", "https://a.test/")]),
        ] {
            assert!(Args::parse(&bad).is_err(), "{bad:?}");
        }
    }
}
