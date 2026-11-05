//! The certificate of `podssh relay serve` (T-447): from `--cert` and
//! `--key`, or from ACME (`--acme NAME`); read again on SIGHUP, and, for
//! files, when either changed, which a host with no SIGHUP (Windows) needs.
//! The handshakes after a read take the new pair; a pair that does not load
//! is said, and the one of before stays; a connection that is open keeps its
//! own.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use podssh_relay::serve::http2::H2;
use podssh_ws::tls_server::{Served, ACME_TLS_1, HTTP1};

use crate::acme::{self, certs::Leaf, Acme};
use crate::relay_settings::Refusal;

/// How often the files of `--cert` and `--key` are looked at.
pub const WATCH: Duration = Duration::from_secs(60);

/// Where the certificate comes from, as the flags say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Files { cert: String, key: String },
    Acme { name: String, directory: Option<String>, ca_file: Option<String> },
}

impl Source {
    /// The source of the flags, or the usage error that says which to give.
    pub fn of(s: &super::ServeArgs, ca_file: Option<&str>) -> Result<Source, Refusal> {
        if s.acme_directory.is_some() && s.acme.is_none() {
            return Err(Refusal::usage("--acme-directory goes with --acme NAME"));
        }
        match (s.cert.as_deref(), s.key.as_deref(), s.acme.as_deref()) {
            (None, None, Some(name)) => Ok(Source::Acme {
                name: acme_name(name)?,
                directory: s.acme_directory.clone(),
                ca_file: ca_file.map(str::to_string),
            }),
            (_, _, Some(_)) => Err(Refusal::usage(
                "--acme takes its certificate from the CA, and --cert and --key name files: give one or the other",
            )),
            // --ca-file is the trust of a list of keys at a URL too (T-646).
            (Some(cert), Some(key), None) if ca_file.is_none() || super::keys_url::named(s.mint.as_deref()) => {
                Ok(Source::Files { cert: cert.to_string(), key: key.to_string() })
            }
            (Some(_), Some(_), None) => Err(Refusal::usage(
                "--ca-file goes with serve only beside --acme, as the trust of the ACME directory, or beside --mint \
                 keys:https://..., as the trust of the list",
            )),
            _ => Err(Refusal::usage(
                "serve needs --cert FILE and --key FILE: a certificate chain and its P-256 key, in PEM; or --acme \
                 NAME, a certificate for NAME from an ACME CA",
            )),
        }
    }
}

/// NAME of `--acme`: a DNS name of two labels at least, lower-cased, with no
/// wildcard and no address, as TLS-ALPN-01 validates it on port 443.
pub fn acme_name(text: &str) -> Result<String, Refusal> {
    let name = text.trim_end_matches('.').to_ascii_lowercase();
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let labels: Vec<&str> = name.split('.').collect();
    let numeric = labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if name.len() > 253 || labels.len() < 2 || !labels.iter().all(|l| label(l)) || numeric {
        return Err(Refusal::usage(format!(
            "--acme {text:?}: a DNS name of this host, as relay.example.org, with no wildcard and no address; the CA \
             reaches it on port 443"
        )));
    }
    Ok(name)
}

/// The files read again, and what they held when they were read last.
#[derive(Debug)]
struct Files {
    cert: PathBuf,
    key: PathBuf,
    seen: Mutex<Option<Stamp>>,
}

/// The modification time and the length of each file.
type Stamp = [(Option<SystemTime>, u64); 2];

impl Files {
    fn stamp(&self) -> Stamp {
        let of = |p: &PathBuf| std::fs::metadata(p).map(|m| (m.modified().ok(), m.len())).unwrap_or((None, 0));
        [of(&self.cert), of(&self.key)]
    }

    fn shown(&self) -> String {
        if self.cert == self.key {
            self.cert.display().to_string()
        } else {
            format!("{} and {}", self.cert.display(), self.key.display())
        }
    }

    /// Read the pair, and keep what the files held, also when it failed,
    /// so that the watch says a failure once.
    fn load(&self) -> Result<(Arc<rustls::sign::CertifiedKey>, Leaf), String> {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(self.stamp());
        let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("{}: {e}{}", p.display(), after_drop(&e)));
        let (cert, key) = (read(&self.cert)?, read(&self.key)?);
        acme::certs::load(&cert, &key).map_err(|e| format!("{}: {e}", self.shown()))
    }

    fn changed(&self) -> bool {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) != Some(self.stamp())
    }
}

/// Why a file read at the start is refused now: the role gave up the
/// capabilities of its start after the bind (T-629), and a root with no
/// `CAP_DAC_OVERRIDE` reads a file of another owner only as its mode says.
fn after_drop(e: &std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::PermissionDenied && super::harden::dropped() {
        AFTER_DROP
    } else {
        ""
    }
}

const AFTER_DROP: &str =
    " (the role gave up its capabilities after the bind: the file's owner and mode must let this user read it)";

/// The certificate of the role, and how it is kept.
pub struct Certs {
    pub served: Arc<Served>,
    files: Files,
    acme: Option<Acme>,
    /// What the first line of the role says of its certificate.
    pub shown: String,
}

impl Certs {
    /// The certificate of `source`, read now: a pair of files that does not
    /// load stops the start (78); ACME's that is not kept yet is ordered
    /// once the role listens.
    pub fn open(source: Source) -> Result<Certs, Refusal> {
        match source {
            Source::Files { cert, key } => {
                let files = Files { cert: cert.into(), key: key.into(), seen: Mutex::new(None) };
                let (pair, leaf) = files.load().map_err(Refusal::config)?;
                let shown = format!("with the certificate of {} {}", files.shown(), acme::about(&leaf));
                Ok(Certs { served: Served::new(Some(pair)), files, acme: None, shown })
            }
            Source::Acme { name, directory, ca_file } => {
                let trust = crate::pairs::trust(ca_file.as_deref());
                let ca = Acme::new(&name, directory.as_deref(), trust)?;
                let path = ca.store.pem_path();
                let files = Files { cert: path.clone(), key: path.clone(), seen: Mutex::new(None) };
                let host = ca.host();
                let (served, shown) = match ca.held(acme::order::now_secs()) {
                    Ok(Some((pair, leaf))) => {
                        let shown = format!("with the certificate from ACME at {host} {}", acme::about(&leaf));
                        (Served::new(Some(pair)), shown)
                    }
                    Ok(None) => (Served::new(None), format!("asking ACME at {host} for {name}")),
                    Err(why) => (Served::new(None), format!("asking ACME at {host} for {name} ({why})")),
                };
                let shown = format!("{shown}, kept in {}", path.display());
                Ok(Certs { served, files, acme: Some(ca), shown })
            }
        }
    }

    /// The protocols that the listener offers: `h2` first with `http2`
    /// (T-321), and TLS-ALPN-01's too with ACME.
    pub fn alpn(&self, http2: bool) -> &'static [&'static [u8]] {
        match (http2, self.acme.is_some()) {
            (true, true) => &[H2, HTTP1, ACME_TLS_1],
            (true, false) => &[H2, HTTP1],
            (false, true) => &[HTTP1, ACME_TLS_1],
            (false, false) => &[HTTP1],
        }
    }

    /// The leaf served now: of the files, or of ACME's last renewal.
    fn leaf(&self) -> Option<Leaf> {
        let pair = self.served.current()?;
        acme::certs::leaf(pair.cert.first()?.as_ref()).ok()
    }

    /// Read the files again, for `why`: the line that says what is served.
    pub fn reload(&self, why: &str) -> String {
        match self.files.load() {
            Ok((pair, leaf)) => {
                self.served.set(pair);
                let line = format!("{why}: read {} again: the certificate {}", self.files.shown(), acme::about(&leaf));
                format!("{line}, for the next handshakes")
            }
            Err(e) => {
                let before = match self.leaf() {
                    Some(leaf) => format!("the certificate {} stays", acme::about(&leaf)),
                    None => "no certificate is served yet".to_string(),
                };
                format!("{why}: {e}; {before}")
            }
        }
    }

    /// The files read again when either changed since its last read; none
    /// with ACME, which writes its own.
    pub fn reload_if_changed(&self) -> Option<String> {
        (self.acme.is_none() && self.files.changed()).then(|| self.reload("a file changed"))
    }

    /// The work that keeps the certificate while the role runs: ACME's
    /// renewals, or nothing for files. Ends only with the reason to stop.
    pub fn keeper(&self, say: acme::Say) -> impl std::future::Future<Output = String> + Send + 'static {
        let (ca, served, held) = (self.acme.clone(), self.served.clone(), self.leaf());
        async move {
            match ca {
                Some(ca) => acme::keep(ca, served, held, say).await,
                None => std::future::pending().await,
            }
        }
    }
}

/// SIGHUP, which the role takes to read its certificate again. Windows has
/// none: the role looks at the files each minute instead ([`WATCH`]).
#[cfg(unix)]
pub struct Hangups(Option<tokio::signal::unix::Signal>);

#[cfg(unix)]
impl Hangups {
    /// Taken from now on: SIGHUP no longer ends the role. Made in the runtime.
    pub fn take() -> Hangups {
        Hangups(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok())
    }

    pub async fn next(&mut self) {
        let ended = match self.0.as_mut() {
            Some(signal) => signal.recv().await.is_none(),
            None => return std::future::pending().await,
        };
        if ended {
            self.0 = None;
        }
    }
}

#[cfg(not(unix))]
pub struct Hangups;

#[cfg(not(unix))]
impl Hangups {
    pub fn take() -> Hangups {
        Hangups
    }

    pub async fn next(&mut self) {
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_for_acme_is_a_dns_name_of_two_labels_with_no_wildcard_or_address() {
        assert_eq!(acme_name("Relay.Example.ORG.").unwrap(), "relay.example.org");
        assert_eq!(acme_name("a-1.b2.example").unwrap(), "a-1.b2.example");
        for wrong in ["localhost", "*.example.org", "192.0.2.1", "-a.example.org", "a..example.org", "a_b.example"] {
            let refusal = acme_name(wrong).unwrap_err();
            assert_eq!(refusal.code, crate::exit_codes::EXIT_USAGE, "{wrong}");
            assert!(refusal.message.contains("port 443"), "{wrong}: {}", refusal.message);
        }
        assert!(acme_name(&format!("{}.example.org", "a".repeat(64))).is_err());
    }

    #[test]
    fn the_flags_name_files_or_acme_and_never_both() {
        let args = |cert: bool, acme: bool, directory: bool| super::super::ServeArgs {
            cert: cert.then(|| "c.pem".into()),
            key: cert.then(|| "k.pem".into()),
            acme: acme.then(|| "relay.example.org".into()),
            acme_directory: directory.then(|| "https://ca.test/dir".into()),
            ..Default::default()
        };
        let files = Source::of(&args(true, false, false), None).unwrap();
        assert_eq!(files, Source::Files { cert: "c.pem".into(), key: "k.pem".into() });
        let acme = Source::of(&args(false, true, true), Some("ca.pem")).unwrap();
        let want = Source::Acme {
            name: "relay.example.org".into(),
            directory: Some("https://ca.test/dir".into()),
            ca_file: Some("ca.pem".into()),
        };
        assert_eq!(acme, want);
        let said = |a, c| Source::of(&a, c).unwrap_err().message;
        assert!(said(args(true, true, false), None).contains("one or the other"));
        assert!(said(args(true, false, true), None).contains("--acme-directory goes with --acme"));
        assert!(said(args(true, false, false), Some("ca.pem")).contains("trust of the ACME directory"));
        assert!(said(args(false, false, false), None).contains("needs --cert FILE and --key FILE"));
        // The trust of a list of keys at a URL, beside files (T-646).
        let mint = Some("keys:https://keys.test/owners".to_string());
        let listed = super::super::ServeArgs { mint, ..args(true, false, false) };
        assert!(Source::of(&listed, Some("ca.pem")).is_ok(), "--ca-file beside a list at a URL");
    }
}
