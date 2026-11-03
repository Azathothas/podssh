//! Grants used once (T-226) at each end of `podssh`. A client's `--grant
//! FILE` (`operator`, `proxy` and `ssh` to `node://`, and `pipe`'s `node:`)
//! is read and checked for its form before anything connects, and goes in
//! the proof of the run's first channel, to a node whose key the channel
//! checked: a grant lets in one session, so a later session of the run
//! sends none. A node's door ([`door`]) takes a grant that its own key
//! signed, or a key that its `--allow` names, or a member of its net, each
//! for what it may reach itself; its record of each grant used is
//! `grants-LABEL` of the cache; `--revoked FILE` names serials that it
//! refuses. `podssh node NAME --grant-to KEY` mints one with the node's own
//! key ([`node`]), as `ssh-keygen -s` does with the key of an issuer.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use podssh_relay::cache;
use podssh_relay::e2e::ends::Redeem;
use podssh_relay::e2e::Ask;
use podssh_relay::grant::{self, Cert, Door, Mint, Spent};
use podssh_relay::identity::{allow, file, Identity, PublicKey};
use podssh_relay::session::{Entropy, OsEntropy};

use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The grant of this run's first session, as `--grant FILE` gave it.
static ASKED: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// `--revoked FILE` of this run's node.
static REVOKED: OnceLock<PathBuf> = OnceLock::new();

/// A grant's window when `--grant-for` names none.
const DEFAULT_LIFE: Duration = Duration::from_secs(3600);
/// The shortest and the longest window that `--grant-for` takes: a record of
/// each grant used is kept until its end.
const SHORTEST_LIFE: Duration = Duration::from_secs(60);
const LONGEST_LIFE: Duration = Duration::from_secs(30 * 86_400);

/// `--grant FILE` of a client, read and checked for its form, and kept for
/// the run's first session: a URL, or `--no-e2e` beside it, is a usage error
/// (64) and a file that is no grant a configuration error (78), each before
/// anything connects.
pub fn ask(file: Option<&str>, no_e2e: bool) -> Result<(), Refusal> {
    let Some(file) = file else { return Ok(()) };
    if no_e2e {
        return Err(Refusal::usage("--grant travels in the end-to-end channel, which --no-e2e turns off"));
    }
    if grant::looks_like_url(file) {
        return Err(Refusal::usage(format!(
            "--grant {file}: a grant is a file, never a URL: it goes in the end-to-end channel alone"
        )));
    }
    let cert = grant::read_file(Path::new(file)).map_err(|why| Refusal::config(format!("--grant {why}")))?;
    *ASKED.lock().unwrap_or_else(|e| e.into_inner()) = Some(cert.blob());
    Ok(())
}

/// Whether this run was given a grant that no channel took yet.
pub fn asked() -> bool {
    ASKED.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// The grant for the channel that starts now, once: the first takes it. A
/// grant for another key than `me` is said, as the node refuses it.
pub fn take(me: &PublicKey, say: &dyn Fn(String)) -> Option<Vec<u8>> {
    let blob = ASKED.lock().unwrap_or_else(|e| e.into_inner()).take()?;
    if let Ok(cert) = Cert::from_blob(&blob) {
        if cert.key != *me {
            say(format!(
                "the grant is for the key {}, not this client's {me} (client.key, or --client-key): the node \
                 refuses it; its issuer signs this one: {}",
                cert.key,
                grant::openssh_public(me)
            ));
        }
    }
    Some(blob)
}

/// A node's flags of grants: `--grant-to` mints one and ends the run, with
/// its code; `--grant-route` and `--grant-for` need it (64); `--revoked`
/// is kept for the node's door, on each road.
pub fn node(args: &NodeArgs, out: &mut dyn Write, err: &mut dyn Write) -> Option<i32> {
    if args.grant_to.is_some() {
        return Some(match minted(args) {
            Ok((line, said)) => {
                let _ = writeln!(out, "{line}");
                let _ = writeln!(err, "podssh node: {said}");
                0
            }
            Err(refusal) => refusal.report("node", err),
        });
    }
    if args.grant_route.is_some() || args.grant_for.is_some() {
        let why = "--grant-route and --grant-for are the route and the window of --grant-to KEY: give it too";
        return Some(Refusal::usage(why).report("node", err));
    }
    if let Some(file) = &args.revoked {
        if args.no_e2e {
            let why = "--revoked names grants, which the end-to-end channel carries, and --no-e2e turns it off";
            return Some(Refusal::usage(why).report("node", err));
        }
        let _ = REVOKED.set(PathBuf::from(file));
    }
    None
}

/// The door for grants of the node `me` of `label`, whose `--allow` is
/// `allow`: the node's own key issues them, and a key of `allow` or a
/// member of the net may, for what it may reach itself.
pub fn door(label: &str, me: PublicKey, allow: Option<PathBuf>) -> Option<Arc<Redeem>> {
    let door = Door { node: me, issuers: issuers(me, allow), spent: spent_of(label), revoked: REVOKED.get().cloned() };
    Some(Arc::new(move |peer: &PublicKey, ask: &Ask, blob: &[u8]| {
        door.redeem(peer, ask, blob, now()).map(|redeemed| redeemed.to_string())
    }))
}

/// The node's line of its door for grants, as it starts.
pub fn line(label: &str, allow: Option<&Path>) -> String {
    let by = match allow {
        Some(path) => format!("its own key or a key of {} (or a member of its net)", path.display()),
        None => "its own key (or a member of its net)".to_string(),
    };
    let kept = match spent_of(label).dir() {
        Some(dir) => format!("each one used is kept in {}", dir.display()),
        None => "none can be kept as used here, so each is refused".to_string(),
    };
    format!("grants used once, signed by {by}, let in one session each; {kept}")
}

/// Who may issue a grant beside the node's own key: a member of the net, as
/// its policy lets it reach what is asked; a key of `allow`, for the target
/// with no route or a route that its line gives. With neither, no other
/// key: the relay's token is then the node's door, and it names no issuer.
fn issuers(me: PublicKey, allow: Option<PathBuf>) -> Arc<grant::Issuers> {
    use crate::net::admit::{verdict, Asks, Verdict};
    Arc::new(move |issuer: &PublicKey, ask: &Ask| {
        if let Verdict::Member(_) = verdict(&me, issuer, Asks::of(ask)) {
            return Ok(());
        }
        let Some(path) = &allow else {
            return Err("this node has no --allow, and its net names no such issuer".into());
        };
        match ask {
            Ask::Target => allow::admits(path, issuer),
            Ask::Route(route) => allow::grants(path, issuer, route),
            Ask::Exit { .. } => Err("an exit's target takes no grant".into()),
        }
    })
}

/// The record of the grants that the node of `label` let in: `grants-LABEL`
/// of the cache where it is already, so that a use of an earlier run is
/// found, else in the first directory of the cache, made at the first use.
fn spent_of(label: &str) -> Spent {
    let name = format!("grants-{}", cache::safe_name(label));
    let dirs = cache::candidate_dirs();
    let kept = dirs.iter().map(|dir| dir.join(&name)).find(|place| place.is_dir());
    match kept.or_else(|| dirs.first().map(|dir| dir.join(&name))) {
        Some(place) => Spent::at(place),
        None => Spent::nowhere(format!("{} is none: no use of a grant can be kept, so each is refused", cache::DIR_ENV)),
    }
}

/// `--grant-to KEY`: the grant's line, and what the node says of it.
fn minted(args: &NodeArgs) -> Result<(String, String), Refusal> {
    let label = args.name.as_deref().ok_or("missing NAME: the label of the node whose key signs the grant")?;
    let to = args.grant_to.as_deref().unwrap_or_default();
    let key = grantee(to)?;
    let route = args.grant_route.as_deref();
    if let Some(route) = route {
        podssh_ws::names::check_node_name(route)
            .map_err(|_| Refusal::usage(format!("--grant-route {route:?} is not the name of a route")))?;
    }
    let life = match args.grant_for.as_deref() {
        Some(text) => life(text).map_err(Refusal::usage)?,
        None => DEFAULT_LIFE,
    };
    let flags = crate::node_flags::key_flags(args)?;
    if flags.ephemeral {
        return Err(Refusal::usage("--grant-to signs with the node's key, which --ephemeral-key keeps in no file"));
    }
    let place = crate::channel::node_place(label, flags.key.as_deref(), false)?;
    // Read, never made: a grant of a key that no node has lets nobody in.
    let identity = file::existing(&place).map_err(Refusal::config)?.ok_or_else(|| {
        Refusal::config(format!("the node {label} has no key yet: start it once, which makes it, or give --key"))
    })?;
    let cert = sign(&identity, key, label, route, now(), life)?;
    let node = identity.public();
    let shown = route.map(|r| format!("{label}/{r}")).unwrap_or_else(|| label.to_string());
    let said = format!(
        "{label}: a grant for {key} to {shown}, serial {}, used once within {} s, signed by the node's key {node}; \
         the operator gives it with --grant FILE",
        cert.serial,
        life.as_secs()
    );
    Ok((cert.to_line(&format!("podssh grant {shown}")), said))
}

/// The grant of `key` for `label` (and `route`), signed by `identity`, from
/// `now` for `life`, with a random nonce and serial.
fn sign(
    identity: &Identity,
    key: PublicKey,
    label: &str,
    route: Option<&str>,
    now: u64,
    life: Duration,
) -> Result<Cert, Refusal> {
    let mut random = [0u8; 40];
    OsEntropy.fill(&mut random).map_err(|_| Refusal::config("the OS gave no random bytes for a grant"))?;
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&random[..32]);
    let mut serial = [0u8; 8];
    serial.copy_from_slice(&random[32..]);
    let principals = vec![grant::principal(&identity.public(), route)];
    let key_id = format!("podssh grant for {label}{}", route.map(|r| format!("/{r}")).unwrap_or_default());
    let once: &[(&str, &[u8])] = &[(grant::ONCE, &[])];
    let mint = Mint {
        nonce,
        key,
        serial: u64::from_be_bytes(serial),
        key_id: &key_id,
        principals: &principals,
        valid_after: now,
        valid_before: now.saturating_add(life.as_secs()),
        critical: once,
    };
    Ok(mint.sign(identity))
}

/// The grantee's key: `ssh-ed25519 BASE64`, 64 hex digits, base32, or a
/// file of one such line; a fingerprint names a key but is none.
fn grantee(text: &str) -> Result<PublicKey, Refusal> {
    if let Some(key) = grant::parse_public(text) {
        return Ok(key);
    }
    let path = Path::new(text);
    if path.is_file() {
        let read = std::fs::read_to_string(path).map_err(|e| Refusal::config(format!("--grant-to {text}: {e}")))?;
        let line = read.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or_default();
        return grant::parse_public(line)
            .ok_or_else(|| Refusal::config(format!("--grant-to {text}: its first line is no Ed25519 key")));
    }
    Err(Refusal::usage(format!(
        "--grant-to {text:?}: not a key (ssh-ed25519 BASE64, 64 hex digits) nor a file of one; a fingerprint names a \
         key, but a grant needs the key itself"
    )))
}

/// A window of `--grant-for`: a whole number, then s, m, h or d.
fn life(text: &str) -> Result<Duration, String> {
    let bad = || format!("--grant-for {text:?}: a whole number, then s, m, h or d, as 90s, 30m, 8h or 3d");
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let scale: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(bad()),
    };
    let seconds = number.parse::<u64>().ok().and_then(|n| n.checked_mul(scale)).ok_or_else(bad)?;
    let time = Duration::from_secs(seconds);
    if !(SHORTEST_LIFE..=LONGEST_LIFE).contains(&time) {
        return Err(format!("--grant-for {text:?}: from 1 minute to 30 days"));
    }
    Ok(time)
}

/// Seconds since the epoch, as a grant's window counts them.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_is_a_whole_time_from_a_minute_to_thirty_days() {
        assert_eq!(life("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(life("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(life("30d"), Ok(LONGEST_LIFE));
        for bad in ["30", "31d", "1.5h", "h", "", "-1m"] {
            assert!(life(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_grantee_is_a_key_never_a_fingerprint() {
        let key = Identity::from_seed(&[0x11; 32]).public();
        assert_eq!(grantee(&grant::openssh_public(&key)).unwrap(), key);
        assert_eq!(grantee(&key.hex()).unwrap(), key);
        let refused = grantee(&key.fingerprint()).unwrap_err();
        assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE);
        assert!(refused.message.contains("needs the key itself"), "{}", refused.message);
    }

    /// The node's key signs a grant of its own principal, with the option
    /// `once@podssh`, which the node's door would take.
    #[test]
    fn a_minted_grant_names_the_node_and_its_route_and_is_used_once() {
        let node = Identity::from_seed(&[0x22; 32]);
        let key = Identity::from_seed(&[0x11; 32]).public();
        let cert = sign(&node, key, "lab", Some("web"), 1_000, Duration::from_secs(60)).unwrap();
        let read = Cert::from_text(&cert.to_line("podssh grant lab/web")).unwrap();
        assert!(read.signed_by_issuer() && read.issuer == node.public() && read.key == key);
        assert_eq!(read.principals, [grant::principal(&node.public(), Some("web"))]);
        assert_eq!((read.valid_after, read.valid_before), (1_000, 1_060));
        assert_eq!(read.critical, [(grant::ONCE.to_string(), Vec::new())]);
        assert_ne!(sign(&node, key, "lab", None, 1_000, Duration::from_secs(60)).unwrap().serial, read.serial);
    }

    #[test]
    fn a_grant_in_a_url_is_refused_before_anything_is_read() {
        let refused = ask(Some("https://relay.example/v1/grant?grant=AAAA"), false).unwrap_err();
        assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE);
        assert!(!asked(), "nothing kept");
    }
}
