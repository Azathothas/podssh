//! The operator's part of a pair as an operator's host keeps it under a
//! label (T-086): a pairing by code brings it with no file to move, and
//! `podssh operator NAME`, `podssh ssh node://NAME` and each other client of
//! the pair find it by the label, as they find a whole pair. It is
//! `operator-LABEL.json`, private, beside the pairs; a whole pair under the
//! same label is read first. A part that comes from the other end is checked
//! as T-076 and T-078 check a pair's answer.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{OperatorPart, PairError};
use crate::cache::{self, valid_token, MIN_REMAINING_MS};
use crate::relay::{check_node_name, parse_relay};
use crate::token::relay_name;

/// The part as it is written: borrowed, so the token is not copied.
#[derive(Serialize)]
pub(crate) struct PartRef<'a> {
    relay: String,
    name: &'a str,
    connect_token: &'a str,
    expires: i64,
}

/// The part as it is read; its token goes into `Zeroizing` at once.
#[derive(Deserialize)]
pub(crate) struct PartStored {
    relay: String,
    name: String,
    connect_token: String,
    expires: i64,
}

impl OperatorPart {
    /// A part of these words, checked as a pair's answer is: a name that
    /// keeps to its path, a token of a token's shape, a relay's name, and
    /// at least 10 minutes left at `now_ms`.
    pub fn checked(
        relay: &str,
        name: String,
        connect_token: Zeroizing<String>,
        expires_ms: i64,
        now_ms: i64,
    ) -> Result<OperatorPart, PairError> {
        check_node_name(&name).map_err(|_| PairError::BadAnswer("the name could change the relay path"))?;
        if !valid_token(&connect_token) {
            return Err(PairError::BadAnswer("a token does not have the shape of a token"));
        }
        let relay = parse_relay(relay).map_err(|_| PairError::BadAnswer("it names no relay"))?;
        let left_ms = expires_ms.saturating_sub(now_ms);
        if left_ms < MIN_REMAINING_MS {
            return Err(PairError::ShortLived { left_ms });
        }
        Ok(OperatorPart { relay, name, connect_token, expires_ms })
    }

    /// The part in the form of the operator's file, for a message.
    pub(crate) fn wire(&self) -> PartRef<'_> {
        PartRef {
            relay: relay_name(&self.relay),
            name: &self.name,
            connect_token: self.connect_token(),
            expires: self.expires_ms,
        }
    }

    /// A part of that form, checked at `now_ms`.
    pub(crate) fn from_wire(stored: PartStored, now_ms: i64) -> Result<OperatorPart, PairError> {
        let PartStored { relay, name, connect_token, expires } = stored;
        OperatorPart::checked(&relay, name, Zeroizing::new(connect_token), expires, now_ms)
    }
}

/// `operator-<label>.json`, for a label that T-076 accepts as a name.
pub fn file_name(label: &str) -> Result<String, PairError> {
    check_node_name(label).map_err(|why| PairError::BadLabel(format!("the label {why}")))?;
    Ok(format!("operator-{label}.json"))
}

/// Keep `part` under `label`, in the first cache directory that takes a
/// private file; a part kept before under it is replaced.
pub fn store(label: &str, part: &OperatorPart) -> Result<PathBuf, PairError> {
    store_in_first(&cache::candidate_dirs(), label, part)
}

/// [`store`] over explicit directories (for tests).
pub fn store_in_first(dirs: &[PathBuf], label: &str, part: &OperatorPart) -> Result<PathBuf, PairError> {
    let name = file_name(label)?;
    let body = Zeroizing::new(serde_json::to_vec(&part.wire()).map_err(|e| PairError::Store(e.to_string()))?);
    cache::store_file_in_first(dirs, &name, &body).map_err(PairError::Store)
}

/// The part kept under `label`, if any. Its expiry is not checked here: a
/// caller says so with the remedy.
pub fn load(label: &str) -> Result<Option<OperatorPart>, PairError> {
    load_from(&cache::read_dirs(), label)
}

/// [`load`] over explicit directories (for tests).
pub fn load_from(dirs: &[PathBuf], label: &str) -> Result<Option<OperatorPart>, PairError> {
    let Some(text) = cache::load_file_from(dirs, &file_name(label)?) else { return Ok(None) };
    let text = Zeroizing::new(text);
    let what = format!("the operator's part stored under {label:?}");
    let stored: PartStored =
        serde_json::from_str(&text).map_err(|_| PairError::Store(format!("{what} is not readable")))?;
    let PartStored { relay, name, connect_token, expires } = stored;
    let connect_token = Zeroizing::new(connect_token);
    check_node_name(&name).map_err(|_| PairError::Store(format!("{what} names no pair")))?;
    if !valid_token(&connect_token) {
        return Err(PairError::Store(format!("{what} holds no usable connect token")));
    }
    let relay = parse_relay(&relay).map_err(|_| PairError::Store(format!("{what} names no relay")))?;
    Ok(Some(OperatorPart { relay, name, connect_token, expires_ms: expires }))
}

/// Forget the part kept under `label`, in each directory where it is ours.
pub fn remove(label: &str) -> Result<(), PairError> {
    cache::remove_named_from(&cache::read_dirs(), &file_name(label)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::Relay;

    const NAME: &str = "0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
    const NOW: i64 = 1_800_000_000_000;

    fn part(expires_ms: i64) -> Result<OperatorPart, PairError> {
        OperatorPart::checked("relay.example.org", NAME.into(), Zeroizing::new(TOKEN.into()), expires_ms, NOW)
    }

    #[test]
    fn a_part_that_came_is_checked_as_a_pairs_answer() {
        let good = part(NOW + 3_600_000).unwrap();
        assert_eq!(good.relay, Relay { host: "relay.example.org".into(), port: 443 });
        assert!(matches!(part(NOW + 60_000), Err(PairError::ShortLived { .. })));
        let bad_name = OperatorPart::checked("r.example", "../x".into(), Zeroizing::new(TOKEN.into()), NOW * 2, NOW);
        assert!(matches!(bad_name, Err(PairError::BadAnswer(_))));
        let bad_token = OperatorPart::checked("r.example", NAME.into(), Zeroizing::new("no".into()), NOW * 2, NOW);
        assert!(matches!(bad_token, Err(PairError::BadAnswer(_))));
        assert!(!format!("{good:?}").contains(TOKEN));
    }

    #[test]
    fn a_part_kept_under_a_label_is_read_back_and_replaced_and_forgotten() {
        let dir = std::env::temp_dir().join(format!("podssh-part-{}", std::process::id()));
        cache::private_dir(&dir).unwrap();
        let dirs = [dir.clone()];
        assert!(load_from(&dirs, "lab").unwrap().is_none());
        let path = store_in_first(&dirs, "lab", &part(NOW + 3_600_000).unwrap()).unwrap();
        assert!(path.ends_with("operator-lab.json"));
        let read = load_from(&dirs, "lab").unwrap().unwrap();
        assert_eq!((read.name.as_str(), read.connect_token(), read.expires_ms), (NAME, TOKEN, NOW + 3_600_000));
        store_in_first(&dirs, "lab", &part(NOW + 7_200_000).unwrap()).unwrap();
        assert_eq!(load_from(&dirs, "lab").unwrap().unwrap().expires_ms, NOW + 7_200_000);
        cache::remove_named_from(&dirs, &file_name("lab").unwrap());
        assert!(load_from(&dirs, "lab").unwrap().is_none());
        assert!(file_name("../lab").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
