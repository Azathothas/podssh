//! The road that last reached each node from this host (T-435), for `podssh
//! status --net`: by the node's label, the road that answered first, its time
//! to the far end's first bytes and when; and the last race that found no
//! road, with why. Each race of `ssh`, of the copies and of `ping` to
//! `node://NAME` writes it, and so does the pair's road alone, in the cache's
//! `net-roads.json`. A record that cannot be kept costs `status` its word,
//! nothing else, so a write that fails is ignored. It holds no secret: labels,
//! the names of roads, times and reasons.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Map, Value};

/// The file of the record in the cache's directories.
pub const FILE: &str = "net-roads.json";
/// The most labels kept: the one whose last word is the oldest goes first.
pub const MOST: usize = 256;
/// The most characters of a reason that are kept.
const WHY_MOST: usize = 400;
/// The longest label kept: a pair's label or a member's name is shorter.
const LABEL_MOST: usize = 200;

/// A race that a road won.
#[derive(Debug, Clone, PartialEq)]
pub struct Reached {
    /// The road, in the words of the race (`the pair's road`).
    pub road: String,
    /// From the start of the race to the far end's first bytes.
    pub ms: f64,
    /// When, in milliseconds since 1970.
    pub at_ms: i64,
}

/// A race that no road won.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    pub why: String,
    pub at_ms: i64,
}

/// What the record holds of one label.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Entry {
    pub reached: Option<Reached>,
    pub missed: Option<Missed>,
}

impl Entry {
    fn read(value: &Value) -> Entry {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        let number = |key: &str| value.get(key).and_then(Value::as_i64);
        let reached = match (text("road"), value.get("ms").and_then(Value::as_f64), number("at_ms")) {
            (Some(road), Some(ms), Some(at_ms)) => Some(Reached { road, ms, at_ms }),
            _ => None,
        };
        let missed = text("missed").zip(number("missed_at_ms")).map(|(why, at_ms)| Missed { why, at_ms });
        Entry { reached, missed }
    }

    fn value(&self) -> Value {
        let mut object = Map::new();
        if let Some(reached) = &self.reached {
            object.insert("road".into(), json!(reached.road));
            object.insert("ms".into(), json!(reached.ms));
            object.insert("at_ms".into(), json!(reached.at_ms));
        }
        if let Some(missed) = &self.missed {
            object.insert("missed".into(), json!(missed.why));
            object.insert("missed_at_ms".into(), json!(missed.at_ms));
        }
        Value::Object(object)
    }

    /// When a race last wrote it.
    fn latest(&self) -> i64 {
        let reached = self.reached.as_ref().map_or(i64::MIN, |r| r.at_ms);
        reached.max(self.missed.as_ref().map_or(i64::MIN, |m| m.at_ms))
    }

    /// Whether the last race reached the node; `None` when none was kept.
    pub fn last_reached(&self) -> Option<bool> {
        match (&self.reached, &self.missed) {
            (None, None) => None,
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (Some(reached), Some(missed)) => Some(reached.at_ms >= missed.at_ms),
        }
    }
}

/// The record, by label.
pub type Records = BTreeMap<String, Entry>;

/// The record of the cache; an empty one when there is none, or one that
/// does not read.
pub fn load() -> Records {
    load_from(&podssh_relay::cache::candidate_dirs())
}

/// [`load`] over explicit directories (for tests).
pub fn load_from(dirs: &[PathBuf]) -> Records {
    let Some(text) = podssh_relay::cache::load_file_from(dirs, FILE) else { return Records::new() };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&text) else { return Records::new() };
    map.iter().map(|(label, value)| (label.clone(), Entry::read(value))).collect()
}

/// The race to the node `label` was won by `road`, `took` after its start.
pub fn reached(label: &str, road: &str, took: Duration) {
    reached_in(&podssh_relay::cache::candidate_dirs(), label, road, took, crate::pairs::now_ms());
}

/// No road of the race to the node `label` answered, for `why`.
pub fn missed(label: &str, why: &str) {
    missed_in(&podssh_relay::cache::candidate_dirs(), label, why, crate::pairs::now_ms());
}

/// [`reached`] over explicit directories, at `now_ms` (for tests).
pub fn reached_in(dirs: &[PathBuf], label: &str, road: &str, took: Duration, now_ms: i64) {
    let ms = (took.as_secs_f64() * 1_000_000.0).round() / 1000.0;
    change(dirs, label, |entry| entry.reached = Some(Reached { road: road.to_string(), ms, at_ms: now_ms }));
}

/// [`missed`] over explicit directories, at `now_ms` (for tests).
pub fn missed_in(dirs: &[PathBuf], label: &str, why: &str, now_ms: i64) {
    let line = podssh_ws::text::one_line(why);
    let why = match line.char_indices().nth(WHY_MOST) {
        Some((at, _)) => format!("{}...", &line[..at]),
        None => line,
    };
    change(dirs, label, |entry| entry.missed = Some(Missed { why, at_ms: now_ms }));
}

/// The record read again, `edit` done to the entry of `label`, the oldest
/// entries past [`MOST`] removed, and the record kept. Two runs at once may
/// each lose the other's word: a status then shows the race before.
fn change(dirs: &[PathBuf], label: &str, edit: impl FnOnce(&mut Entry)) {
    if dirs.is_empty() || label.is_empty() || label.len() > LABEL_MOST {
        return;
    }
    let mut records = load_from(dirs);
    edit(records.entry(label.to_string()).or_default());
    while records.len() > MOST {
        let oldest = records.iter().min_by_key(|(_, entry)| entry.latest()).map(|(label, _)| label.clone());
        let Some(oldest) = oldest else { break };
        records.remove(&oldest);
    }
    let object: Map<String, Value> = records.iter().map(|(label, entry)| (label.clone(), entry.value())).collect();
    let _ = podssh_relay::cache::store_file_in_first(dirs, FILE, Value::Object(object).to_string().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_793_577_600_000;

    /// A directory of the test, gone when it ends.
    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dir(tag: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("podssh-net-roads-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Dir(dir)
    }

    /// The road that won, then a race that found none: the miss is the last
    /// word, and the road stays beside it; a road that wins again is the
    /// last word again. The file holds the label, the road and the reason.
    #[test]
    fn the_last_race_is_the_word_and_the_road_that_won_stays() {
        let dir = dir("last");
        let dirs = vec![dir.0.clone()];
        assert!(load_from(&dirs).is_empty());
        reached_in(&dirs, "lab", "the pair's road", Duration::from_micros(84_250), NOW);
        let entry = &load_from(&dirs)["lab"];
        assert_eq!(entry.reached, Some(Reached { road: "the pair's road".into(), ms: 84.25, at_ms: NOW }));
        assert_eq!(entry.last_reached(), Some(true));
        missed_in(&dirs, "lab", "no road reached the node:\nthe pair's road: offline", NOW + 1000);
        let entry = &load_from(&dirs)["lab"];
        let said = "no road reached the node: the pair's road: offline".to_string();
        assert_eq!(entry.missed, Some(Missed { why: said, at_ms: NOW + 1000 }));
        assert!(entry.reached.is_some(), "the road that won stays");
        assert_eq!(entry.last_reached(), Some(false));
        reached_in(&dirs, "lab", "the DERP road", Duration::from_millis(9), NOW + 2000);
        assert_eq!(load_from(&dirs)["lab"].last_reached(), Some(true));
        let text = std::fs::read_to_string(dir.0.join(FILE)).unwrap();
        assert!(text.contains("\"road\":\"the DERP road\"") && text.contains("\"missed\":"), "{text}");
        std::fs::write(dir.0.join(FILE), "not json").unwrap();
        assert!(load_from(&dirs).is_empty(), "a record that does not read is none");
    }

    /// The record keeps [`MOST`] labels, the oldest word going first; no
    /// directory keeps nothing, and a long reason is cut.
    #[test]
    fn the_record_is_bounded_and_a_long_reason_is_cut() {
        let dir = dir("bound");
        let dirs = vec![dir.0.clone()];
        for i in 0..=MOST as i64 {
            reached_in(&dirs, &format!("n{i}"), "the pair's road", Duration::from_millis(5), NOW + i);
        }
        let records = load_from(&dirs);
        assert_eq!(records.len(), MOST);
        assert!(!records.contains_key("n0") && records.contains_key(&format!("n{MOST}")), "the oldest went");
        missed_in(&dirs, "n1", &"x".repeat(1000), NOW + 10_000);
        let why = &load_from(&dirs)["n1"].missed.clone().unwrap().why;
        assert_eq!(why.len(), WHY_MOST + 3, "{why}");
        missed_in(&[], "none", "kept nowhere", NOW);
        assert_eq!(Entry::default().last_reached(), None);
    }
}
