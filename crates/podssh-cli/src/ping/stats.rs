//! The numbers of `podssh ping` (T-053): the minimum, the median, the 95th
//! percentile and the maximum of a set of round trips, and the sizes that
//! `--size` takes.

use std::time::Duration;

/// The largest `--size`: down and up together stay under the relay's
/// 64 MiB for one session (`docs/relay.md`).
pub const MAX_SIZE: u64 = 30 * 1024 * 1024;
/// The default `--size`.
pub const DEFAULT_SIZE: u64 = 8 * 1024 * 1024;

/// A summary of round trips, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

impl Summary {
    /// The summary of `samples`, by the nearest rank; `None` for none.
    pub fn of(samples: &[Duration]) -> Option<Summary> {
        if samples.is_empty() {
            return None;
        }
        let mut ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        ms.sort_by(f64::total_cmp);
        let rank = |p: f64| ms[((p * ms.len() as f64).ceil() as usize).clamp(1, ms.len()) - 1];
        Some(Summary { min: ms[0], p50: rank(0.50), p95: rank(0.95), max: ms[ms.len() - 1] })
    }

    /// `min 1.2, p50 1.5, p95 2.0, max 2.1 ms`.
    pub fn shown(&self) -> String {
        format!("min {:.1}, p50 {:.1}, p95 {:.1}, max {:.1} ms", self.min, self.p50, self.p95, self.max)
    }

    pub fn json(&self) -> serde_json::Value {
        let round = |v: f64| (v * 1000.0).round() / 1000.0;
        serde_json::json!({ "min_ms": round(self.min), "p50_ms": round(self.p50), "p95_ms": round(self.p95), "max_ms": round(self.max) })
    }
}

/// `--size`: bytes, or a number with K, M or G (KiB, MiB, GiB), more than
/// 0 and at most [`MAX_SIZE`].
pub fn size(value: &str) -> Result<u64, String> {
    let v = value.trim();
    let upper = v.to_ascii_uppercase();
    let trimmed = upper.strip_suffix("IB").or_else(|| upper.strip_suffix('B')).unwrap_or(&upper);
    let (number, unit) = match trimmed.char_indices().last() {
        Some((at, 'K')) => (&trimmed[..at], 1024),
        Some((at, 'M')) => (&trimmed[..at], 1024 * 1024),
        Some((at, 'G')) => (&trimmed[..at], 1024 * 1024 * 1024),
        _ => (trimmed, 1),
    };
    let bytes = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .ok_or_else(|| format!("--size {value}: a number of bytes, with K, M or G"))?;
    if bytes == 0 {
        return Err(format!("--size {value}: more than 0 bytes"));
    }
    if bytes > MAX_SIZE {
        return Err(format!(
            "--size {value}: at most 30M, so that both ways stay under the relay's 64 MiB for one session"
        ));
    }
    Ok(bytes)
}

/// `8.0 MiB`.
pub fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_take_units_and_stay_under_the_relays_limit() {
        assert_eq!(size("8M"), Ok(8 * 1024 * 1024));
        assert_eq!(size("512k"), Ok(512 * 1024));
        assert_eq!(size("30MiB"), Ok(MAX_SIZE));
        assert_eq!(size("1048576"), Ok(1024 * 1024));
        assert!(size("31M").unwrap_err().contains("at most 30M"));
        assert!(size("40M").unwrap_err().contains("64 MiB"));
        assert!(size("1G").is_err());
        assert!(size("0").unwrap_err().contains("more than 0"));
        assert!(size("ten").unwrap_err().contains("a number of bytes"));
        assert!(size("").is_err());
    }

    #[test]
    fn a_summary_ranks_its_samples() {
        let ms = |v: &[u64]| v.iter().map(|m| Duration::from_millis(*m)).collect::<Vec<_>>();
        let s = Summary::of(&ms(&[5, 1, 3, 2, 4, 10, 9, 8, 7, 6])).unwrap();
        assert_eq!((s.min, s.p50, s.p95, s.max), (1.0, 5.0, 10.0, 10.0));
        let one = Summary::of(&ms(&[7])).unwrap();
        assert_eq!((one.min, one.p50, one.p95, one.max), (7.0, 7.0, 7.0, 7.0));
        assert_eq!(Summary::of(&[]), None);
        assert_eq!(s.shown(), "min 1.0, p50 5.0, p95 10.0, max 10.0 ms");
    }
}
