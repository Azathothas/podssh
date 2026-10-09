//! Throughput on each road (T-157), by one committed method. In each cell,
//! 5 runs, each a new `podssh ssh` and a new connection, of 20 MiB up and
//! then 20 MiB down, in separate sessions, 300 s at most each; then the
//! minimum, p50, p95 and maximum in MiB/s for each direction, with the line
//! of each run. The clock of a run starts when the far end is ready (the
//! `R` of its sink, or the first byte of its source) and stops at the last
//! byte, so the connection's setup is not counted.
//!
//! The statistics, and one small run on the loopback, are tested in each
//! test run. The measurement is ignored by default, as its cells reach the
//! network:
//!
//! ```sh
//! cargo test -p podssh-cli --test throughput_live -- --ignored --nocapture
//! cargo test -p podssh-cli --features iroh-test --test throughput_live -- --ignored --nocapture
//! ```
//!
//! The cells that run when nothing is set: the loopback (`--direct` to the
//! test's server: podssh's own limit), the forward road through
//! `scripts/fake-relay.py` on the loopback when Python and `openssl` are
//! found (the control of the relay), the reverse road through the live relay
//! (a pair, and `podssh node` in front of the test's server), and with
//! `iroh-test` the iroh road through iroh's relay server on the loopback.
//! Only when a variable names their target (Q38, `TODO/PROGRESS.md`):
//! `PODSSH_THROUGHPUT_SSH` (`USER@HOST[:PORT]`, a POSIX server, with the key
//! of `PODSSH_THROUGHPUT_KEY`) for the forward road through the live relay
//! and the direct road; `PODSSH_THROUGHPUT_IROH_RELAY` for the iroh road
//! through those relays.

mod ssh_harness;
mod throughput_harness;

use throughput_harness::{measure, Cell, Far, Session};

const MIB: u64 = 1 << 20;
/// Each run's bytes, in each direction.
const BYTES: u64 = 20 * MIB;
const RUNS: usize = 5;

/// The minimum, the 50th and 95th percentiles, and the maximum.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Summary {
    min: f64,
    p50: f64,
    p95: f64,
    max: f64,
}

/// The nearest-rank percentile `q` of `sorted`: the smallest value with at
/// least the share `q` of the sample at or below it.
fn rank(sorted: &[f64], q: f64) -> f64 {
    let k = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[k - 1]
}

fn summary(samples: &[f64]) -> Option<Summary> {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let (first, last) = (*sorted.first()?, *sorted.last()?);
    Some(Summary { min: first, p50: rank(&sorted, 0.50), p95: rank(&sorted, 0.95), max: last })
}

/// Whether `summarize` gives the figures of a known sample: 40 values in no
/// order, one value, and none.
fn right(summarize: impl Fn(&[f64]) -> Option<Summary>) -> bool {
    let sample: Vec<f64> = (1..=40).map(|i| f64::from((i * 17) % 40 + 1)).collect();
    summarize(&sample) == Some(Summary { min: 1.0, p50: 20.0, p95: 38.0, max: 40.0 })
        && summarize(&[7.0]) == Some(Summary { min: 7.0, p50: 7.0, p95: 7.0, max: 7.0 })
        && summarize(&[]).is_none()
}

#[test]
fn the_statistics_of_a_known_sample() {
    assert!(right(summary));
}

#[test]
fn a_planted_p95_that_takes_the_maximum_fails_the_check() {
    let planted = |samples: &[f64]| summary(samples).map(|s| Summary { p95: s.max, ..s });
    assert!(!right(planted), "the check cannot tell a p95 that is the maximum");
}

/// One small run each way on the loopback: the method itself works, with no
/// network.
#[test]
fn the_method_runs_on_the_loopback() {
    let session = Session::start("method");
    let cell = Cell::direct(&session);
    let up = throughput_harness::run(&session, &cell, true, MIB).expect("a run up");
    let down = throughput_harness::run(&session, &cell, false, MIB).expect("a run down");
    assert!(up > 0.0 && down > 0.0, "{up} {down}");
}

/// The table of one cell: each run's line, then the summary of each
/// direction, or why the cell did not run.
fn report(cell: &Cell, ups: &[f64], downs: &[f64], why: Option<&str>) -> String {
    let mut out = format!("cell: {}\n", cell.name);
    if let Some(why) = why {
        out.push_str(&format!("  skipped: {why}\n"));
        return out;
    }
    for (i, (up, down)) in ups.iter().zip(downs).enumerate() {
        out.push_str(&format!("  run {}: up {up:.2} MiB/s, down {down:.2} MiB/s\n", i + 1));
    }
    for (name, samples) in [("up", ups), ("down", downs)] {
        if let Some(s) = summary(samples) {
            out.push_str(&format!(
                "  {name}: min {:.2}, p50 {:.2}, p95 {:.2}, max {:.2} MiB/s ({} runs)\n",
                s.min,
                s.p50,
                s.p95,
                s.max,
                samples.len()
            ));
        }
    }
    out
}

/// Each cell measured, in a table.
fn table(session: &Session, cells: Vec<Result<Cell, (String, String)>>) -> String {
    let mut table = String::new();
    for cell in cells {
        let cell = match cell {
            Ok(cell) => cell,
            Err((name, why)) => {
                let skipped = Cell { name, args: Vec::new(), far: Far::Test };
                table.push_str(&report(&skipped, &[], &[], Some(&why)));
                continue;
            }
        };
        match measure(session, &cell, RUNS, BYTES) {
            Ok((ups, downs)) => table.push_str(&report(&cell, &ups, &downs, None)),
            Err(why) => table.push_str(&report(&cell, &[], &[], Some(&why))),
        }
    }
    table
}

/// The cells on this machine's loopback, which reach no network: podssh's
/// own limit, the stand-in relay, and with `iroh-test` iroh's relay server.
fn loopback_cells(session: &Session) -> Vec<Result<Cell, (String, String)>> {
    let cells = vec![Ok(Cell::direct(session)), Cell::fake_relay(session)];
    #[cfg(feature = "iroh-test")]
    let cells = {
        let mut cells = cells;
        cells.push(Cell::iroh_loopback(session));
        cells
    };
    cells
}

#[test]
#[ignore = "a measurement: 200 MiB a cell through this machine's loopback"]
fn throughput_on_the_loopback() {
    let session = Session::start("loopback");
    let cells = loopback_cells(&session);
    println!("\n{}", table(&session, cells));
}

#[test]
#[ignore = "network: the reverse road through the live relay, and the cells that variables name"]
fn throughput_on_each_road() {
    let session = Session::start("throughput");
    let mut cells = loopback_cells(&session);
    cells.push(Cell::reverse(&session));
    cells.extend(Cell::named(&session));
    println!("\n{}", table(&session, cells));
}
