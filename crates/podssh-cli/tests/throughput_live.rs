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
//! (a pair, and `podssh node` in front of the test's server), the forward
//! road through the live relay's own loop to a node of its own (each byte
//! crosses the relay twice: a lower bound, the operator's decision of
//! 2026-10-31), and with
//! `iroh-test` the iroh road through iroh's relay server on the loopback.
//! `PODSSH_THROUGHPUT_MIB` sets the MiB of each run in each direction (20
//! by default); the live run of T-251 takes 100, 500 MiB a direction in a
//! cell (the operator, 2026-10-10: Q38).
//!
//! Only when a variable names their target (Q38, `docs/decisions.md`):
//! `PODSSH_THROUGHPUT_SSH` (`USER@HOST[:PORT]`, a POSIX server, with the key
//! of `PODSSH_THROUGHPUT_KEY`) for the forward road through the live relay
//! and the direct road; `PODSSH_THROUGHPUT_IROH_RELAY` for the iroh road
//! through those relays.

mod ssh_harness;
mod throughput_harness;

use podssh_ssh::sftp::Pipeline;
use throughput_harness::{cp_run, cp_tree_run, measure, sftp_run, Cell, Far, Session};

const MIB: u64 = 1 << 20;
/// Each run's MiB in each direction, when `PODSSH_THROUGHPUT_MIB` sets none.
const RUN_MIB: u64 = 20;
const RUNS: usize = 5;

/// Each run's bytes, in each direction: a size that does not parse is said
/// and not used, so that a run never measures an unknown size.
fn run_bytes() -> u64 {
    let Ok(text) = std::env::var("PODSSH_THROUGHPUT_MIB") else { return RUN_MIB * MIB };
    match text.trim().parse::<u64>() {
        Ok(mib) if (1..=4096).contains(&mib) => mib * MIB,
        _ => panic!("PODSSH_THROUGHPUT_MIB={text:?}: MiB from 1 to 4096"),
    }
}

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
                let skipped =
                    Cell { name, args: Vec::new(), far: Far::Test, env: Vec::new(), must_say: None, through: None };
                table.push_str(&report(&skipped, &[], &[], Some(&why)));
                continue;
            }
        };
        match measure(session, &cell, RUNS, run_bytes()) {
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
#[ignore = "a measurement: 200 MiB a cell, by default, through this machine's loopback"]
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
    cells.push(Cell::relay_loop(&session));
    cells.extend(Cell::named(&session));
    println!("\n{}", table(&session, cells));
}

/// The forward road through the live relay's own loop alone (the operator's
/// decision of 2026-10-31), as `throughput_on_each_road` measures it.
#[test]
#[ignore = "network: the forward road through the live relay's own loop, to a node"]
fn throughput_through_the_relay_s_own_loop() {
    let session = Session::start("loop");
    println!("\n{}", table(&session, vec![Cell::relay_loop(&session)]));
}

/// The pipelines of the SFTP cells (T-140): requests in flight, and the
/// bytes of each; 261120 is OpenSSH's limit, which the window holds twice.
const PIPES: [(usize, u32); 6] = [(1, 32768), (4, 32768), (16, 32768), (64, 32768), (1, 261120), (2, 261120)];

/// SFTP by the requests in flight and their size (T-140): a put and a get of
/// the run's bytes for each pipeline, on the loopback, through the stand-in
/// relay with 50 ms each way, a round trip of a far relay, and through the
/// live relay to a node in front of the test's server, which `sftp` names
/// as `node://` (T-296); the rate of each is what podssh's `-v` says.
#[test]
#[ignore = "network: SFTP on the loopback, through the stand-in relay with a delay, and to a node on the live relay"]
fn sftp_throughput_by_requests_in_flight() {
    if ssh_harness::sftp::server_path().is_none() {
        println!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let session = Session::start("sftp");
    let bytes = run_bytes();
    println!(
        "
{} MiB a copy
",
        bytes >> 20
    );
    println!("| Cell | Requests | Bytes each | In flight | Put MiB/s | Get MiB/s |");
    println!("| --- | --- | --- | --- | --- | --- |");
    let delayed = Cell::fake_relay_mode(&session, "delay:50", "forward road, the stand-in relay, 50 ms each way");
    let node = Cell::reverse(&session);
    for cell in [Ok(Cell::direct(&session)), delayed, node] {
        let cell = match cell {
            Ok(cell) => cell,
            Err((name, why)) => {
                println!("| {name} | skipped: {why} | | | | |");
                continue;
            }
        };
        for (requests, len) in PIPES {
            let depth = Pipeline { requests, len, ..Pipeline::default() }.depth(len);
            match sftp_run(&session, &cell, requests, len, bytes) {
                Ok((up, down)) => println!("| {} | {requests} | {len} | {depth} | {up:.2} | {down:.2} |", cell.name),
                Err(why) => println!("| {} | {requests} | {len} | {depth} | failed: {why} | |", cell.name),
            }
        }
    }
}

/// `cp --parallel K` (T-141): a copy up and a copy down of the run's bytes,
/// 24 MiB at least so that a file has three chunks, with 1 and 4 tasks, on
/// the loopback and through the stand-in relay with 50 ms each way.
#[test]
#[ignore = "a measurement: cp on the loopback, and through the stand-in relay with a delay"]
fn cp_throughput_by_tasks() {
    if ssh_harness::sftp::server_path().is_none() {
        println!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let session = Session::start("cp");
    let bytes = run_bytes().max(24 << 20);
    println!("\n{} MiB a copy\n", bytes >> 20);
    println!("| Cell | Tasks | Up MiB/s | Down MiB/s |");
    println!("| --- | --- | --- | --- |");
    let delayed = Cell::fake_relay_mode(&session, "delay:50", "forward road, the stand-in relay, 50 ms each way");
    for cell in [Ok(Cell::direct(&session)), delayed] {
        let cell = match cell {
            Ok(cell) => cell,
            Err((name, why)) => {
                println!("| {name} | skipped: {why} | | |");
                continue;
            }
        };
        for tasks in [1, 2, 4] {
            match cp_run(&session, &cell, tasks, bytes) {
                Ok((up, down)) => println!("| {} | {tasks} | {up:.2} | {down:.2} |", cell.name),
                Err(why) => println!("| {} | {tasks} | failed: {why} | |", cell.name),
            }
        }
    }
}

/// Many small files through the relay (T-297, by T-157's method; T-251):
/// `cp -r --parallel K` of 200 files of 16 KiB up and back down, with 1 and
/// 8 tasks, through the stand-in relay with 50 ms each way and through the
/// live relay to a node in front of the test's server; files a second, the
/// connection's setup counted.
#[test]
#[ignore = "network: cp of many small files through the stand-in relay with a delay, and to a node on the live relay"]
fn cp_small_files_by_tasks() {
    if ssh_harness::sftp::server_path().is_none() {
        println!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let session = Session::start("cp-small");
    println!("\n200 files of 16 KiB a copy\n");
    println!("| Cell | Tasks | Up files/s | Down files/s |");
    println!("| --- | --- | --- | --- |");
    let delayed = Cell::fake_relay_mode(&session, "delay:50", "forward road, the stand-in relay, 50 ms each way");
    for cell in [delayed, Cell::reverse(&session)] {
        let cell = match cell {
            Ok(cell) => cell,
            Err((name, why)) => {
                println!("| {name} | skipped: {why} | | |");
                continue;
            }
        };
        for tasks in [1, 8] {
            match cp_tree_run(&session, &cell, tasks, 200, 16 * 1024) {
                Ok((up, down)) => println!("| {} | {tasks} | {up:.1} | {down:.1} |", cell.name),
                Err(why) => println!("| {} | {tasks} | failed: {why} | |", cell.name),
            }
        }
    }
}
