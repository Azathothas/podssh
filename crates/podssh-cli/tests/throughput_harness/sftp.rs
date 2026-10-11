//! SFTP through a cell (T-140): `podssh sftp` puts a file of the run's bytes,
//! then, in a session of its own, gets it back, each with the requests in
//! flight and the size of each that `-R` and `-B` give. The rate of each copy
//! is the one that its `-v` says: its bytes over the time from the first
//! request to the last reply, before the digest is read. A session carries
//! one copy and its digest, within the relay's 64 MiB of a session.

use std::io::Read;
use std::process::Stdio;
use std::time::Instant;

use super::{Cell, Session, RUN_LIMIT};

/// The file that each put sends, made once in the session's home, where the
/// test's `sftp-server` runs.
const FILE: &str = "tp-sftp.bin";

/// The arguments of `podssh sftp` for `cell`, whose arguments are those of
/// `podssh ssh`: the verb, and `-p` as sftp's `-P`.
fn sftp_args(cell: &Cell, batch: &str, requests: usize, len: u32) -> Vec<String> {
    let mut args = vec!["sftp".to_string(), "-b".into(), batch.into(), "-v".into()];
    args.extend(["-R".to_string(), requests.to_string(), "-B".into(), len.to_string()]);
    args.extend(cell.args.iter().skip(1).map(|a| if a == "-p" { "-P".to_string() } else { a.clone() }));
    args
}

/// The rate that `-v` says of the copy of `source`, in MiB/s.
fn said_rate(said: &str, source: &str) -> Option<f64> {
    said.lines()
        .filter(|l| l.contains(&format!("{source}: ")) && l.contains(" bytes in "))
        .find_map(|l| l.trim_end().strip_suffix(" MiB/s")?.rsplit(", ").next()?.parse().ok())
}

/// One `podssh sftp` with the batch `lines`, within the run's limit; what
/// it said on stderr, or why it failed.
fn run_batch(s: &Session, cell: &Cell, lines: &str, requests: usize, len: u32) -> Result<String, String> {
    let batch = s.home.join("tp-batch");
    std::fs::write(&batch, lines).map_err(|e| e.to_string())?;
    let mut child = s
        .command(&sftp_args(cell, &batch.display().to_string(), requests, len))
        .current_dir(&s.home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("podssh: {e}"))?;
    let mut stderr = child.stderr.take().expect("stderr");
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let end = Instant::now() + RUN_LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() > end {
            let _ = child.kill();
            break child.wait().map_err(|e| e.to_string())?;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let said = said.join().unwrap_or_default();
    if !status.success() {
        let last = said.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no message");
        return Err(format!("exit {:?}: {last}", status.code()));
    }
    Ok(said)
}

/// A put of `bytes` and a get of them back, in `cell`, with `requests` in
/// flight of `len` bytes each: MiB/s up and down, or why not.
pub fn sftp_run(s: &Session, cell: &Cell, requests: usize, len: u32, bytes: u64) -> Result<(f64, f64), String> {
    let file = s.home.join(FILE);
    if std::fs::metadata(&file).map(|m| m.len()).ok() != Some(bytes) {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let data: Vec<u8> = (0..bytes)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        std::fs::write(&file, data).map_err(|e| e.to_string())?;
    }
    let said = run_batch(s, cell, &format!("put {FILE} tp-put.bin\n"), requests, len)?;
    let up = said_rate(&said, FILE).ok_or_else(|| format!("no rate of the put: {said}"))?;
    let said = run_batch(s, cell, "get tp-put.bin tp-got.bin\n", requests, len)?;
    let down = said_rate(&said, "tp-put.bin").ok_or_else(|| format!("no rate of the get: {said}"))?;
    let back = std::fs::read(s.home.join("tp-got.bin")).map_err(|e| e.to_string())?;
    if back.len() as u64 != bytes {
        return Err(format!("{} of {bytes} bytes came back", back.len()));
    }
    Ok((up, down))
}

#[cfg(test)]
mod tests {
    use super::said_rate;

    #[test]
    fn the_rate_is_read_from_the_line_of_its_copy() {
        let said = "debug1: tp-sftp.bin: writes of 32768 bytes, 4 in flight\n\
                    tp-sftp.bin: 20971520 bytes in 4.000 s, 5.00 MiB/s\n\
                    tp-put.bin: 20971520 bytes in 2.000 s, 10.00 MiB/s\n";
        assert_eq!(said_rate(said, "tp-sftp.bin"), Some(5.0));
        assert_eq!(said_rate(said, "tp-put.bin"), Some(10.0));
        assert_eq!(said_rate(said, "other"), None);
    }
}
