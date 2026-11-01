//! Throughput of the Tor road (T-353, step 4, by the method of T-157: a
//! fixed size each way, three runs, the median), through chutney's private
//! network on this host, which `PODSSH_TEST_TOR_NETWORK` names
//! (`scripts/tor-net.sh` starts it): Arti and podssh's own part, the
//! circuits on the loopback; then C tor's own client of the same network,
//! through its SOCKS port, as the figure without podssh. The operator's ruling of Q60 lets a test reach
//! Tor's public network for one stream to `github.com:22`, which takes no
//! bytes of a test, so the public network's figure is its time to the first
//! byte (`tests/tor_live.rs`). On request only:
//!
//! ```sh
//! PODSSH_TEST_TOR_NETWORK=$(sh scripts/tor-net.sh start .work/tor-net) \
//!     cargo test -p podssh-cli --features tor --test tor_throughput -- --ignored --nocapture
//! ```
#![cfg(all(feature = "tor", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const NETWORK_ENV: &str = "PODSSH_TEST_TOR_NETWORK";
/// The bytes of each run, each way.
const SIZE: usize = 16 << 20;
const RUNS: usize = 3;
/// A run's bound, the bootstrap of its own process included.
const LIMIT: Duration = Duration::from_secs(300);
const READY: &[u8] = b"ready\n";

/// A service on the loopback that an exit reaches: it says `ready` once a
/// stream came through, then takes `SIZE` bytes and says `done` (`u`), or
/// sends `SIZE` bytes (`d`).
fn service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut way = [0u8; 1];
                if stream.read_exact(&mut way).is_err() || stream.write_all(READY).is_err() {
                    return;
                }
                let mut block = vec![0x5au8; 64 << 10];
                let mut left = SIZE;
                while left > 0 {
                    let n = left.min(block.len());
                    let moved = match way[0] {
                        b'u' => stream.read(&mut block[..n]),
                        _ => stream.write_all(&block[..n]).map(|_| n),
                    };
                    match moved {
                        Ok(0) | Err(_) => return,
                        Ok(n) => left -= n,
                    }
                }
                if way[0] == b'u' {
                    let _ = stream.write_all(b"done\n");
                }
                let _ = stream.flush();
            });
        }
    });
    port
}

/// One run of `way` through `podssh proxy tor://127.0.0.1:PORT`: the MiB/s
/// from the service's `ready` to the last byte, the circuit already built.
fn run(home: &Path, network: &std::ffi::OsStr, port: u16, way: u8) -> f64 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["proxy", &format!("tor://127.0.0.1:{port}")])
        .env("HOME", home)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_CACHE_DIR", home.join("cache"))
        .env("PODSSH_TOR_NETWORK", network)
        .env("PODSSH_TOR_PORTS", "any")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let err = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = BufReader::new(err).read_to_string(&mut text);
        text
    });
    let watch = child.id();
    let guard = std::thread::spawn(move || {
        std::thread::sleep(LIMIT);
        // SAFETY: a signal to the child that this test started.
        unsafe { libc::kill(watch as i32, libc::SIGKILL) };
    });
    let figure = transfer(&mut input, &mut output, way);
    drop(input);
    let _ = child.kill();
    let _ = child.wait();
    let text = said.join().unwrap_or_default();
    drop(guard);
    assert!(text.contains("in the network of"), "not through the private network: {text}");
    figure
}

/// `way` over a stream to the service: the MiB/s from its `ready` to the
/// last byte.
fn transfer(input: &mut dyn Write, output: &mut dyn BufRead, way: u8) -> f64 {
    input.write_all(&[way]).unwrap();
    let mut line = Vec::new();
    output.read_until(b'\n', &mut line).unwrap();
    assert_eq!(line, READY, "no stream through the network");
    let start = Instant::now();
    if way == b'u' {
        let block = vec![0xa5u8; 64 << 10];
        for _ in 0..SIZE / block.len() {
            input.write_all(&block).unwrap();
        }
        input.flush().unwrap();
        line.clear();
        output.read_until(b'\n', &mut line).unwrap();
        assert_eq!(line, b"done\n", "the service took fewer bytes than sent");
    } else {
        let mut got = 0usize;
        let mut block = vec![0u8; 64 << 10];
        while got < SIZE {
            match output.read(&mut block).unwrap() {
                0 => break,
                n => got += n,
            }
        }
        assert_eq!(got, SIZE, "fewer bytes came than the service sent");
    }
    SIZE as f64 / (1 << 20) as f64 / start.elapsed().as_secs_f64()
}

/// The SOCKS port of a client of C tor in the network of `network`
/// (chutney's nodes whose name ends in `c`), to measure the same circuits
/// without podssh.
fn c_tor_client(network: &std::ffi::OsStr) -> Option<SocketAddr> {
    let nodes = Path::new(network).parent()?;
    let mut dirs: Vec<_> = std::fs::read_dir(nodes).ok()?.flatten().map(|e| e.path()).collect();
    dirs.sort();
    dirs.iter().filter(|d| d.to_string_lossy().ends_with('c')).find_map(|d| {
        let torrc = std::fs::read_to_string(d.join("torrc")).ok()?;
        torrc.lines().find_map(|l| l.strip_prefix("SocksPort ")?.trim().parse().ok())
    })
}

/// One run of `way` through C tor's client at `socks` (SOCKS5, no login).
fn c_tor_run(socks: SocketAddr, port: u16, way: u8) -> f64 {
    let mut stream = TcpStream::connect(socks).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).unwrap();
    assert_eq!(chosen, [5, 0], "the SOCKS port took no method without a login");
    let [hi, lo] = port.to_be_bytes();
    stream.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, hi, lo]).unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "C tor's client did not open the stream: {reply:?}");
    let mut input = stream.try_clone().unwrap();
    let mut output = BufReader::new(stream);
    transfer(&mut input, &mut output, way)
}

fn median(mut figures: Vec<f64>) -> f64 {
    figures.sort_by(f64::total_cmp);
    figures[figures.len() / 2]
}

#[test]
#[ignore = "a private Tor network of chutney on this host: scripts/tor-net.sh"]
fn throughput_through_a_private_tor_network() {
    let Some(network) = std::env::var_os(NETWORK_ENV).filter(|v| !v.is_empty()) else {
        panic!("{NETWORK_ENV} is not set: start a network with scripts/tor-net.sh");
    };
    let home = std::env::temp_dir().join(format!("podssh-tor-throughput-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let port = service();
    let up: Vec<f64> = (0..RUNS).map(|_| run(&home, &network, port, b'u')).collect();
    let down: Vec<f64> = (0..RUNS).map(|_| run(&home, &network, port, b'd')).collect();
    let mib = SIZE >> 20;
    println!("tor throughput, {mib} MiB a run, through chutney's network: up {up:.2?} MiB/s, down {down:.2?} MiB/s");
    println!("tor throughput: p50 up {:.2} MiB/s, p50 down {:.2} MiB/s", median(up), median(down));
    // The same circuits through C tor's own client: the network's part.
    match c_tor_client(&network) {
        Some(socks) => {
            let up: Vec<f64> = (0..RUNS).map(|_| c_tor_run(socks, port, b'u')).collect();
            let down: Vec<f64> = (0..RUNS).map(|_| c_tor_run(socks, port, b'd')).collect();
            println!("C tor's client at {socks}: up {up:.2?} MiB/s, down {down:.2?} MiB/s");
            println!("C tor's client: p50 up {:.2} MiB/s, p50 down {:.2} MiB/s", median(up), median(down));
        }
        None => println!("no client of C tor in the network: no figure without podssh"),
    }
    let _ = std::fs::remove_dir_all(&home);
}
