//! The network check of each Tailscale mode, before the start (T-102): the
//! DERP servers that `tcp` tries, read from Tailscale's own default map, the
//! proxy of the checks, and a run in which no check passes, so no node
//! starts. The proxy there refuses on the loopback: no test here leaves the
//! machine.
#![cfg(feature = "ts")]

mod cleanup;

use podssh_cli::dispatch::{run, Streams};
use podssh_cli::tree::parse;
use podssh_cli::ts::probe::{derp_servers, proxy_choice};
use podssh_ws::ProxyChoice;

/// The default DERP map as login.tailscale.com served it on 2026-10-10.
const DEFAULT_MAP: &[u8] = include_bytes!("fixtures/derpmap-default-2026-10-10.json");

fn servers(map: &str, most: usize) -> Vec<(String, u16)> {
    derp_servers(map.as_bytes(), most)
}

fn server(host: &str, port: u16) -> (String, u16) {
    (host.to_string(), port)
}

#[test]
fn the_default_map_gives_one_server_of_each_first_region() {
    assert_eq!(
        derp_servers(DEFAULT_MAP, 3),
        [server("derp1f.tailscale.com", 443), server("derp2d.tailscale.com", 443), server("derp3e.tailscale.com", 443)]
    );
    // One for each of its 28 regions, and no more.
    assert_eq!(derp_servers(DEFAULT_MAP, 100).len(), 28);
}

#[test]
fn servers_for_stun_or_tests_and_regions_to_avoid_are_passed_over() {
    let map = r#"{"Regions":{
        "10":{"RegionID":10,"Nodes":[
            {"Name":"10a","HostName":"stun.example","STUNOnly":true},
            {"Name":"10b","HostName":"derp10b.example","DERPPort":8443}]},
        "2":{"RegionID":2,"Avoid":true,"Nodes":[{"Name":"2a","HostName":"avoid.example"}]},
        "3":{"RegionID":3,"Nodes":[
            {"Name":"3a","HostName":"test.example","InsecureForTests":true},
            {"Name":"3b","HostName":"off.example","DERPPort":-1},
            {"Name":"3c","HostName":"zero.example","DERPPort":0}]},
        "4":{"RegionID":4,"Nodes":[{"Name":"4a","HostName":"  "}]},
        "x":{"Nodes":[{"HostName":"unnumbered.example"}]}
    }}"#;
    // In the order of the regions' numbers, not of the text.
    assert_eq!(servers(map, 5), [server("zero.example", 443), server("derp10b.example", 8443)]);
    assert_eq!(servers(map, 1), [server("zero.example", 443)]);
}

#[test]
fn a_map_that_cannot_be_read_names_no_server() {
    for map in ["not JSON", "{}", r#"{"Regions":[]}"#, r#"{"Regions":{"1":{"Nodes":{}}}}"#] {
        assert_eq!(servers(map, 3), [], "{map}");
    }
}

#[test]
fn the_checks_use_the_flags_proxy_with_the_forks_port_else_the_environments() {
    assert_eq!(proxy_choice(None), Ok(ProxyChoice::FromEnvironment));
    // A URL with no port means 8080 to the fork, so the check goes there too.
    let Ok(ProxyChoice::Via(proxy)) = proxy_choice(Some("http://proxy.example")) else { panic!("a proxy") };
    assert_eq!((proxy.host.as_str(), proxy.port), ("proxy.example", 8080));
    let Ok(ProxyChoice::Via(proxy)) = proxy_choice(Some("http://u:p@proxy.example:3128/")) else { panic!("a proxy") };
    assert_eq!((proxy.host.as_str(), proxy.port), ("proxy.example", 3128));
    assert!(proxy_choice(Some("socks5://proxy.example:1080")).is_err());
}

/// `podssh ts` with a key file, a state file to be, and a proxy that
/// refuses each connection; its exit, stdout, stderr, and whether the node
/// started (the fork makes the state file when it starts).
fn refused_run(mode: &str) -> (i32, String, String, bool) {
    let dir = std::env::temp_dir().join(format!("podssh-ts-probe-{mode}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let key = dir.join("key");
    std::fs::write(&key, b"tskey-auth-test-not-a-secret").unwrap();
    let state = dir.join("state.json");
    let argv = [
        "ts",
        "--ts-mode",
        mode,
        "--ts-auth-key-file",
        key.to_str().unwrap(),
        "--ts-state",
        state.to_str().unwrap(),
        // Port 1 on the loopback: nothing listens, so each dial is refused.
        "--ts-proxy",
        "http://127.0.0.1:1",
        "--timeout",
        "60s",
    ];
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let rc = run(&parse(owned), &mut Streams { out: &mut out, err: &mut err });
    (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap(), state.exists())
}

#[test]
fn no_mode_is_ready_when_no_check_passes_and_no_node_starts() {
    let (rc, out, err, started) = refused_run("auto");
    assert_eq!(rc, 78, "{err}");
    assert!(out.is_empty(), "stdout carries nothing: {out}");
    assert!(err.contains("podssh ts: mode tcp: the default DERP map from login.tailscale.com: "), "{err}");
    assert!(
        err.contains("podssh ts: mode relay tcp.ts.relay.ajam.dev:443: could not reach the proxy 127.0.0.1:1"),
        "{err}"
    );
    assert!(err.contains("podssh ts: no mode is ready."), "{err}");
    assert!(!started, "the node started: the state file was made");
}

#[test]
fn a_forced_mode_is_checked_alone() {
    let (rc, _, err, started) = refused_run("relay");
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("podssh ts: mode relay tcp.ts.relay.ajam.dev:443: could not reach the proxy"), "{err}");
    assert!(!err.contains("mode tcp"), "tcp was not asked for: {err}");
    assert!(!started, "the node started: the state file was made");
}

/// A proxy that opens each tunnel late, 1.8 s after the request, to a
/// server that then says nothing: each check ends at its bound, the 2 s that
/// remain of a run's, and not at 2 s more for the handshake that follows a
/// slow dial.
#[test]
fn a_slow_proxy_and_a_silent_server_fail_each_check_within_its_bound() {
    use std::io::{Read, Write};

    use podssh_cli::ts::probe::reach;
    use podssh_ts::chain::Verdict;
    use podssh_ts::config::TsMode;
    use podssh_ts::wait::Deadline;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read_exact(&mut byte).is_ok() {
                    head.push(byte[0]);
                }
                std::thread::sleep(std::time::Duration::from_millis(1800));
                let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                // Held open, never written to again: the server is silent.
                std::thread::sleep(std::time::Duration::from_secs(30));
            });
        }
    });
    let proxy = ProxyChoice::Via(podssh_ws::HttpProxy::parse(&format!("http://127.0.0.1:{port}")).unwrap());
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for mode in [TsMode::Tcp, TsMode::default_relay()] {
        let started = std::time::Instant::now();
        let verdict = rt.block_on(reach(&mode, &proxy, Deadline::after(Some(std::time::Duration::from_secs(2)))));
        let took = started.elapsed();
        assert!(matches!(verdict, Verdict::Fail(_)), "{mode:?}: {verdict:?}");
        // 2 s, with room; each step bounded alone would take 3.8 s.
        assert!(took < std::time::Duration::from_millis(3200), "{mode:?} took {took:?}: {verdict:?}");
    }
}

/// Live: from this machine, through the environment's proxy if it names
/// one, Tailscale's default map names a DERP server that answers, and so
/// does the relay host. Only TLS handshakes; nothing registers.
#[test]
#[ignore = "live: login.tailscale.com, a stock DERP server and the relay host"]
fn both_checks_pass_from_this_machine() {
    use podssh_cli::ts::probe::reach;
    use podssh_ts::chain::Verdict;
    use podssh_ts::config::TsMode;
    use podssh_ts::wait::Deadline;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for mode in [TsMode::Tcp, TsMode::default_relay()] {
        let started = std::time::Instant::now();
        let verdict = rt.block_on(reach(&mode, &ProxyChoice::FromEnvironment, Deadline::after(None)));
        eprintln!("{mode:?}: {verdict:?} in {} ms", started.elapsed().as_millis());
        assert_eq!(verdict, Verdict::Ok, "{mode:?}");
    }
}
