//! The resumable layer with `PODSSH_RELAY_LAYER` unset (T-173): `podssh
//! proxy` to a relay host that the user named reads its offer once, keeps it
//! for a day, and takes the layer where it was offered, with no read of its
//! own after the first and no line; `no` takes the contract's road. A kept
//! offer whose host answers 404 for the layer's path is forgotten, with one
//! line, and the contract's road carries the session. On the layer, the end
//! of stdin keeps receiving, as on the contract's road.

use std::io::Write;
use std::net::TcpListener;
use std::process::Output;
use std::time::Duration;

use crate::throughput_harness::{Cell, Session};
use crate::{banner_target, ran_with, relay_flags, role, said};

/// `podssh proxy` to `127.0.0.1:port` through `flags`, with
/// `PODSSH_RELAY_LAYER` as `layer` gives it, unset where `None`.
fn proxy(s: &Session, flags: &[String], port: u16, layer: Option<&str>) -> Output {
    let mut args = vec!["proxy".to_string()];
    args.extend(flags.iter().cloned());
    args.extend(["127.0.0.1".into(), port.to_string()]);
    let mut cmd = s.command(&args);
    cmd.env_remove("PODSSH_RELAY_LAYER");
    let set: Vec<(&str, &str)> = layer.map(|value| ("PODSSH_RELAY_LAYER", value)).into_iter().collect();
    ran_with(cmd, &set)
}

/// The relay's events so far, one a line.
fn events(s: &Session) -> String {
    std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default()
}

/// How many lines of `events` are `line`.
fn count(events: &str, line: &str) -> usize {
    events.lines().filter(|l| l.trim() == line).count()
}

#[test]
fn unasked_the_layer_is_taken_where_the_role_offered_it_with_one_read_of_its_offer() {
    let s = Session::start("serve-layer-unasked");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let flags = relay_flags(&cell);
    let target = banner_target("SSH-2.0-unasked\r\n");
    for run in 1..=2 {
        let out = proxy(&s, &flags, target, None);
        let text = said(&out);
        assert!(out.status.success(), "run {run}: {text}; the role: {}", events(&s));
        assert!(text.contains("SSH-2.0-unasked"), "run {run}: the banner came: {text}");
        assert!(!text.contains("resumable layer"), "run {run}: no line where the user did not ask: {text}");
    }
    let seen = events(&s);
    assert_eq!(count(&seen, "upgrade layer"), 2, "each run took the layer: {seen}");
    assert_eq!(count(&seen, "upgrade"), 0, "no run took the contract's road: {seen}");
    assert_eq!(count(&seen, "relays.json"), 1, "the offer was read once, then kept: {seen}");
    // `no`: the contract's road, with the offer kept.
    let out = proxy(&s, &flags, target, Some("no"));
    assert!(out.status.success() && said(&out).contains("SSH-2.0-unasked"), "{}", said(&out));
    let seen = events(&s);
    assert_eq!((count(&seen, "upgrade layer"), count(&seen, "upgrade")), (2, 1), "{seen}");
    assert_eq!(count(&seen, "relays.json"), 1, "{seen}");
}

#[test]
fn a_kept_offer_whose_host_no_longer_serves_the_layer_is_forgotten_and_the_contract_carries_it() {
    let s = Session::start("serve-layer-stale");
    // The stand-in, which serves the contract alone: 404 for the layer.
    let cell = match Cell::fake_relay(&s) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let flags = relay_flags(&cell);
    let relay_host = flags[1].clone();
    let (host, port) = relay_host.rsplit_once(':').expect("the stand-in's port");
    // An offer kept yesterday-ish, as a role at this name made it once.
    let cache = s.home.join("cache").join("podssh");
    std::fs::create_dir_all(&cache).unwrap();
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let kept = cache.join(format!("relay-offer-{host}-{port}.json"));
    std::fs::write(&kept, format!(r#"{{"read_ms":{},"layer":true}}"#, now_ms - 3_600_000)).unwrap();
    private(&kept);
    let target = banner_target("SSH-2.0-kept-but-gone\r\n");
    let out = proxy(&s, &flags, target, None);
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("SSH-2.0-kept-but-gone"), "the contract's road carried it: {text}");
    assert!(text.contains("no longer serves the resumable layer (404): the session goes on with no resume"), "{text}");
    // Forgotten: the next run reads the offer, finds none, and says nothing.
    let out = proxy(&s, &flags, target, None);
    let text = said(&out);
    assert!(out.status.success() && text.contains("SSH-2.0-kept-but-gone"), "{text}");
    assert!(!text.contains("resumable layer"), "{text}");
}

/// The end of stdin stops sending and keeps receiving on the layer, as on
/// the contract's road: a reply that the target sends after it still comes,
/// where a `CLOSE` for the end would make the role forget the session first.
#[test]
fn a_reply_after_the_end_of_stdin_still_comes_on_the_layer() {
    let s = Session::start("serve-layer-late");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let flags = relay_flags(&cell);
    let target = late_target("SSH-2.0-after-the-end\r\n", Duration::from_millis(500));
    let out = proxy(&s, &flags, target, Some("yes"));
    let text = said(&out);
    assert!(out.status.success(), "{text}; the role: {}", events(&s));
    assert!(
        text.contains("SSH-2.0-after-the-end"),
        "the reply after the end of stdin: {text}; the role: {}",
        events(&s)
    );
    assert_eq!(count(&events(&s), "upgrade layer"), 1, "the layer's road: {}", events(&s));
}

/// A target that sends `line` `after` each connection came, then closes it.
fn late_target(line: &'static str, after: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                std::thread::sleep(after);
                let _ = stream.write_all(line.as_bytes());
            });
        }
    });
    port
}

/// A cache file that podssh trusts: this user's, read by nobody else.
fn private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if let Some(dir) = path.parent() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}
