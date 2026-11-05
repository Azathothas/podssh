//! `podssh share` (T-433) from end to end. With no connection: the file that
//! `add`, `rm` and `ls` change and read for a node of this host, the
//! refusals that the manual names, the node's own refusal of `--shares`
//! where no route travels, and the net's list of each member's shares
//! (`podssh net add --shares`, `podssh share ls --net`). On the stand-in
//! relay's reverse road: a node started once, with no share, refuses
//! `lab/web`; a share added while it runs is reached at its next session,
//! with no restart; `share ls` lists what the node serves; a share removed
//! is refused again, and was dialled only while it was there. A check that
//! needs Python and openssl for the stand-in says that it did not run when
//! this host has none.

mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::identity::Identity;
use throughput_harness::{command_in, lines_of, Cell, Session};

/// The bound on each wait for a node's line.
const LIMIT: Duration = Duration::from_secs(60);

/// What a run gave: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `podssh ARGS` with HOME and the cache under `home`, and no other cache
/// or net of the machine that runs the test.
fn podssh_in(home: &Path, args: &[&str]) -> Command {
    let words: Vec<String> = args.iter().map(|w| w.to_string()).collect();
    let mut cmd = command_in(home, &words);
    cmd.env_remove("PODSSH_CACHE_DIR").env_remove("PODSSH_NET");
    cmd
}

/// A TCP service on the loopback that writes `word` to each connection, and
/// counts them.
fn service(word: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(word.as_bytes());
        }
    });
    (port, count)
}

/// Removes a scratch directory, with its keys, however the test ends.
struct Gone(PathBuf);

impl Drop for Gone {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The file that a line of `add` names, between its parentheses.
fn named_file(line: &str) -> PathBuf {
    let inside = line.split_once(" (").and_then(|(_, rest)| rest.split_once(')')).map(|(path, _)| path);
    PathBuf::from(inside.unwrap_or_else(|| panic!("no file in {line:?}")))
}

#[test]
fn share_changes_the_node_s_file_and_refuses_as_the_manual_says() {
    let home = throughput_harness::scratch("share-cli");
    let _gone = Gone(home.clone());
    let podssh = |args: &[&str]| ran(&mut podssh_in(&home, args));
    // Usage errors, 64, before anything is read.
    for (args, says) in [
        (&["share"][..], "missing SUBCOMMAND"),
        (&["share", "mv", "web"], "is not a subcommand"),
        (&["share", "add"], "podssh share add NAME=HOST:PORT: 0 words given"),
        (&["share", "ls", "web"], "podssh share ls: 1 words given"),
        (&["share", "add", "web", "--node", "lab"], "is not NAME=HOST:PORT"),
        (&["share", "add", "dns=udp:127.0.0.1:53", "--node", "lab"], "a share is a TCP service"),
        (&["share", "add", "a/b=127.0.0.1:80", "--node", "lab"], "is not a share's name"),
        (&["share", "rm", "web", "--net"], "--net is for podssh share ls"),
        (&["share", "ls", "--net", "--node", "lab"], "--net lists each member's shares"),
        (&["node", "lab", "127.0.0.1:9", "--no-e2e", "--shares", "s"], "--shares is not for a node of --no-e2e"),
        (&["node", "lab", "udp:127.0.0.1:53", "--shares", "s"], "--shares is not for a node of a udp: TARGET"),
    ] {
        let (rc, out, err) = podssh(args);
        assert!(rc == 64 && out.is_empty() && err.contains(says), "{args:?}: {rc} {err}");
    }
    // A node with no file has no share.
    let (rc, out, err) = podssh(&["share", "ls", "--node", "lab"]);
    assert!(rc == 0 && out.is_empty() && err.contains("the node lab has no shares"), "{rc} {err}");
    // Added, each with the address that reaches it.
    let (rc, _, err) = podssh(&["share", "add", "web=127.0.0.1:8080", "--node", "lab"]);
    assert!(
        rc == 0 && err.contains("the node lab shares web=127.0.0.1:8080") && err.contains("node://lab/web"),
        "{err}"
    );
    let file = named_file(&err);
    assert!(file.ends_with("node-lab.shares"), "beside the node's key, in the cache: {}", file.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a private file, as the node refuses one that others may change");
    }
    let (rc, _, err) = podssh(&["share", "add", "db=[::1]:5432", "--node", "lab"]);
    assert_eq!(rc, 0, "{err}");
    let (rc, out, err) = podssh(&["share", "ls", "--node", "lab"]);
    assert_eq!((rc, out.as_str()), (0, "web\t127.0.0.1:8080\ndb\t[::1]:5432\n"), "{err}");
    // A new target for a name, the same one again, a name that is none.
    let (rc, _, err) = podssh(&["share", "add", "web=127.0.0.1:9090", "--node", "lab"]);
    assert!(rc == 0 && err.contains("in place of 127.0.0.1:8080"), "{err}");
    let (rc, _, err) = podssh(&["share", "add", "web=127.0.0.1:9090", "--node", "lab"]);
    assert!(rc == 0 && err.contains("already"), "{err}");
    let (rc, _, err) = podssh(&["share", "rm", "db", "--node", "lab"]);
    assert!(rc == 0 && err.contains("shares db no more"), "{err}");
    let (rc, _, err) = podssh(&["share", "rm", "db", "--node", "lab"]);
    assert!(rc == 64 && err.contains("has no share db"), "{rc} {err}");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with('#') && text.ends_with("\nweb=127.0.0.1:9090\n"), "{text}");
    // The file of --shares, as the node's --shares FILE names it.
    let own = home.join("lab.shares");
    let own_word = own.display().to_string();
    let (rc, _, err) = podssh(&["share", "add", "ssh=127.0.0.1:22", "--shares", &own_word]);
    assert!(rc == 0 && err.contains("node://NODE/ssh"), "{err}");
    let (rc, out, err) = podssh(&["share", "ls", "--shares", &own_word]);
    assert_eq!((rc, out.as_str()), (0, "ssh\t127.0.0.1:22\n"), "{err}");
    // A cache that keeps no file holds no share: the file of --shares does.
    let (rc, _, err) =
        ran(podssh_in(&home, &["share", "add", "web=127.0.0.1:1", "--node", "lab"]).env("PODSSH_CACHE_DIR", "none"));
    assert!(rc == 78 && err.contains("--shares FILE"), "{rc} {err}");
}

#[test]
fn the_net_lists_each_member_s_shares_as_its_owner_wrote_them() {
    let home = throughput_harness::scratch("share-net");
    let _gone = Gone(home.clone());
    let dir = home.join("private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    let owner = dir.join("owner");
    let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", owner.to_str().unwrap()];
    let (rc, _, err) = ran(&mut podssh_in(&home, &keygen));
    assert_eq!(rc, 0, "podssh keygen: {err}");
    let doc = dir.join("net.doc");
    let net = |args: &[&str]| {
        let mut words = args.to_vec();
        words.extend(["--owner-key", owner.to_str().unwrap()]);
        ran(podssh_in(&home, &words).env("PODSSH_NET", &doc))
    };
    let key = |seed: u8| Identity::from_seed(&[seed; 32]).public().hex();
    let (lab, box_key) = (key(0x22), key(0x23));
    assert_eq!(net(&["net", "init", "home"]).0, 0);
    let (rc, _, err) = net(&["net", "add", "lab", &lab, "--roles", "node", "--shares", "web"]);
    assert!(rc == 64 && err.contains("give --roles with share too"), "shares with no role share: {rc} {err}");
    let (rc, _, err) = net(&["net", "add", "lab", &lab, "--roles", "node,share", "--shares", "web,a/b"]);
    assert!(rc == 64 && err.contains("is not a share's name"), "{rc} {err}");
    let (rc, _, err) = net(&["net", "add", "lab", &lab, "--roles", "node,share", "--shares", "web, db,web"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(net(&["net", "add", "box", &box_key]).0, 0);
    let ls = || ran(podssh_in(&home, &["share", "ls", "--net"]).env("PODSSH_NET", &doc));
    let (rc, out, err) = ls();
    assert_eq!((rc, out.as_str()), (0, "lab\tweb\tnode://lab/web\nlab\tdb\tnode://lab/db\n"), "{err}");
    assert!(err.contains("the net home, serial 3"), "{err}");
    // A member written with no share, and a net with none.
    let (rc, _, err) = net(&["net", "add", "lab", &lab, "--roles", "node,share"]);
    assert_eq!(rc, 0, "{err}");
    let (rc, out, err) = ls();
    assert!(rc == 0 && out.is_empty() && err.contains("the net lists no share"), "{rc} {out} {err}");
    // No net held: the remedy, 78.
    let (rc, _, err) = ran(podssh_in(&home, &["share", "ls", "--net"]).env("PODSSH_NET", dir.join("none.doc")));
    assert!(rc == 78 && err.contains("holds no net"), "{rc} {err}");
}

/// The lines of a node until one holds `needle`, within [`LIMIT`].
fn until(lines: &std::sync::mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let (deadline, mut seen) = (Instant::now() + LIMIT, Vec::new());
    while !seen.last().is_some_and(|line: &String| line.contains(needle)) {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => seen.push(line),
            Err(_) => panic!("no {needle:?} within {} s: {seen:#?}", LIMIT.as_secs()),
        }
    }
    seen
}

#[test]
fn a_share_added_while_the_node_runs_is_reached_at_its_next_session() {
    let session = Session::start("share");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    // The pins go after the verb, before its words; `share` dials nothing.
    let command = |args: &[&str]| {
        let mut cmd = session.stand_in(&[args[0].to_string()], &ca);
        cmd.args(&pins).args(&args[1..]).env_remove("PODSSH_CACHE_DIR").env_remove("PODSSH_NET");
        cmd
    };
    let share = |args: &[&str]| ran(&mut podssh_in(&session.home, args));
    let (rc, _, err) = ran(&mut command(&["relay", "pair", "lab", "--relay-host", &relay]));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    let ((default, _), (web, web_seen)) = (service("default\n"), service("web\n"));
    let target = format!("127.0.0.1:{default}");
    let mut node = command(&["node", "lab", &target]).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let start = until(&lines, "online");
    let said = start.iter().find(|l| l.contains("its shares by name in")).expect("the node says where its shares are");
    assert!(said.contains("none now") && said.contains("--node lab"), "{said}");
    let node_said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    let operator = |name: &str| ran(&mut command(&["operator", name]));
    // No share yet: refused as a route that the node does not have.
    let (rc, out, err) = operator("lab/web");
    assert!(rc != 0 && out.is_empty() && err.contains("may not use the route web"), "{rc} {err}");
    let (rc, out, err) = operator("lab");
    assert_eq!((rc, out.as_str()), (0, "default\n"), "{err}");
    // Added while the node runs: its next session reaches it, no restart.
    let (rc, _, err) = share(&["share", "add", &format!("web=127.0.0.1:{web}"), "--node", "lab"]);
    assert_eq!(rc, 0, "{err}");
    let (rc, out, err) = operator("lab/web");
    let fault = format!("a share added while the node runs was not reached: {err}\nthe node:\n{}", node_said());
    assert_eq!((rc, out.as_str()), (0, "web\n"), "{fault}");
    let (rc, out, err) = share(&["share", "ls", "--node", "lab"]);
    assert_eq!((rc, out), (0, format!("web\t127.0.0.1:{web}\n")), "{err}");
    // Removed: refused from its next session, and not dialled again.
    let (rc, _, err) = share(&["share", "rm", "web", "--node", "lab"]);
    assert_eq!(rc, 0, "{err}");
    let (rc, out, err) = operator("lab/web");
    assert!(rc != 0 && out.is_empty() && err.contains("may not use the route web"), "a share removed: {rc} {err}");
    assert_eq!(web_seen.load(Ordering::SeqCst), 1, "the share was dialled once, while it was there");
}
