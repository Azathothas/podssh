//! The tests of the line `nat` (T-641): stand-in STUN servers on the
//! loopback, each answering with a script, which speak the codec that
//! RFC 5769's vectors hold (`podssh_ws::stun`); the verdict of each form;
//! the variable; and the lines of a run offline or turned off.

use std::sync::{Arc, Mutex};

use super::*;

/// The waits of the probe in these tests: the loopback answers at once.
const QUICK: Duration = Duration::from_millis(300);

/// An address that a trick names, which the probe must never take.
const FAKE: &str = "203.0.113.66:666";

/// What a stand-in does with each request.
#[derive(Clone, Copy)]
enum Script {
    /// Answers with the address that the request came from: no NAT between.
    Echo,
    /// Answers with this address, as a server beyond a NAT that mapped the
    /// request to it.
    Says(SocketAddr),
    /// Reads each request and answers none.
    Silent,
    /// First an answer of another id, one from another port of this host and
    /// a datagram that is no STUN, each naming [`FAKE`]; then this address.
    Tricks(SocketAddr),
    /// A success response that names no address.
    NoMapping,
    /// A Binding error response, 400.
    Refuses,
}

/// A stand-in server: its address, and the source and the id of each
/// request that it read.
struct StandIn {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<(SocketAddr, stun::TransactionId)>>>,
}

async fn stand_in(script: Script) -> StandIn {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let Ok(request) = stun::parse(&buffer[..n]) else { continue };
            let id = request.id;
            log.lock().unwrap().push((from, id));
            let fake: SocketAddr = FAKE.parse().unwrap();
            let answer = match script {
                Script::Echo => stun::binding_success(&id, from),
                Script::Says(mapped) => stun::binding_success(&id, mapped),
                Script::Silent => continue,
                Script::Tricks(mapped) => {
                    let mut other = id;
                    other[0] ^= 0xff;
                    let _ = socket.send_to(&stun::binding_success(&other, fake), from).await;
                    let _ = stranger.send_to(&stun::binding_success(&id, fake), from).await;
                    let _ = socket.send_to(b"no STUN at all", from).await;
                    // The tricks first, so that the probe reads them before the answer.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    stun::binding_success(&id, mapped)
                }
                Script::NoMapping => {
                    stun::message(stun::BINDING_SUCCESS, &id, &[(stun::SOFTWARE, b"stand-in".as_slice())])
                }
                Script::Refuses => {
                    let code = [[0u8, 0, 4, 0].as_slice(), b"Bad Request".as_slice()].concat();
                    stun::message(stun::BINDING_ERROR, &id, &[(stun::ERROR_CODE, code.as_slice())])
                }
            };
            let _ = socket.send_to(&answer, from).await;
        }
    });
    StandIn { addr, seen }
}

impl StandIn {
    fn seen(&self) -> Vec<(SocketAddr, stun::TransactionId)> {
        self.seen.lock().unwrap().clone()
    }
}

/// The stand-ins as the variable would name them.
fn servers(stand_ins: &[&StandIn]) -> Vec<Server> {
    stand_ins.iter().map(|s| Server { host: s.addr.ip().to_string(), port: s.addr.port() }).collect()
}

/// The probe as `check` runs it, with short waits: the answers, this host's
/// own address, and the verdict.
async fn run(stand_ins: &[&StandIn], tries: u32) -> (Vec<Asked>, Option<SocketAddr>, Verdict) {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    let asked = ask_each(&socket, &servers(stand_ins), tries, QUICK).await;
    let own = own_address(&socket, &asked).await;
    let verdict = verdict(&asked, own);
    (asked, own, verdict)
}

fn detail(verdict: &Verdict) -> &str {
    match verdict {
        Verdict::Ok { detail } => detail,
        Verdict::Unknown { why } => why,
        Verdict::Failed { detail } => panic!("the line is never FAIL: {detail}"),
    }
}

/// Two servers that each give the address that they saw: both saw the one
/// socket's, which is this host's own on the loopback, so no NAT. Two
/// sockets would read as a mapping for each destination.
#[tokio::test]
async fn the_two_questions_go_from_one_socket_and_read_no_nat() {
    let (a, b) = (stand_in(Script::Echo).await, stand_in(Script::Echo).await);
    let (asked, own, verdict) = run(&[&a, &b], 2).await;
    let (seen_a, seen_b) = (a.seen(), b.seen());
    assert_eq!((seen_a.len(), seen_b.len()), (1, 1), "{asked:?}");
    assert_eq!(seen_a[0].0, seen_b[0].0, "one socket asks both");
    assert_ne!(seen_a[0].1, seen_b[0].1, "an id for each question");
    assert_eq!(own, Some(seen_a[0].0), "the host's own address on that route");
    assert!(matches!(verdict, Verdict::Ok { .. }), "{verdict:?}");
    let text = detail(&verdict);
    assert!(text.starts_with(&format!("no NAT: {} and {} each saw", a.addr, b.addr)), "{text}");
}

/// One mapped address for both servers: one mapping for all destinations.
#[tokio::test]
async fn one_mapped_address_for_both_is_one_mapping() {
    let mapped: SocketAddr = "198.51.100.7:40000".parse().unwrap();
    let (a, b) = (stand_in(Script::Says(mapped)).await, stand_in(Script::Says(mapped)).await);
    let (_, own, verdict) = run(&[&a, &b], 2).await;
    let text = detail(&verdict);
    assert!(matches!(verdict, Verdict::Ok { .. }), "{text}");
    let own = own.unwrap();
    let says = format!("one mapping for all destinations: {} and {} each saw {mapped} for {own}", a.addr, b.addr);
    assert!(text.starts_with(&says), "{text}");
    assert!(text.ends_with("(hole punching can work here)"), "{text}");
}

/// Two ports: a mapping for each destination, and hole punching will not
/// work; two addresses say so too.
#[tokio::test]
async fn two_ports_differ_is_a_mapping_for_each_destination() {
    let one: SocketAddr = "198.51.100.7:40000".parse().unwrap();
    let two: SocketAddr = "198.51.100.7:40001".parse().unwrap();
    let (a, b) = (stand_in(Script::Says(one)).await, stand_in(Script::Says(two)).await);
    let (_, _, verdict) = run(&[&a, &b], 2).await;
    let text = detail(&verdict);
    assert!(matches!(verdict, Verdict::Ok { .. }), "{text}");
    let says =
        format!("a mapping for each destination: {} saw {one} and {} saw {two}, its port changed", a.addr, b.addr);
    assert!(text.starts_with(&says), "{text}");
    assert!(text.contains("hole punching will not work here"), "{text}");
}

/// A silent server: `????`, naming it, after its tries, each with the same
/// id; the run's exit is not moved, as the line is never FAIL.
#[tokio::test]
async fn silence_is_unknown_and_names_the_silent_server() {
    let (a, b) = (stand_in(Script::Echo).await, stand_in(Script::Silent).await);
    let began = Instant::now();
    let (asked, _, verdict) = run(&[&a, &b], 2).await;
    assert!(began.elapsed() >= QUICK * 2, "{:?}", began.elapsed());
    assert!(matches!(verdict, Verdict::Unknown { .. }), "{verdict:?}");
    let text = detail(&verdict);
    assert!(text.starts_with("fewer than two STUN servers gave a mapped address"), "{text}");
    assert!(text.contains(&format!("{} said nothing in 2 tries of 300 ms", b.addr)), "{text}");
    assert!(text.contains(&format!("{} saw ", a.addr)), "{text}");
    let tries = b.seen();
    assert_eq!(tries.len(), 2, "{asked:?}");
    assert_eq!(tries[0].1, tries[1].1, "a try again keeps the id");
}

/// A server that answers with no address, or with an error, gives no
/// verdict.
#[tokio::test]
async fn an_answer_with_no_mapped_address_is_no_verdict() {
    let (a, b) = (stand_in(Script::Echo).await, stand_in(Script::NoMapping).await);
    let (_, _, verdict) = run(&[&a, &b], 2).await;
    assert!(matches!(verdict, Verdict::Unknown { .. }), "{verdict:?}");
    assert!(detail(&verdict).contains(&format!("{} answered with no mapped address", b.addr)), "{verdict:?}");
    let c = stand_in(Script::Refuses).await;
    let (_, _, verdict) = run(&[&a, &c], 2).await;
    assert!(detail(&verdict).contains(&format!("{} answered the error 400 Bad Request", c.addr)), "{verdict:?}");
}

/// An answer of another id, one from another address and a datagram that
/// is no STUN come first, and are skipped: the verdict is the servers'.
#[tokio::test]
async fn a_wrong_transaction_id_and_a_strangers_datagram_are_skipped() {
    let mapped: SocketAddr = "198.51.100.7:40000".parse().unwrap();
    let (a, b) = (stand_in(Script::Tricks(mapped)).await, stand_in(Script::Tricks(mapped)).await);
    let (asked, _, verdict) = run(&[&a, &b], 2).await;
    let text = detail(&verdict);
    assert!(text.starts_with("one mapping for all destinations") && text.contains(&mapped.to_string()), "{text}");
    assert!(!text.contains(FAKE), "{text}");
    assert!(asked.iter().all(|one| one.answer == Answer::Mapped(mapped)), "{asked:?}");
    assert_eq!((a.seen().len(), b.seen().len()), (1, 1), "each answered on the first try");
}

/// Each server in turn until two gave an address: a silent first one is
/// passed for the next, and a third is not asked once two answered.
#[tokio::test]
async fn the_servers_are_asked_in_turn_until_two_answered() {
    let (silent, a, b) = (stand_in(Script::Silent).await, stand_in(Script::Echo).await, stand_in(Script::Echo).await);
    let (asked, _, verdict) = run(&[&silent, &a, &b], 1).await;
    assert_eq!(asked.len(), 3);
    assert!(detail(&verdict).starts_with("no NAT"), "{verdict:?}");
    let (c, d, e) = (stand_in(Script::Echo).await, stand_in(Script::Echo).await, stand_in(Script::Echo).await);
    let (asked, _, _) = run(&[&c, &d, &e], 1).await;
    assert_eq!(asked.len(), 2);
    assert!(e.seen().is_empty(), "the third was asked");
}

/// The whole line through `check`, as a run gives it.
#[tokio::test]
async fn the_line_says_no_nat_through_check() {
    let (a, b) = (stand_in(Script::Echo).await, stand_in(Script::Echo).await);
    let mut out = Vec::new();
    let mut report = Report::new(&mut out);
    check(&mut report, &Setting::Servers(servers(&[&a, &b]))).await;
    let _ = report.finish();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains(&format!("  ok    nat            no NAT: {} and {} each saw", a.addr, b.addr)), "{text}");
    assert!(text.contains("1 ok, 0 FAIL, 0 ????"), "{text}");
}

/// Each form of the verdict, and none is FAIL: the address that changed is
/// named, and with no own address, one mapping says no " for ".
#[test]
fn each_form_of_the_verdict_is_ok_or_unknown() {
    let at = |text: &str| -> SocketAddr { text.parse().unwrap() };
    let one = |shown: &str, mapped: &str| Asked { shown: shown.into(), at: None, answer: Answer::Mapped(at(mapped)) };
    let apart = [one("s1:3478", "198.51.100.7:1"), one("s2:3478", "198.51.100.8:1")];
    assert!(detail(&verdict(&apart, None)).contains("its address changed"));
    let same = [one("s1:3478", "198.51.100.7:1"), one("s2:3478", "198.51.100.7:1")];
    let text = detail(&verdict(&same, None)).to_string();
    let says = "one mapping for all destinations: s1:3478 and s2:3478 each saw 198.51.100.7:1, so";
    assert!(text.starts_with(says), "{text}");
    assert!(detail(&verdict(&same, Some(at("198.51.100.7:1")))).starts_with("no NAT"));
    assert!(matches!(verdict(&[], None), Verdict::Unknown { .. }));
    let silent = |shown: &str, addr: Option<SocketAddr>, why: &str| Asked {
        shown: shown.into(),
        at: addr,
        answer: Answer::Silent(why.into()),
    };
    let unresolved = [silent("s1:3478", None, "its name did not resolve: no")];
    assert!(detail(&verdict(&unresolved, None)).ends_with("s1:3478 its name did not resolve: no"));
    // The address asked is named beside a name, not beside itself.
    assert_eq!(silent("stun.example:3478", Some(at("192.0.2.5:3478")), "x").named(), "stun.example:3478 (192.0.2.5)");
    assert_eq!(silent("192.0.2.5:3478", Some(at("192.0.2.5:3478")), "x").named(), "192.0.2.5:3478");
}

/// The variable: the default, `no`, a list of 2 to 4 with STUN's port by
/// default; one server, five, a bad host and port 0 are 78.
#[test]
fn the_variable_names_the_servers_or_turns_the_line_off() {
    let default = Setting::Servers(vec![
        Server { host: "stun.cloudflare.com".into(), port: 3478 },
        Server { host: "stun.l.google.com".into(), port: 19302 },
    ]);
    assert_eq!(setting_of(None).unwrap(), default);
    assert_eq!(setting_of(Some("  ")).unwrap(), default);
    assert_eq!(setting_of(Some("no")).unwrap(), Setting::Off);
    let named = setting_of(Some("a.example:1, b.example ,[2001:db8::1]:9")).unwrap();
    let want = ["a.example:1", "b.example:3478", "[2001:db8::1]:9"];
    match named {
        Setting::Servers(list) => assert_eq!(list.iter().map(|s| s.to_string()).collect::<Vec<_>>(), want),
        Setting::Off => panic!("off"),
    }
    for bad in ["a.example", "a,b,c,d,e", "a.example,bad host!", "a.example,b.example:0", "a.example,"] {
        let refusal = setting_of(Some(bad)).unwrap_err();
        assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG, "{bad}");
        assert!(refusal.message.starts_with("PODSSH_STUN: "), "{}", refusal.message);
        let words = "give 2 to 4 STUN servers as HOST[:PORT],HOST[:PORT], or no";
        assert!(refusal.message.ends_with(words), "{}", refusal.message);
    }
}

/// Offline nothing is sent, and `no` says that it turned the line off;
/// either is `????`.
#[tokio::test]
async fn offline_and_off_are_unknown_lines() {
    let mut out = Vec::new();
    let mut report = Report::new(&mut out);
    offline(&mut report, &setting_of(None).unwrap());
    offline(&mut report, &Setting::Off);
    check(&mut report, &Setting::Off).await;
    let _ = report.finish();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("  ????  nat            not attempted: PODSSH_OFFLINE is set"), "{text}");
    let off = "  ????  nat            PODSSH_STUN=no turns it off, so no STUN server was asked";
    assert_eq!(text.matches(off).count(), 2, "{text}");
    assert!(text.contains("0 ok, 0 FAIL, 3 ????"), "{text}");
}
