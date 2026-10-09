//! A direct dial over several addresses (T-265): an address that never
//! answers does not hold the dial, as the next one starts after the attempt
//! delay and the first that connects wins; and the two families take turns.
//! A test binary of its own, as the pinned addresses are the process's.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use podssh_ws::dial::{dial, interleave, ProxyChoice};
use podssh_ws::resolve::set_pins;
use tokio::net::TcpListener;

#[tokio::test]
async fn a_silent_first_address_does_not_hold_the_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // 192.0.2.1 is a documentation address: a SYN to it gets no answer, or
    // an error at once where no route exists. Either way the dial goes on.
    let silent = "192.0.2.1".parse().unwrap();
    let loopback = "127.0.0.1".parse().unwrap();
    set_pins(vec![("silent-first.test".into(), silent), ("silent-first.test".into(), loopback)]);
    let started = Instant::now();
    let stream = dial("silent-first.test", port, &ProxyChoice::Direct, Duration::from_secs(10))
        .await
        .expect("the second address connects");
    let took = started.elapsed();
    assert!(took < Duration::from_secs(3), "the dial waited for the silent address: {took:?}");
    assert_eq!(stream.peer_addr().unwrap().ip(), loopback);
}

#[test]
fn the_families_take_turns_the_first_family_first() {
    let a = |s: &str| s.parse::<SocketAddr>().unwrap();
    let mixed = vec![a("[2001:db8::1]:1"), a("[2001:db8::2]:1"), a("192.0.2.1:1"), a("192.0.2.2:1"), a("192.0.2.3:1")];
    assert_eq!(
        interleave(mixed),
        vec![a("[2001:db8::1]:1"), a("192.0.2.1:1"), a("[2001:db8::2]:1"), a("192.0.2.2:1"), a("192.0.2.3:1")]
    );
    assert_eq!(interleave(vec![a("192.0.2.1:1"), a("[2001:db8::1]:1")]), vec![a("192.0.2.1:1"), a("[2001:db8::1]:1")]);
    assert_eq!(interleave(Vec::new()), Vec::<SocketAddr>::new());
}
