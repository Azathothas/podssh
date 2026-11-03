//! The forward road of podssh's relay role to IPv6 targets (T-253), on this
//! machine's loopback. Where the host has IPv6, the role carries OpenSSH's
//! version line from a target on `::1`: by its address, bare or in brackets,
//! by a name with `?family=6`, and in `/trace`. Where its host has no IPv6
//! route out, an IPv6 target gets the role's `502` before the upgrade, with
//! why, by `?dial=lazy` too, while an IPv4 target and the loopback's own
//! `::1` go on, and `/relays.json` says so. Through the host's proxy, the
//! proxy's way out decides, and the role refuses nothing for it. A host with
//! no IPv6 loopback says so, and those parts do not run.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use podssh_relay::relay::NO_IPV6_ROUTE;
use podssh_relay::serve::egress::Egress;
use podssh_relay::serve::ipv6::Ipv6Out;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::ConnectError;
use role_harness::proxy::{self, StandIn};
use role_harness::{next, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// OpenSSH's version line, in the form that its sshd sends it first.
const BANNER: &str = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";

/// A target on `::1` that sends [`BANNER`] to each connection, then reads
/// until its end: its port, or `None`, with why, on a host with no IPv6
/// loopback.
async fn banner_on_v6() -> Option<u16> {
    let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("did not run: this host has no IPv6 loopback ({e})");
            return None;
        }
    };
    let port = listener.local_addr().ok()?.port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = tcp.write_all(BANNER.as_bytes()).await;
                let mut sink = vec![0u8; 4096];
                while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    Some(port)
}

/// The role with private targets allowed, as the test's are on the
/// loopback, what it knows of IPv6 out of its host, and its egress; and a
/// token of its own.
async fn role(ipv6: Ipv6Out, egress: Egress) -> (Role, String) {
    let policy = Policy { private: true, ipv6, ..Policy::default() };
    let role = Role::configured(Mint::Anyone, policy, egress).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// The answer of a refused upgrade: its status and body.
fn refusal(r: Result<podssh_ws::session::RelaySession<tokio::net::TcpStream>, ConnectError>) -> (u16, String) {
    match r {
        Err(ConnectError::Refused { status, body }) => (status, body),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade was taken"),
    }
}

/// `/relays.json` of `role`, as JSON.
async fn relays(role: &Role) -> serde_json::Value {
    let (status, body) = role.http("GET", "/relays.json", None).await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_a_host_with_ipv6_the_role_carries_a_target_on_the_ipv6_loopback() {
    let Some(port) = banner_on_v6().await else { return };
    // The host's own probes: the loopback is this host's on each host.
    let (role, token) = role(Ipv6Out::default(), Egress::Direct).await;
    let bare = role.socket(&format!("/connect/::1/{port}"), &token).await.expect("the role dials ::1");
    assert_eq!(next(&bare).await, Some((OPCODE_BINARY, BANNER.as_bytes().to_vec())));
    let bracketed = role.socket(&format!("/connect/[::1]/{port}?family=6"), &token).await.expect("in brackets");
    assert_eq!(next(&bracketed).await, Some((OPCODE_BINARY, BANNER.as_bytes().to_vec())));
    let (status, body) = role.http("GET", &format!("/trace?target=[::1]:{port}"), Some(token.as_str())).await;
    assert_eq!(status, 200, "{body}");
    let traced: serde_json::Value = serde_json::from_str(&body).unwrap();
    let leg = &traced["target"];
    assert_eq!((leg["dialed"].as_str(), leg["address_family"].as_str()), (Some("::1"), Some("6")), "{body}");
    assert_eq!(leg["banner"].as_str(), Some(BANNER.trim_end()), "{body}");
    // A name with ?family=6, by its IPv6 address alone, where it has one.
    let named = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", port)).map(|mut a| a.any(|a| a.is_ipv6()));
    if named.unwrap_or(false) {
        let six = role.socket(&format!("/connect/localhost/{port}?family=6"), &token).await.expect("its IPv6");
        assert_eq!(next(&six).await, Some((OPCODE_BINARY, BANNER.as_bytes().to_vec())));
    } else {
        eprintln!("did not run: localhost has no IPv6 address here, for ?family=6");
    }
    // What the host's own probes found: a word, or null where none tells.
    let doc = relays(&role).await;
    let egress = &doc["egress"];
    assert!(egress["ipv6"].is_boolean() || egress["ipv6"].is_null(), "{egress}");
    assert!(egress["known_by"].is_string(), "{egress}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_route_out_an_ipv6_target_gets_the_502_before_the_upgrade() {
    let ipv4 = proxy::greeting("SSH-2.0-over-ipv4\r\n").await;
    let (role, token) = role(Ipv6Out::none(), Egress::Direct).await;
    // `?dial=lazy` first, whose dial would come after the upgrade: the
    // refusal comes before it, and no address of the documentation range is
    // dialed by any of them.
    for path in ["/connect/2001:db8::7/22?dial=lazy", "/connect/2001:db8::7/22", "/connect/[2001:db8::7]/22?family=6"] {
        let (status, body) = refusal(role.socket(path, &token).await);
        assert_eq!(status, 502, "{path}: {body}");
        assert!(body.contains(NO_IPV6_ROUTE) && body.contains("[2001:db8::7]:22"), "{path}: {body}");
    }
    assert!(!role.said("upgrade"), "an upgrade with no route: {:?}", role.events.lock().unwrap());
    // An IPv4 target goes on.
    let v4 = role.socket(&format!("/connect/127.0.0.1/{ipv4}"), &token).await.expect("an IPv4 target");
    assert_eq!(next(&v4).await, Some((OPCODE_BINARY, b"SSH-2.0-over-ipv4\r\n".to_vec())));
    // /trace says why, and /relays.json that the host has no IPv6 route out.
    let (status, body) = role.http("GET", "/trace?target=[2001:db8::7]:22", Some(token.as_str())).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(NO_IPV6_ROUTE), "{body}");
    assert_eq!(relays(&role).await["egress"]["ipv6"], false);
    // The loopback's ::1 is this host's own, with a route out or none.
    if let Some(port) = banner_on_v6().await {
        let local = role.socket(&format!("/connect/::1/{port}"), &token).await.expect("::1, with no route out");
        assert_eq!(next(&local).await, Some((OPCODE_BINARY, BANNER.as_bytes().to_vec())));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn through_the_hosts_proxy_its_way_out_decides() {
    let target = proxy::greeting("SSH-2.0-through-the-proxy\r\n").await;
    let stand_in = StandIn::start("200 Connection Established", target).await;
    let url = stand_in.url("");
    let egress = Egress::from_vars(|name| (name == "HTTPS_PROXY").then(|| url.clone())).expect("the proxy's URL");
    let (role, token) = role(Ipv6Out::none(), egress).await;
    let lazy = role.socket("/connect/2001:db8::7/22?dial=lazy", &token).await.expect("the proxy decides");
    lazy.send_binary(b"first").await.unwrap();
    assert_eq!(next(&lazy).await, Some((OPCODE_BINARY, b"SSH-2.0-through-the-proxy\r\n".to_vec())));
    assert_eq!(stand_in.asked(), ["CONNECT [2001:db8::7]:22 HTTP/1.1"]);
    assert!(relays(&role).await["egress"]["ipv6"].is_null(), "the proxy's way out is not the role's to tell");
}
