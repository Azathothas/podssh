use super::*;

/// `DISPLAY` as Xlib reads it: a local socket, TCP to a host, a screen, and
/// XQuartz's path.
#[test]
fn x11_display_parses_as_xlib_reads_it() {
    let local = Display::parse(":0").unwrap();
    assert_eq!((local.number, local.screen), (0, 0));
    if cfg!(unix) {
        assert_eq!(local.at, At::Socket(PathBuf::from("/tmp/.X11-unix/X0")));
    } else {
        assert_eq!(local.at, At::Tcp("127.0.0.1".into()));
    }
    assert_eq!(Display::parse("unix:1.2").unwrap().screen, 2);
    let tcp = Display::parse("localhost:10.0").unwrap();
    assert_eq!((tcp.at, tcp.number), (At::Tcp("localhost".into()), 10));
    assert_eq!(Display::parse("[::1]:3").unwrap().at, At::Tcp("::1".into()));
    let quartz = "/private/tmp/com.apple.launchd.x/org.xquartz:0";
    assert_eq!(Display::parse(quartz).unwrap().at, At::Socket(PathBuf::from(quartz)));
    for bad in ["nocolon", ":x", ":70000", ":0.y"] {
        assert!(Display::parse(bad).is_err(), "{bad}");
    }
}

/// One entry of an authority file.
fn entry(family: u16, host: &[u8], number: &str, name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = family.to_be_bytes().to_vec();
    for field in [host, number.as_bytes(), name.as_bytes(), data] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// The cookie of a display: this host's by its name, another host's never;
/// the right number; MIT-MAGIC-COOKIE-1 alone; an address for TCP; any host
/// for a wild entry; nothing from a cut file.
#[test]
fn x11_authority_file_gives_the_cookie_of_the_display() {
    let file = [
        entry(LOCAL, b"otherhost", "0", PROTOCOL, &[1; 16]),
        entry(LOCAL, b"thishost", "0", "XDM-AUTHORIZATION-1", &[2; 16]),
        entry(LOCAL, b"thishost", "1", PROTOCOL, &[3; 16]),
        entry(LOCAL, b"thishost", "0", PROTOCOL, &[4; 16]),
        entry(INTERNET, &[10, 0, 0, 5], "2", PROTOCOL, &[5; 16]),
        entry(WILD, b"", "7", PROTOCOL, &[6; 16]),
    ]
    .concat();
    let cookie =
        |display: &str, host: Option<&str>| cookie_in(&file, &Display::parse(display).unwrap(), host).map(|c| c[0]);
    assert_eq!(cookie(":0", Some("thishost")), Some(4));
    assert_eq!(cookie(":1", Some("thishost")), Some(3));
    assert_eq!(cookie(":0", None), Some(1), "with no name known, the first entry of this host's kind");
    assert_eq!(cookie("10.0.0.5:2", Some("thishost")), Some(5));
    assert_eq!(cookie("10.0.0.6:2", Some("thishost")), None);
    assert_eq!(cookie("remote.example:7", Some("thishost")), Some(6));
    assert_eq!(cookie(":5", Some("thishost")), None);
    assert_eq!(cookie_in(&file[..file.len() - 3], &Display::parse(":7").unwrap(), None), None);
}

/// A setup request, in the byte order of `order`, with `name` and `data`.
fn setup_request(order: u8, name: &[u8], data: &[u8]) -> Vec<u8> {
    let card16 = |n: usize| if order == b'B' { (n as u16).to_be_bytes() } else { (n as u16).to_le_bytes() };
    let mut out = vec![order, 0];
    out.extend_from_slice(&card16(11));
    out.extend_from_slice(&card16(0));
    out.extend_from_slice(&card16(name.len()));
    out.extend_from_slice(&card16(data.len()));
    out.extend_from_slice(&[0, 0]);
    for part in [name, data] {
        out.extend_from_slice(part);
        out.extend(std::iter::repeat_n(0, pad(part.len())));
    }
    out
}

/// The spoofed cookie of the first packet becomes the real one, in both byte
/// orders; none for an X server that takes none; another cookie is refused.
#[tokio::test]
async fn x11_first_packet_carries_the_real_cookie() {
    let display = Display::parse("localhost:0").unwrap();
    let real = Zeroizing::new(vec![0xaa; 16]);
    let forward = Forward::new(display.clone(), Some(real.clone()), None);
    assert_eq!(forward.spoofed.len(), 16);
    assert_ne!(forward.spoofed, *real);
    assert_eq!(forward.spoofed_hex().len(), 32);
    for order in *b"Bl" {
        let sent = setup_request(order, PROTOCOL.as_bytes(), &forward.spoofed);
        let mut stream = &sent[..];
        let swapped = setup(&mut stream, &forward).await.unwrap();
        assert_eq!(swapped, setup_request(order, PROTOCOL.as_bytes(), &real), "byte order {}", order as char);
    }
    let other = setup_request(b'l', PROTOCOL.as_bytes(), &[0xbb; 16]);
    assert!(setup(&mut &other[..], &forward).await.unwrap_err().contains("another cookie"));
    assert!(setup(&mut &b"no setup request"[..], &forward).await.is_err());

    let open = Forward::new(display, None, None);
    let sent = setup_request(b'B', PROTOCOL.as_bytes(), &open.spoofed);
    assert_eq!(setup(&mut &sent[..], &open).await.unwrap(), setup_request(b'B', b"", b""));
}

/// Forwarding of `-X` ends with its time: no channel after it.
#[test]
fn x11_untrusted_forwarding_has_an_end() {
    let display = Display::parse("localhost:0").unwrap();
    let ended = Forward::new(display.clone(), None, Some(Duration::ZERO));
    std::thread::sleep(Duration::from_millis(5));
    assert!(ended.until.is_some_and(|until| Instant::now() > until));
    assert!(Forward::new(display, None, None).until.is_none());
}
