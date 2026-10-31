//! `podssh pipe` with WebSockets (T-368). `ws://` to websocat's echo
//! server, software that podssh did not write, gives each line back, and
//! websocat as the client of `ws-listen:` reaches a test server through
//! `tcp:`, 1 MiB each way with equal digests. `wss://` to a stand-in whose
//! certificate is for another name is refused, and with its own name
//! reaches the upgrade, its query sent as written and shown nowhere. A
//! stand-in client gets the echo of its masked frame unmasked, and the
//! close 1002 for an unmasked one; a request that is no upgrade, or a
//! browser's, gets its status, and the listener waits for the next. A
//! server's text and binary frames come as bytes, and its close ends the
//! pipe with its code and its reason. A check that needs websocat says that
//! it did not run where there is none.

mod update_support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ws::frame::{self, Frame, Role};
use sha2::{Digest, Sha256};

const LIMIT: Duration = Duration::from_secs(30);
const MIB: usize = 1 << 20;
/// The key of RFC 6455 section 1.3, and its accept value.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// A process of the test, killed when the test ends, also by a panic.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `podssh pipe ARGS`, with no proxy of the machine's and nothing that
/// turns listening or connecting off.
fn podssh(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("pipe").args(args).env("PODSSH_SSH_CONFIG", "none");
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env_remove("PODSSH_LISTEN").env_remove("PODSSH_OFFLINE");
    cmd
}

fn spawn(mut cmd: Command) -> Running {
    Running(cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs"))
}

/// websocat with `args`: its stdin and stdout piped, its stderr nowhere, so
/// that its lines cannot fill a pipe that nobody reads.
fn websocat(args: &[&str]) -> Running {
    let mut cmd = Command::new("websocat");
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    Running(cmd.spawn().expect("websocat runs"))
}

/// What `from` gives, as it comes, on a thread of its own.
fn collect(mut from: impl Read + Send + 'static) -> Arc<Mutex<Vec<u8>>> {
    let into = Arc::new(Mutex::new(Vec::new()));
    let kept = into.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                break;
            }
            kept.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    into
}

fn text(seen: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&seen.lock().unwrap()).into_owned()
}

/// Until `seen` holds `want`, or panic with `what`.
fn wait_for(seen: &Arc<Mutex<Vec<u8>>>, want: &str, what: &str) {
    let started = Instant::now();
    while !text(seen).contains(want) {
        assert!(started.elapsed() < LIMIT, "{what}: no {want:?} in {:?}", text(seen));
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The exit code within the limit.
fn ended(child: &mut Child, what: &str) -> i32 {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        assert!(started.elapsed() < LIMIT, "{what} did not end");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The address of a listener's line: `listening on ADDR: ...`.
fn listening_at(err: &Arc<Mutex<Vec<u8>>>) -> String {
    wait_for(err, "can connect", "the listener");
    text(err).split("listening on ").nth(1).unwrap().split(": ").next().unwrap().to_string()
}

fn websocat_here() -> bool {
    let here = Command::new("websocat")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !here {
        eprintln!("did not run: no websocat here");
    }
    here
}

/// A request's answer, read to the end of its head, byte by byte.
fn read_head(stream: &mut TcpStream) -> String {
    let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).expect("an answer within the limit") == 1 {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// `text` to `at`, and the head of its answer.
fn asked(at: &str, text: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(at).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    stream.write_all(text.as_bytes()).unwrap();
    let head = read_head(&mut stream);
    (stream, head)
}

/// An upgrade of RFC 6455's key, with `extra` headers.
fn upgrade(extra: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

/// The next frame of a server's, read as a client reads it: a masked one
/// fails here. A Ping is skipped.
fn server_frame(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Frame {
    loop {
        if let Some((f, used)) = frame::decode(buf, Role::Server).expect("a server's frame is unmasked") {
            buf.drain(..used);
            if f.opcode != frame::OPCODE_PING {
                return f;
            }
            continue;
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).expect("a frame within the limit");
        assert!(n > 0, "the connection ended before a frame");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A target that sends each chunk back as it comes: its port.
fn echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[test]
fn ws_to_websocat_s_echo_server_gives_each_line_back() {
    if !websocat_here() {
        return;
    }
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = websocat(&["-b", "--no-line", &format!("ws-l:127.0.0.1:{port}"), "mirror:"]);
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(started.elapsed() < LIMIT, "websocat does not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut client = spawn(podssh(&["stdio", &format!("ws://127.0.0.1:{port}/echo")]));
    let (out, err) = (collect(client.0.stdout.take().unwrap()), collect(client.0.stderr.take().unwrap()));
    let mut input = client.0.stdin.take().unwrap();
    input.write_all(b"one\ntwo\nthree\n").unwrap();
    wait_for(&out, "three\n", "the echo");
    // The end of input: a Close, which websocat answers.
    drop(input);
    assert_eq!(ended(&mut client.0, "podssh"), 0, "{}", text(&err));
    assert_eq!(text(&out), "one\ntwo\nthree\n");
}

#[test]
fn websocat_as_a_client_of_ws_listen_reaches_a_tcp_server_1_mib_each_way() {
    if !websocat_here() {
        return;
    }
    let up: Vec<u8> = (0..MIB as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let down: Vec<u8> = (0..MIB as u32).map(|i| (i.wrapping_mul(40_503) >> 7) as u8).collect();
    let digest = |bytes: &[u8]| Sha256::digest(bytes).to_vec();
    let (up_digest, down_digest) = (digest(&up), digest(&down));
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_at = target.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let (kept, sent) = (got.clone(), down);
    // The test's server reads its 1 MiB and sends its own, and holds the
    // connection: a WebSocket has no half-close to end it by.
    std::thread::spawn(move || {
        let (mut stream, _) = target.accept().unwrap();
        let mut reader = stream.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = stream.write_all(&sent);
            stream
        });
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            kept.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        drop(writer.join());
    });
    let mut server = spawn(podssh(&["ws-listen:127.0.0.1:0", &format!("tcp:{target_at}")]));
    let server_err = collect(server.0.stderr.take().unwrap());
    let at = listening_at(&server_err);
    // -n: no Close at the end of its input, which would end the session.
    let mut client = websocat(&["-b", "-n", "--no-line", &format!("ws://{at}/")]);
    let out = collect(client.0.stdout.take().unwrap());
    let mut input = client.0.stdin.take().unwrap();
    std::thread::spawn(move || {
        let _ = input.write_all(&up);
    });
    let started = Instant::now();
    while out.lock().unwrap().len() < MIB || got.lock().unwrap().len() < MIB {
        let (o, g) = (out.lock().unwrap().len(), got.lock().unwrap().len());
        assert!(started.elapsed() < LIMIT, "{o} and {g} of {MIB} bytes came: {}", text(&server_err));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(digest(&got.lock().unwrap()) == up_digest, "the test's server got other bytes");
    assert!(digest(&out.lock().unwrap()) == down_digest, "websocat got other bytes");
}

#[test]
fn wss_to_a_certificate_of_another_name_is_refused_and_its_own_name_reaches_the_upgrade() {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-pipe-wss-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let server = runtime.block_on(update_support::Server::start(&dir));
    let (ca, port) = (server.ca_file.display().to_string(), server.addr.port());
    let runs = [
        (format!("wss://localhost:{port}/"), "TLS with localhost failed"),
        (format!("wss://127.0.0.1:{port}/socket?k=SECRET"), "socket refused the upgrade: HTTP 404"),
    ];
    for (url, want) in runs {
        let mut child = spawn(podssh(&["--ca-file", &ca, "stdio", &url]));
        let err = collect(child.0.stderr.take().unwrap());
        assert_eq!(ended(&mut child.0, "podssh"), 69, "{url}: {}", text(&err));
        wait_for(&err, want, &url);
        assert!(!text(&err).contains("SECRET"), "the query is shown: {}", text(&err));
    }
    assert!(server.was_asked("/socket?k=SECRET"), "the path and its query go as written");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_upgrade_gets_its_status_and_a_client_s_unmasked_frame_the_close_1002() {
    let echo = echo_target();
    let mut server = spawn(podssh(&["ws-listen:127.0.0.1:0", &format!("tcp:127.0.0.1:{echo}")]));
    let err = collect(server.0.stderr.take().unwrap());
    let at = listening_at(&err);
    // Neither is a session: the one client of the listener is still to come.
    let (_, head) = asked(&at, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 426 ") && head.contains("Upgrade: websocket\r\n"), "{head}");
    let (_, head) = asked(&at, &upgrade("Origin: https://page.example\r\n"));
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    let (mut stream, head) = asked(&at, &upgrade(""));
    let accept = format!("Sec-WebSocket-Accept: {ACCEPT}\r\n");
    assert!(head.starts_with("HTTP/1.1 101 ") && head.contains(&accept), "{head}");
    let client_frame = |payload: &[u8], role| {
        frame::encode(&Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: payload.to_vec() }, role, [5, 6, 7, 8])
    };
    stream.write_all(&client_frame(b"there and back", Role::Client)).unwrap();
    let mut buf = Vec::new();
    let mut echoed = Vec::new();
    while echoed.len() < 14 {
        echoed.extend(server_frame(&mut stream, &mut buf).payload);
    }
    assert_eq!(echoed, b"there and back");
    stream.write_all(&client_frame(b"unmasked", Role::Server)).unwrap();
    let close = server_frame(&mut stream, &mut buf);
    assert_eq!((close.opcode, close.payload), (frame::OPCODE_CLOSE, 1002u16.to_be_bytes().to_vec()));
    assert_eq!(ended(&mut server.0, "the server"), 69, "{}", text(&err));
    assert!(text(&err).contains("not masked"), "{}", text(&err));
}

/// A WebSocket server of the test: one upgrade, answered; a text frame, a
/// binary frame and a close of `code`; then it reads to the end. It gives
/// back the request that it read.
fn standin_server(code: u16) -> (u16, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        let head = read_head(&mut stream);
        let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap_or("").trim().to_string();
        let accept = podssh_ws::handshake::accept_key(&key);
        let answer = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(answer.as_bytes()).unwrap();
        let close = podssh_ws::session::close_payload(Some(code), "done");
        for (opcode, payload) in [(frame::OPCODE_TEXT, b"text,".to_vec()), (frame::OPCODE_BINARY, b"binary".to_vec())] {
            stream.write_all(&frame::encode(&Frame { fin: true, opcode, payload }, Role::Server, [0; 4])).unwrap();
        }
        let closing = Frame { fin: true, opcode: frame::OPCODE_CLOSE, payload: close };
        stream.write_all(&frame::encode(&closing, Role::Server, [0; 4])).unwrap();
        let _ = stream.read_to_end(&mut Vec::new());
        head
    });
    (port, handle)
}

#[test]
fn a_server_s_frames_come_as_bytes_and_its_close_ends_the_pipe_with_its_code() {
    for (code, exit) in [(4000u16, 69), (1000, 0)] {
        let (port, server) = standin_server(code);
        let mut client = spawn(podssh(&["stdio", &format!("ws://127.0.0.1:{port}/q?secret=SECRET")]));
        let (out, err) = (collect(client.0.stdout.take().unwrap()), collect(client.0.stderr.take().unwrap()));
        // The input stays open: the server's close alone ends the pipe.
        let _input = client.0.stdin.take();
        assert_eq!(ended(&mut client.0, "podssh"), exit, "{code}: {}", text(&err));
        wait_for(&out, "text,binary", "the frames as bytes");
        if code != 1000 {
            wait_for(&err, &format!("ws://127.0.0.1:{port}/q closed the WebSocket: 4000 done"), "the close");
        }
        assert!(!text(&err).contains("SECRET"), "{}", text(&err));
        let head = server.join().unwrap();
        assert!(head.starts_with("GET /q?secret=SECRET HTTP/1.1\r\n"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("x-relay-token") && !lower.contains("origin:"), "{head}");
    }
}
