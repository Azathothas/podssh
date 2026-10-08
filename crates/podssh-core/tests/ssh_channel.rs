//! Task 5 tests: the open handshake, window arithmetic, exit mapping, and
//! request builders. The live server cross-check (real confirmation bytes,
//! real exit-status) is Task 6's.

use podssh_core::ssh::channel::{
    Channel, ChannelError, ChannelEvent, Exit, INITIAL_WINDOW, MAX_PACKET, MSG_CHANNEL_CLOSE,
    MSG_CHANNEL_DATA, MSG_CHANNEL_OPEN, MSG_CHANNEL_REQUEST, encode_pty_modes,
};
use podssh_core::ssh::types::{Reader, put_string, put_u32};

fn confirm_for(local: u32, remote: u32, window: u32, max_packet: u32) -> Vec<u8> {
    let mut out = vec![91u8];
    put_u32(&mut out, remote);
    put_u32(&mut out, local);
    put_u32(&mut out, remote);
    put_u32(&mut out, window);
    put_u32(&mut out, max_packet);
    out
}

fn open_channel() -> Channel {
    let mut ch = Channel::new(7);
    let confirm = confirm_for(7, 42, 128 * 1024, 16 * 1024);
    assert_eq!(ch.on_message(&confirm).unwrap(), ChannelEvent::Opened);
    assert!(ch.is_open());
    ch
}

#[test]
fn open_confirm_sets_ids_window_and_packet() {
    let mut ch = Channel::new(7);
    assert!(!ch.is_open());
    let open = ch.open_session();
    assert_eq!(open[0], MSG_CHANNEL_OPEN);
    let mut r = Reader::new(&open[1..]);
    assert_eq!(r.string().unwrap(), b"session");
    assert_eq!(r.u32().unwrap(), 7);
    // A confirmation for another id is refused, never absorbed.
    let wrong = confirm_for(8, 42, 1024, 1024);
    assert!(matches!(
        ch.on_message(&wrong),
        Err(ChannelError::BadState { .. })
    ));
    assert!(!ch.is_open());
    // The real one opens.
    assert_eq!(
        ch.on_message(&confirm_for(7, 42, 128 * 1024, 16 * 1024)).unwrap(),
        ChannelEvent::Opened
    );
    assert!(ch.is_open());
    // A second confirmation is state confusion, not a re-open.
    assert!(matches!(
        ch.on_message(&confirm_for(7, 42, 1, 1)),
        Err(ChannelError::BadState { .. })
    ));
}

#[test]
fn open_failure_names_reason_and_message() {
    let mut ch = Channel::new(3);
    let mut fail = vec![92u8];
    put_u32(&mut fail, 99);
    put_u32(&mut fail, 2);
    put_string(&mut fail, b"administratively prohibited");
    put_string(&mut fail, b"en");
    let err = ch.on_message(&fail).unwrap_err();
    assert!(matches!(err, ChannelError::OpenFailed { reason: 2, .. }), "{err}");
    assert!(format!("{err}").contains("administratively prohibited"), "{err}");
    assert!(!ch.is_open());
}

#[test]
fn window_accounting_refuses_over_window_and_adjust_replenishes() {
    let mut ch = open_channel();
    // claim_send is bounded by the SMALLER of window and max packet.
    assert_eq!(ch.claim_send(64 * 1024), 16 * 1024);
    ch.sent(16 * 1024);
    // Inbound: the window fills in max-packet halves (one 64 KiB payload
    // would be OversizePayload first — the peer was told 32 KiB max).
    let half = vec![b'x'; MAX_PACKET as usize];
    let mut d1 = vec![94u8];
    put_u32(&mut d1, 42);
    put_string(&mut d1, &half);
    assert_eq!(ch.on_message(&d1).unwrap(), ChannelEvent::Data);
    let mut d2 = vec![94u8];
    put_u32(&mut d2, 42);
    put_string(&mut d2, &half);
    assert_eq!(ch.on_message(&d2).unwrap(), ChannelEvent::Data);
    assert_eq!(ch.take_received().len(), INITIAL_WINDOW as usize);
    let mut over = vec![94u8];
    put_u32(&mut over, 42);
    put_string(&mut over, b"y");
    // Window refilled by the drain, so one byte fits again...
    assert_eq!(ch.on_message(&over).unwrap(), ChannelEvent::Data);
    assert_eq!(ch.take_received(), b"y");
    // ...but refilling past the window without a drain does not.
    let mut d3 = vec![94u8];
    put_u32(&mut d3, 42);
    put_string(&mut d3, &half);
    assert_eq!(ch.on_message(&d3).unwrap(), ChannelEvent::Data);
    let mut d4 = vec![94u8];
    put_u32(&mut d4, 42);
    put_string(&mut d4, &half);
    assert_eq!(ch.on_message(&d4).unwrap(), ChannelEvent::Data);
    let mut d5 = vec![94u8];
    put_u32(&mut d5, 42);
    put_string(&mut d5, &half);
    let err = ch.on_message(&d5).unwrap_err();
    assert!(
        matches!(err, ChannelError::WindowExceeded { available: 0, .. }),
        "{err}"
    );
    // Adjust replenishes the send side.
    let mut adj = vec![93u8];
    put_u32(&mut adj, 42);
    put_u32(&mut adj, 16 * 1024);
    assert_eq!(ch.on_message(&adj).unwrap(), ChannelEvent::WindowAdjusted { by: 16 * 1024 });
    // Adjust past u32::MAX is refused, never wrapped.
    let mut warp = vec![93u8];
    put_u32(&mut warp, 42);
    put_u32(&mut warp, u32::MAX);
    let err = ch.on_message(&warp).unwrap_err();
    assert!(matches!(err, ChannelError::WindowOverflow { .. }), "{err}");
}

#[test]
fn oversize_payload_refused_even_with_window() {
    let mut ch = open_channel();
    let mut data = vec![94u8];
    put_u32(&mut data, 42);
    put_string(&mut data, &vec![b'z'; MAX_PACKET as usize + 1]);
    let err = ch.on_message(&data).unwrap_err();
    assert!(matches!(err, ChannelError::OversizePayload { .. }), "{err}");
}

#[test]
fn exit_status_passes_through_and_signal_is_255() {
    let mut ch = open_channel();
    let mut st = vec![98u8];
    put_u32(&mut st, 42);
    put_string(&mut st, b"exit-status");
    st.push(0);
    put_u32(&mut st, 3);
    assert_eq!(ch.on_message(&st).unwrap(), ChannelEvent::Exit);
    assert_eq!(ch.exit(), Some(&Exit::Status(3)));
    assert_eq!(ch.exit().unwrap().code(), 3);
    let mut ch2 = open_channel();
    let mut sig = vec![98u8];
    put_u32(&mut sig, 42);
    put_string(&mut sig, b"exit-signal");
    sig.push(0);
    put_string(&mut sig, b"KILL");
    sig.push(0);
    put_string(&mut sig, b"killed");
    put_string(&mut sig, b"en");
    assert_eq!(ch2.on_message(&sig).unwrap(), ChannelEvent::Exit);
    assert_eq!(ch2.exit().unwrap().code(), 255);
    assert!(matches!(ch2.exit(), Some(Exit::Signal { .. })));
    // A signal with no name is meaningless: refused, not defaulted.
    let mut noname = vec![98u8];
    put_u32(&mut noname, 42);
    put_string(&mut noname, b"exit-signal");
    noname.push(0);
    put_string(&mut noname, b"");
    noname.push(0);
    put_string(&mut noname, b"");
    put_string(&mut noname, b"en");
    assert!(matches!(
        open_channel().on_message(&noname),
        Err(ChannelError::SignalWithoutName)
    ));
}

#[test]
fn request_builders_carry_reply_flags_and_shapes() {
    let ch = open_channel();
    let pty = ch.pty_request("xterm-256color", 80, 24, 0, 0, &[(1, 3), (5, 4)]);
    assert_eq!(pty[0], MSG_CHANNEL_REQUEST);
    let mut r = Reader::new(&pty[1..]);
    let _id = r.u32().unwrap();
    assert_eq!(r.string().unwrap(), b"pty-req");
    assert_eq!(r.u8().unwrap(), 1, "pty-req wants its reply");
    assert_eq!(r.string().unwrap(), b"xterm-256color");
    let exec = ch.exec_request("echo hi");
    let mut re = Reader::new(&exec[1..]);
    let _id = re.u32().unwrap();
    assert_eq!(re.string().unwrap(), b"exec");
    assert_eq!(re.u8().unwrap(), 1);
    assert_eq!(re.string().unwrap(), b"echo hi");
    let shell = ch.shell_request();
    let mut rs = Reader::new(&shell[1..]);
    let _id = rs.u32().unwrap();
    assert_eq!(rs.string().unwrap(), b"shell");
    let wc = ch.window_change(100, 30, 0, 0);
    let mut rw = Reader::new(&wc[1..]);
    let _id = rw.u32().unwrap();
    assert_eq!(rw.string().unwrap(), b"window-change");
    assert_eq!(rw.u8().unwrap(), 0, "window-change never waits");
    let env = ch.env_request("LANG", "C.UTF-8");
    let mut renv = Reader::new(&env[1..]);
    let _id = renv.u32().unwrap();
    assert_eq!(renv.string().unwrap(), b"env");
    // Data frames carry the REMOTE id (42), learned from the confirmation.
    let d = ch.data(b"hi");
    assert_eq!(d[0], MSG_CHANNEL_DATA);
    assert_eq!(&d[1..5], &42u32.to_be_bytes());
    let c = ch.close();
    assert_eq!(c[0], MSG_CHANNEL_CLOSE);
}

#[test]
fn pty_modes_end_with_tty_op_end() {
    assert_eq!(encode_pty_modes(&[]), vec![0]);
    let m = encode_pty_modes(&[(1, 3)]);
    assert_eq!(m, vec![1, 0, 0, 0, 3, 0]);
}
