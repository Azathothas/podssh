//! The words of a Piping Server's answer to a sender, as nwtgck's servers
//! and `piping.onrender.com` wrote them (T-497, 2026-11-06).

use super::exchange::{delivered, delivered_whole};

/// nwtgck/piping-server 1.12.9, a transfer that ended.
const SENT: &str = "[INFO] Waiting for 1 receiver(s)...\n[INFO] 1 receiver(s) has/have been connected.\n\
                    [INFO] Start sending to 1 receiver(s)!\n[INFO] Sent successfully!\n\
                    [INFO] All receiver(s) was/were received successfully.\n";
/// `piping.onrender.com`, a POST of 64 KiB whose transfer its front cut:
/// the answer ends after its start.
const CUT: &str = "[INFO] Waiting for 1 receiver(s)...\n[INFO] 1 receiver(s) has/have been connected.\n\
                   [INFO] Start sending to 1 receiver(s)!\n";
/// piping-server-rust 0.18.0, a receiver that took the whole body and closed.
const HALFWAY: &str = "[INFO] Waiting for 1 receiver(s)...\n[INFO] A receiver was connected.\n\
                       [INFO] Start sending to 1 receiver(s)!\n[INFO] All receiver(s) was/were halfway disconnected.\n";

#[test]
fn a_transfer_that_ended_is_a_delivery() {
    assert_eq!(delivered(SENT), Ok(()));
    assert_eq!(delivered_whole(SENT), Ok(()));
}

#[test]
fn an_answer_cut_after_the_start_is_no_delivery_of_a_whole_piece() {
    let why = delivered_whole(CUT).unwrap_err();
    assert!(why.contains("before its receiver took the whole body"), "{why}");
}

#[test]
fn a_halfway_close_after_a_whole_piece_is_a_delivery_and_an_error_is_not() {
    assert_eq!(delivered_whole(HALFWAY), Ok(()));
    assert!(delivered(HALFWAY).is_err(), "a streamed body that its receiver left is no delivery");
    assert!(delivered_whole("[ERROR] All receiver(s) was/were halfway disconnected.\n").is_err());
}
