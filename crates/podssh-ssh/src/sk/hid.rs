//! CTAPHID, the framing of FIDO2 over USB HID (CTAP 2.0, section 8.1): a
//! message goes in reports of 64 bytes, on a channel that the device gives
//! at INIT. The reports come and go through [`Reports`]: the device file on
//! Linux, and a device in software in the tests.

use std::time::{Duration, Instant};

/// The size of a report of a FIDO device.
pub(crate) const REPORT: usize = 64;

const BROADCAST: u32 = 0xffff_ffff;
const INIT: u8 = 0x86;
const CBOR: u8 = 0x90;
const CANCEL: u8 = 0x91;
const KEEPALIVE: u8 = 0xbb;
const ERROR: u8 = 0xbf;
/// INIT's capability: the device speaks CTAP2 (CBOR).
const CAPABILITY_CBOR: u8 = 0x04;
/// KEEPALIVE's status: the device waits for a touch.
const UP_NEEDED: u8 = 2;
/// The data of an initial report, and of a continuation report.
const FIRST: usize = REPORT - 7;
const NEXT: usize = REPORT - 5;
/// The largest message: an initial report and 128 continuation reports.
const MAX_MESSAGE: usize = FIRST + 128 * NEXT;
/// The time of a device to answer INIT.
const INIT_LIMIT: Duration = Duration::from_secs(5);

/// The reports of one device.
pub(crate) trait Reports {
    /// Send one report.
    fn send(&mut self, report: &[u8; REPORT]) -> std::io::Result<()>;
    /// The next report of the device, waiting at most `wait`; `None` when
    /// none came.
    fn receive(&mut self, wait: Duration) -> std::io::Result<Option<[u8; REPORT]>>;
}

/// A channel of a device, which INIT gave.
pub(crate) struct Channel<R: Reports> {
    reports: R,
    cid: u32,
}

impl<R: Reports> Channel<R> {
    /// Ask the device for a channel. A device that speaks U2F only (CTAP1)
    /// is refused, as podssh speaks CTAP2.
    pub fn open(mut reports: R, nonce: [u8; 8]) -> Result<Channel<R>, String> {
        send(&mut reports, BROADCAST, INIT, &nonce)?;
        let until = Instant::now() + INIT_LIMIT;
        loop {
            let Some((command, data)) = receive(&mut reports, BROADCAST, until)? else {
                return Err(format!("the device did not answer INIT within {} s", INIT_LIMIT.as_secs()));
            };
            // The answer to another program's INIT carries its nonce.
            if command != INIT || data.len() < 17 || data[..8] != nonce {
                continue;
            }
            if data[16] & CAPABILITY_CBOR == 0 {
                return Err("the device speaks U2F (CTAP1) only, and podssh speaks CTAP2 (FIDO2)".into());
            }
            let cid = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            return Ok(Channel { reports, cid });
        }
    }

    /// Send the CTAP2 command `command` with its CBOR, and wait at most
    /// `limit` for the answer: its status and its CBOR. When the time is
    /// over, podssh cancels the command, and says whether the device waited
    /// for a touch.
    pub fn cbor(&mut self, command: u8, payload: &[u8], limit: Duration) -> Result<(u8, Vec<u8>), String> {
        let mut message = Vec::with_capacity(1 + payload.len());
        message.push(command);
        message.extend_from_slice(payload);
        send(&mut self.reports, self.cid, CBOR, &message)?;
        let until = Instant::now() + limit;
        let mut touch = false;
        loop {
            match receive(&mut self.reports, self.cid, until)? {
                Some((KEEPALIVE, data)) => touch |= data.first() == Some(&UP_NEEDED),
                Some((CBOR, data)) => {
                    let (&status, rest) = data.split_first().ok_or("the device's answer is empty")?;
                    return Ok((status, rest.to_vec()));
                }
                Some((ERROR, data)) => {
                    return Err(format!(
                        "the device refused the message (CTAPHID error {:#04x})",
                        data.first().copied().unwrap_or(0)
                    ))
                }
                Some((other, _)) => return Err(format!("the device answered with the command {other:#04x}")),
                None => {
                    let _ = send(&mut self.reports, self.cid, CANCEL, &[]);
                    let secs = limit.as_secs();
                    return Err(if touch {
                        format!("nobody touched the security key within {secs} s")
                    } else {
                        format!("the security key did not answer within {secs} s")
                    });
                }
            }
        }
    }
}

/// Send a message on `cid`: an initial report, then continuation reports.
fn send<R: Reports>(reports: &mut R, cid: u32, command: u8, data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_MESSAGE {
        return Err(format!("a message of {} bytes, more than a device takes", data.len()));
    }
    let failed = |e: std::io::Error| format!("could not write to the device: {e}");
    let mut report = [0u8; REPORT];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = command;
    report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(FIRST);
    report[7..7 + first].copy_from_slice(&data[..first]);
    reports.send(&report).map_err(failed)?;
    for (seq, chunk) in data[first..].chunks(NEXT).enumerate() {
        let mut report = [0u8; REPORT];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = seq as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.send(&report).map_err(failed)?;
    }
    Ok(())
}

/// The next message on `cid`, as its command and its data; `None` when
/// `until` passed. Reports of other channels are another program's.
fn receive<R: Reports>(reports: &mut R, cid: u32, until: Instant) -> Result<Option<(u8, Vec<u8>)>, String> {
    let ours = cid.to_be_bytes();
    let (command, total, mut data) = loop {
        let Some(report) = next(reports, until)? else { return Ok(None) };
        if report[..4] != ours || report[4] & 0x80 == 0 {
            continue;
        }
        let total = usize::from(u16::from_be_bytes([report[5], report[6]]));
        if total > MAX_MESSAGE {
            return Err(format!("the device announced a message of {total} bytes"));
        }
        let mut data = Vec::with_capacity(total);
        data.extend_from_slice(&report[7..7 + total.min(FIRST)]);
        break (report[4], total, data);
    };
    let mut seq = 0u8;
    while data.len() < total {
        let Some(report) = next(reports, until)? else { return Ok(None) };
        if report[..4] != ours {
            continue;
        }
        if report[4] != seq {
            return Err(format!("the device's report {} came where {seq} was due", report[4]));
        }
        let take = (total - data.len()).min(NEXT);
        data.extend_from_slice(&report[5..5 + take]);
        seq += 1;
    }
    Ok(Some((command, data)))
}

/// The next report before `until`.
fn next<R: Reports>(reports: &mut R, until: Instant) -> Result<Option<[u8; REPORT]>, String> {
    let left = until.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Ok(None);
    }
    reports.receive(left).map_err(|e| format!("could not read the device: {e}"))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// A device that answers from a list, and keeps what it was sent.
    #[derive(Default)]
    struct Scripted {
        sent: Vec<[u8; REPORT]>,
        answers: VecDeque<[u8; REPORT]>,
    }

    impl Reports for &mut Scripted {
        fn send(&mut self, report: &[u8; REPORT]) -> std::io::Result<()> {
            self.sent.push(*report);
            Ok(())
        }

        fn receive(&mut self, _wait: Duration) -> std::io::Result<Option<[u8; REPORT]>> {
            Ok(self.answers.pop_front())
        }
    }

    fn initial(cid: u32, command: u8, total: usize, data: &[u8]) -> [u8; REPORT] {
        let mut report = [0u8; REPORT];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = command;
        report[5..7].copy_from_slice(&(total as u16).to_be_bytes());
        report[7..7 + data.len()].copy_from_slice(data);
        report
    }

    fn init_answer(nonce: [u8; 8], cid: u32, capabilities: u8) -> [u8; REPORT] {
        let mut data = nonce.to_vec();
        data.extend_from_slice(&cid.to_be_bytes());
        data.extend_from_slice(&[2, 5, 4, 1, capabilities]);
        initial(BROADCAST, INIT, 17, &data)
    }

    #[test]
    fn a_message_goes_in_reports_and_comes_back_whole() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut device = Scripted::default();
        // The answer to another program's INIT comes first, and is not ours.
        device.answers.push_back(init_answer([9; 8], 0x0bad_0bad, CAPABILITY_CBOR));
        device.answers.push_back(init_answer(nonce, 0x1234_5678, CAPABILITY_CBOR));
        let answer: Vec<u8> = (0..150u8).collect();
        let mut first = vec![0u8];
        first.extend_from_slice(&answer[..FIRST - 1]);
        device.answers.push_back(initial(0x1234_5678, KEEPALIVE, 1, &[UP_NEEDED]));
        device.answers.push_back(initial(0x1234_5678, CBOR, answer.len() + 1, &first));
        let mut next_report = |seq: u8, part: &[u8]| {
            let mut report = [0u8; REPORT];
            report[..4].copy_from_slice(&0x1234_5678u32.to_be_bytes());
            report[4] = seq;
            report[5..5 + part.len()].copy_from_slice(part);
            device.answers.push_back(report);
        };
        let rest = &answer[FIRST - 1..];
        next_report(0, &rest[..NEXT]);
        next_report(1, &rest[NEXT..]);
        let mut channel = Channel::open(&mut device, nonce).unwrap();
        let payload = vec![0xaa; 200];
        let (status, body) = channel.cbor(0x02, &payload, Duration::from_secs(1)).unwrap();
        assert_eq!((status, body), (0, answer));
        // INIT, then 201 bytes: 57 in the first report, then 59, 59 and 26.
        assert_eq!(device.sent.len(), 5);
        assert_eq!(&device.sent[0][..7], &[0xff, 0xff, 0xff, 0xff, INIT, 0, 8]);
        assert_eq!(&device.sent[1][..8], &[0x12, 0x34, 0x56, 0x78, CBOR, 0, 201, 0x02]);
        assert_eq!(device.sent[2][4], 0);
        assert_eq!(device.sent[4][4], 2);
        assert_eq!(&device.sent[4][5..5 + 26], &[0xaa; 26]);
        assert!(device.sent[4][5 + 26..].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_device_of_u2f_only_is_refused() {
        let nonce = [7; 8];
        let mut device = Scripted::default();
        device.answers.push_back(init_answer(nonce, 1, 0x01));
        let refused = Channel::open(&mut device, nonce).err().unwrap();
        assert!(refused.contains("U2F (CTAP1) only"), "{refused}");
    }

    /// With no answer, the command is cancelled, and the message says
    /// whether the device waited for a touch.
    #[test]
    fn no_answer_cancels_and_says_why() {
        let nonce = [3; 8];
        let mut device = Scripted::default();
        device.answers.push_back(init_answer(nonce, 5, CAPABILITY_CBOR));
        device.answers.push_back(initial(5, KEEPALIVE, 1, &[UP_NEEDED]));
        let mut channel = Channel::open(&mut device, nonce).unwrap();
        let late = channel.cbor(0x02, &[], Duration::from_secs(1)).unwrap_err();
        assert_eq!(late, "nobody touched the security key within 1 s");
        assert_eq!(device.sent.last().unwrap()[4], CANCEL);
    }
}
