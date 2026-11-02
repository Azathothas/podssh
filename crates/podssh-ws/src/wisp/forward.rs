//! A forwarder's session through a Wisp server (T-438): the template
//! `wisp+wss://HOST/PATH/`, a connection of its own for each session, and
//! one stream on it to the target, so that the WebSocket closes with the
//! session. The first word is waited for as a Worker's is: a server that
//! confirms streams says once the target's socket is open; one that does
//! not (version 1) says only that it could not reach the target, in a
//! CLOSE that comes within [`EARLY_WAIT`], which lets the next forwarder be
//! tried. The stream's end goes into the forwarder's status before the
//! session reads the end of its bytes.

use super::{Connect, End, OnEnd, Reason, Wisp, WispError};
use crate::forwarder::{Carried, Dial, Ended, ForwarderError, Status, Template, EARLY_WAIT};

/// A session to `host:port` through the Wisp server of `template`.
pub(crate) async fn open(
    template: &Template,
    host: &str,
    port: u16,
    dial: &Dial<'_>,
) -> Result<Carried, ForwarderError> {
    let url = template.fill(host, port).map_err(ForwarderError::Target)?;
    let how = Connect { trust: dial.trust, proxy: dial.proxy, timeout: dial.timeout, note: dial.note.clone() };
    let wisp = Wisp::connect(&url, &how).await.map_err(refused)?;
    let status = Status::default();
    let kept = status.clone();
    let on_end: OnEnd = Box::new(move |end: &End| kept.set_once(ended(end)));
    let mut stream = wisp.open_noting(host, port, dial.close_at_end, Some(on_end)).await.map_err(refused)?;
    let wait = if wisp.confirms() { dial.timeout } else { EARLY_WAIT };
    if let Err(e) = stream.opened(wait).await {
        stream.close().await;
        return Err(refused(e));
    }
    // The handle goes: the WebSocket closes once its one stream ends.
    drop(wisp);
    let (pipe, tasks) = stream.into_parts();
    Ok(Carried::of(pipe, status, tasks))
}

/// A failure of the road, in a forwarder's words.
fn refused(e: WispError) -> ForwarderError {
    match e {
        WispError::Connect(c) => ForwarderError::Connect(c),
        WispError::Gone { code, reason } => ForwarderError::Closed { code, reason },
        other => ForwarderError::Answer(other.to_string()),
    }
}

/// A stream's end as a forwarder's session ends: the target's CLOSE and
/// this side's are ordinary, and say nothing; each other reason is said.
pub(crate) fn ended(end: &End) -> Ended {
    match end {
        End::Closed(Reason::VOLUNTARY) => Ended::Closed { code: Some(1000), reason: "the target closed".into() },
        End::ClosedHere => Ended::Closed { code: Some(1000), reason: String::new() },
        End::Closed(reason) => Ended::Failed(format!("the Wisp server closed the stream: {reason}")),
        End::Gone { code, reason } => Ended::Closed { code: *code, reason: reason.clone() },
        End::Failed(why) => Ended::Failed(why.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectError;

    #[test]
    fn an_ordinary_end_is_a_close_1000_and_another_says_its_reason() {
        let target = Ended::Closed { code: Some(1000), reason: "the target closed".into() };
        assert_eq!(ended(&End::Closed(Reason::VOLUNTARY)), target);
        assert!(matches!(ended(&End::ClosedHere), Ended::Closed { code: Some(1000), .. }));
        let cut = ended(&End::Closed(Reason::NETWORK));
        assert_eq!(cut, Ended::Failed("the Wisp server closed the stream: 0x03, a network error".into()));
        let gone = ended(&End::Gone { code: Some(1011), reason: "down".into() });
        assert_eq!(gone, Ended::Closed { code: Some(1011), reason: "down".into() });
    }

    #[test]
    fn a_failure_of_the_road_is_a_forwarder_s_failure() {
        let line = refused(WispError::Closed(Reason::UNREACHABLE)).line("wisp (wisp+wss://w.example/)");
        assert_eq!(
            line,
            "the forwarder wisp (wisp+wss://w.example/): the Wisp server closed the stream: 0x42, the destination is \
             unreachable (its name may not resolve)"
        );
        let upgrade = refused(WispError::Connect(ConnectError::Refused { status: 403, body: String::new() }));
        assert_eq!(upgrade, ForwarderError::Connect(ConnectError::Refused { status: 403, body: String::new() }));
        let gone = refused(WispError::Gone { code: Some(1011), reason: String::new() });
        assert!(matches!(gone, ForwarderError::Closed { code: Some(1011), .. }));
    }
}
