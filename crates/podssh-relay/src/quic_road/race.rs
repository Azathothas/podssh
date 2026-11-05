//! The race of QUIC and a TCP road to one relay host (T-667): QUIC alone for
//! a head start, then the TCP road beside it, or at once when QUIC failed.
//! The first session is kept and the other road is dropped where it stands,
//! which closes its connection at once: two connections to one host for a
//! short time, as the race between relay hosts makes (rule 2 of `AGENTS.md`).
//! An answer that either road would get alike, the relay's refusal of a token
//! or a target, ends the race where it comes. A road's own failure does not:
//! the race waits for the other, and when both failed it gives the TCP
//! road's, which the opener classifies as it did before QUIC.

use std::future::Future;
use std::time::Duration;

/// How a race ended.
#[derive(Debug)]
pub struct Raced<T, E> {
    /// The session, or the failure that the caller sees.
    pub result: Result<T, E>,
    /// Whether QUIC gave it.
    pub by_quic: bool,
    /// QUIC's own failure, where QUIC failed and TCP gave the result.
    pub quic_failed: Option<E>,
}

/// Race `quic` and `tcp`: `tcp` is not polled before `head` has passed, or
/// before `quic` failed; `decisive` says which failure ends the race on
/// either road. Each future is dropped once the race ends.
pub async fn race<T, E, Q, P>(quic: Q, tcp: P, head: Duration, decisive: impl Fn(&E) -> bool) -> Raced<T, E>
where
    Q: Future<Output = Result<T, E>>,
    P: Future<Output = Result<T, E>>,
{
    tokio::pin!(quic);
    tokio::pin!(tcp);
    let start_at = tokio::time::Instant::now() + head;
    let mut tcp_on = false;
    let mut quic_failed: Option<E> = None;
    let mut tcp_failed: Option<E> = None;
    loop {
        tokio::select! {
            // Of two that came in one turn, QUIC's.
            biased;
            got = &mut quic, if quic_failed.is_none() => match got {
                Ok(t) => return Raced { result: Ok(t), by_quic: true, quic_failed: None },
                Err(e) if decisive(&e) => return Raced { result: Err(e), by_quic: true, quic_failed: None },
                Err(e) => match tcp_failed.take() {
                    // Both roads failed: the TCP road's words, as before QUIC.
                    Some(tcp_e) => return Raced { result: Err(tcp_e), by_quic: false, quic_failed: Some(e) },
                    None => {
                        quic_failed = Some(e);
                        tcp_on = true;
                    }
                },
            },
            got = &mut tcp, if tcp_on && tcp_failed.is_none() => match got {
                Ok(t) => return Raced { result: Ok(t), by_quic: false, quic_failed },
                Err(e) if decisive(&e) || quic_failed.is_some() => {
                    return Raced { result: Err(e), by_quic: false, quic_failed };
                }
                // QUIC may still give the session.
                Err(e) => tcp_failed = Some(e),
            },
            () = tokio::time::sleep_until(start_at), if !tcp_on => tcp_on = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use tokio::time::Instant;

    use super::*;

    const HEAD: Duration = Duration::from_millis(300);
    /// When a road was first polled, in ms after the race began; `u64::MAX`
    /// while it never was.
    type Polled = Arc<AtomicU64>;

    fn never() -> Polled {
        Arc::new(AtomicU64::new(u64::MAX))
    }

    /// A road that answers `result` after `after`, and notes when it was
    /// first polled.
    async fn road(
        began: Instant,
        polled: Polled,
        after: Duration,
        result: Result<&'static str, &'static str>,
    ) -> Result<&'static str, &'static str> {
        polled.store(began.elapsed().as_millis() as u64, Ordering::SeqCst);
        tokio::time::sleep(after).await;
        result
    }

    fn refusal(e: &&'static str) -> bool {
        e.starts_with("refused")
    }

    /// A QUIC that answers within its head start: the TCP road is never
    /// polled, so it never connects.
    #[tokio::test(start_paused = true)]
    async fn a_quic_answer_within_the_head_start_starts_no_tcp() {
        let (began, tcp) = (Instant::now(), never());
        let quic = road(began, never(), Duration::from_millis(80), Ok("quic"));
        let raced = race(quic, road(began, tcp.clone(), Duration::ZERO, Ok("tcp")), HEAD, refusal).await;
        assert_eq!((raced.result, raced.by_quic), (Ok("quic"), true));
        assert_eq!(tcp.load(Ordering::SeqCst), u64::MAX, "the TCP road was polled");
    }

    /// A QUIC that says nothing: the TCP road starts at the head start, and
    /// its session is kept; QUIC's is dropped where it stands.
    #[tokio::test(start_paused = true)]
    async fn a_silent_quic_gives_way_to_tcp_at_the_head_start() {
        let (began, tcp) = (Instant::now(), never());
        let quic = road(began, never(), Duration::from_secs(3600), Ok("quic"));
        let raced = race(quic, road(began, tcp.clone(), Duration::from_millis(50), Ok("tcp")), HEAD, refusal).await;
        assert_eq!((raced.result, raced.by_quic), (Ok("tcp"), false));
        assert_eq!(tcp.load(Ordering::SeqCst), 300, "TCP starts at the head start");
        assert_eq!(began.elapsed(), Duration::from_millis(350));
    }

    /// QUIC that fails at once (a probe that UDP refused): TCP at once, and
    /// QUIC's failure is kept for the caller.
    #[tokio::test(start_paused = true)]
    async fn a_failed_quic_starts_tcp_at_once() {
        let (began, tcp) = (Instant::now(), never());
        let quic = road(began, never(), Duration::from_millis(10), Err("no UDP"));
        let raced = race(quic, road(began, tcp.clone(), Duration::from_millis(50), Ok("tcp")), HEAD, refusal).await;
        assert_eq!((raced.result, raced.quic_failed), (Ok("tcp"), Some("no UDP")));
        assert_eq!(tcp.load(Ordering::SeqCst), 10, "TCP starts when QUIC failed, not at the head start");
    }

    /// The relay's refusal over QUIC ends the race: TCP would get the same.
    #[tokio::test(start_paused = true)]
    async fn the_relay_s_refusal_over_quic_ends_the_race() {
        let (began, tcp) = (Instant::now(), never());
        let quic = road(began, never(), Duration::from_millis(400), Err("refused 403"));
        let raced = race(quic, road(began, tcp.clone(), Duration::from_secs(5), Ok("tcp")), HEAD, refusal).await;
        assert_eq!((raced.result, raced.by_quic), (Err("refused 403"), true));
        assert_eq!(began.elapsed(), Duration::from_millis(400), "no wait for the TCP road");
    }

    /// TCP's own failure while QUIC goes on: the race waits for QUIC.
    #[tokio::test(start_paused = true)]
    async fn a_tcp_failure_waits_for_quic() {
        let began = Instant::now();
        let quic = road(began, never(), Duration::from_secs(2), Ok("quic"));
        let tcp = road(began, never(), Duration::from_millis(100), Err("TLS cut"));
        let raced = race(quic, tcp, HEAD, refusal).await;
        assert_eq!((raced.result, raced.by_quic), (Ok("quic"), true));
    }

    /// Both roads failed: the TCP road's failure, in either order.
    #[tokio::test(start_paused = true)]
    async fn both_failed_give_the_tcp_road_s_failure() {
        let began = Instant::now();
        let quic = road(began, never(), Duration::from_millis(500), Err("no answer over QUIC"));
        let tcp = road(began, never(), Duration::from_millis(50), Err("TLS cut"));
        let raced = race(quic, tcp, HEAD, refusal).await;
        assert_eq!((raced.result, raced.quic_failed), (Err("TLS cut"), Some("no answer over QUIC")));
        let quic = road(began, never(), Duration::from_millis(10), Err("no UDP"));
        let tcp = road(began, never(), Duration::from_millis(50), Err("TLS cut"));
        let raced = race(quic, tcp, HEAD, refusal).await;
        assert_eq!((raced.result, raced.quic_failed), (Err("TLS cut"), Some("no UDP")));
    }
}
