//! The QUIC of the iroh road (T-665): the transport settings that podssh
//! may set where iroh 1.4's builder lets it, and iroh's own beside them, so
//! that the A/B run of `scripts/iroh-ab.py` can measure each arm on one
//! wide-area path before a default depends on it.
//!
//! READ in iroh 1.4.1 and noq-proto 1.4.0 (the QUIC that iroh builds): an
//! initial round trip of 333 ms, an initial window of 12000 bytes (Cubic,
//! with no HyStart; 14720 clamped to 10 packets), a stream's receive window
//! of 1.25 MB, a connection's with no bound, and a first MTU of 1200, the
//! floor, which osewa takes too.
//! iroh's sockets already ask for 7 MiB of buffer each way by `SO_RCVBUF`
//! and `SO_SNDBUF` (netwatch), never the `FORCE` forms, so podssh asks
//! nothing more of them.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{ControllerFactory, QuicTransportConfig, VarInt};
use noq_proto::congestion::{Bbr3Config, CubicConfig, NewRenoConfig};

/// The variable that chooses the arm: `iroh` (iroh's own), `tuned`, or
/// words of [`WORDS`] separated by commas.
pub const QUIC_ENV: &str = "PODSSH_IROH_QUIC";

/// The words of [`QUIC_ENV`], each one setting, and what each sets.
pub const WORDS: &[(&str, &str)] = &[
    ("iroh", "iroh's own settings: no word of podssh's"),
    ("tuned", "rtt, window and streams"),
    ("rtt", "an initial round trip of 100 ms, for 333 ms"),
    ("window", "an initial window of 32 packets, for 10"),
    ("streams", "receive windows of 8 MiB a stream, for 1.25 MB, and 16 MiB a connection, for no bound"),
    ("cubic", "Cubic, iroh's congestion controller"),
    ("bbr", "BBR, version 3, in place of Cubic"),
    ("newreno", "NewReno in place of Cubic"),
];

/// The initial round trip of `rtt`, osewa's: a first loss is found sooner
/// than after iroh's 333 ms.
pub const INITIAL_RTT: Duration = Duration::from_millis(100);
/// The initial window of `window`, in packets of [`PACKET`] bytes, osewa's.
pub const INITIAL_PACKETS: u64 = 32;
/// The first packet's size, QUIC's floor and iroh's first MTU.
pub const PACKET: u64 = 1200;
/// The receive windows of `streams`: a stream's above the resumable layer's
/// 4 MiB in flight (its replay buffer), so that QUIC is not what bounds a
/// session; a connection's for two such streams, a terminal's and a copy's
/// (T-666), where iroh sets no bound.
pub const STREAM_WINDOW: u64 = 8 << 20;
pub const CONNECTION_WINDOW: u64 = 16 << 20;

/// The arm until the A/B run shows what helps (T-665): iroh's own.
pub const DEFAULT: &str = "iroh";

/// The congestion controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    Cubic,
    Bbr,
    NewReno,
}

/// The settings of one arm: `None` keeps iroh's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    pub initial_rtt: Option<Duration>,
    /// In packets of [`PACKET`] bytes.
    pub initial_packets: Option<u64>,
    /// A stream's, then the connection's, in bytes.
    pub receive_windows: Option<(u64, u64)>,
    pub congestion: Congestion,
}

impl Tuning {
    /// iroh's own settings.
    pub const IROH: Tuning =
        Tuning { initial_rtt: None, initial_packets: None, receive_windows: None, congestion: Congestion::Cubic };

    /// osewa's settings where iroh lets podssh set them, with Cubic.
    pub const TUNED: Tuning = Tuning {
        initial_rtt: Some(INITIAL_RTT),
        initial_packets: Some(INITIAL_PACKETS),
        receive_windows: Some((STREAM_WINDOW, CONNECTION_WINDOW)),
        congestion: Congestion::Cubic,
    };

    /// The arm of [`QUIC_ENV`]: [`DEFAULT`] when it is unset or empty; a
    /// word that is not one of [`WORDS`] is refused, as a measurement of the
    /// wrong arm would say nothing.
    pub fn from_environment() -> Result<Tuning, String> {
        Tuning::from_value(std::env::var(QUIC_ENV).ok().as_deref())
    }

    /// The arm of the variable's value.
    pub fn from_value(value: Option<&str>) -> Result<Tuning, String> {
        let text = value.map(str::trim).filter(|v| !v.is_empty()).unwrap_or(DEFAULT);
        let mut tuning = Tuning::IROH;
        let mut congestion = None;
        for word in text.split(',').map(|w| w.trim().to_ascii_lowercase()) {
            let chosen = match word.as_str() {
                "iroh" => None,
                "tuned" => {
                    let Tuning { initial_rtt, initial_packets, receive_windows, .. } = Tuning::TUNED;
                    tuning = Tuning { initial_rtt, initial_packets, receive_windows, ..tuning };
                    None
                }
                "rtt" => {
                    tuning.initial_rtt = Some(INITIAL_RTT);
                    None
                }
                "window" => {
                    tuning.initial_packets = Some(INITIAL_PACKETS);
                    None
                }
                "streams" => {
                    tuning.receive_windows = Some((STREAM_WINDOW, CONNECTION_WINDOW));
                    None
                }
                "cubic" => Some(Congestion::Cubic),
                "bbr" => Some(Congestion::Bbr),
                "newreno" => Some(Congestion::NewReno),
                _ => {
                    let known: Vec<&str> = WORDS.iter().map(|(w, _)| *w).collect();
                    return Err(format!("{QUIC_ENV}: {word:?} is not one of {}", known.join(", ")));
                }
            };
            if let Some(chosen) = chosen {
                if congestion.is_some_and(|had| had != chosen) {
                    return Err(format!("{QUIC_ENV}: {text:?} names two congestion controllers; give one"));
                }
                congestion = Some(chosen);
            }
        }
        tuning.congestion = congestion.unwrap_or(Congestion::Cubic);
        Ok(tuning)
    }

    /// The words of this arm, as the A/B record keeps them.
    pub fn words(&self) -> String {
        let mut words = Vec::new();
        if self.initial_rtt.is_some() {
            words.push("rtt");
        }
        if self.initial_packets.is_some() {
            words.push("window");
        }
        if self.receive_windows.is_some() {
            words.push("streams");
        }
        words.push(match self.congestion {
            Congestion::Cubic => "cubic",
            Congestion::Bbr => "bbr",
            Congestion::NewReno => "newreno",
        });
        words.join(",")
    }

    /// iroh's transport settings with this arm's, and a line for each of
    /// them that iroh's types refused, whose iroh's own value is kept.
    /// iroh's builder, not quinn's bare one: it keeps the keep-alives, the
    /// paths' idle times and the multipath that iroh's hole punching needs.
    pub fn config(&self) -> (QuicTransportConfig, Vec<String>) {
        let mut kept = Vec::new();
        let mut builder = QuicTransportConfig::builder();
        if let Some(rtt) = self.initial_rtt {
            builder = builder.initial_rtt(rtt);
        }
        if let Some((stream, connection)) = self.receive_windows {
            if let (Ok(s), Ok(c)) = (VarInt::from_u64(stream), VarInt::from_u64(connection)) {
                builder = builder.stream_receive_window(s).receive_window(c);
            } else {
                let past = format!("receive windows of {stream} and {connection} bytes are past what QUIC can say");
                kept.push(format!("{past}; iroh's own are kept"));
            }
        }
        // iroh's own controller is left alone when nothing of it changes.
        if self.congestion != Congestion::Cubic || self.initial_packets.is_some() {
            builder = builder.congestion_controller_factory(self.controller());
        }
        (builder.build(), kept)
    }

    /// The congestion controller of this arm, with its initial window.
    pub fn controller(&self) -> Arc<dyn ControllerFactory + Send + Sync + 'static> {
        let window = self.initial_packets.map(|packets| packets.saturating_mul(PACKET));
        match self.congestion {
            Congestion::Cubic => {
                let mut config = CubicConfig::default();
                if let Some(window) = window {
                    config.initial_window(window);
                }
                Arc::new(config)
            }
            Congestion::Bbr => {
                let mut config = Bbr3Config::default();
                if let Some(window) = window {
                    config.initial_window(window);
                }
                Arc::new(config)
            }
            Congestion::NewReno => {
                let mut config = NewRenoConfig::default();
                if let Some(window) = window {
                    config.initial_window(window);
                }
                Arc::new(config)
            }
        }
    }
}

impl std::fmt::Display for Tuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Tuning::IROH {
            return f.write_str("iroh's own settings");
        }
        let mut parts = Vec::new();
        if let Some(rtt) = self.initial_rtt {
            parts.push(format!("an initial round trip of {} ms", rtt.as_millis()));
        }
        if let Some(packets) = self.initial_packets {
            parts.push(format!("an initial window of {packets} packets"));
        }
        if let Some((stream, connection)) = self.receive_windows {
            let (s, c) = (stream >> 20, connection >> 20);
            parts.push(format!("receive windows of {s} MiB a stream and {c} MiB a connection"));
        }
        let controller = match self.congestion {
            Congestion::Cubic => "Cubic",
            Congestion::Bbr => "BBR",
            Congestion::NewReno => "NewReno",
        };
        parts.push(controller.to_string());
        write!(f, "{} ({})", parts.join(", "), self.words())
    }
}

#[cfg(test)]
#[path = "tuning_tests.rs"]
mod tests;
