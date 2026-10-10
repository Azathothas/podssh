//! What the user sees: each message of the peer as a line of stdout, and each
//! notice as a line of stderr; or, with `--jsonl`, each event as one JSON
//! object on stdout. The peer's words are made safe for a terminal: no
//! control character and no direction override reaches it.

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Where the events go.
pub struct Output<W> {
    out: W,
    jsonl: bool,
    say: Box<dyn Fn(String) + Send>,
}

impl<W: AsyncWrite + Unpin> Output<W> {
    pub fn new(out: W, jsonl: bool, say: impl Fn(String) + Send + 'static) -> Output<W> {
        Output { out, jsonl, say: Box::new(say) }
    }

    /// A message of the peer: a line of stdout.
    pub async fn message(&mut self, from: &str, id: u64, text: &str) {
        let line = if self.jsonl {
            serde_json::json!({ "event": "message", "from": from, "id": id, "text": text }).to_string()
        } else {
            format!("{}: {}", safe(from), safe(text))
        };
        self.line(&line).await;
    }

    /// A notice: a line of stderr, or with `--jsonl` the event as JSON on
    /// stdout, with `fields` beside its name.
    pub async fn notice(&mut self, event: &str, fields: serde_json::Value, line: String) {
        if !self.jsonl {
            // A notice with no words is for scripts alone.
            if !line.is_empty() {
                (self.say)(line);
            }
            return;
        }
        let mut object = serde_json::Map::new();
        object.insert("event".into(), event.into());
        if let serde_json::Value::Object(more) = fields {
            object.extend(more);
        }
        self.line(&serde_json::Value::Object(object).to_string()).await;
    }

    async fn line(&mut self, line: &str) {
        // A closed stdout ends no conversation: the peer's bytes still count.
        let _ = self.out.write_all(format!("{line}\n").as_bytes()).await;
        let _ = self.out.flush().await;
    }
}

/// The peer's words, safe for a terminal: each control character and each
/// direction override becomes U+FFFD.
pub fn safe(text: &str) -> String {
    let unsafe_char = |c: char| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    text.chars().map(|c| if unsafe_char(c) { '\u{fffd}' } else { c }).collect()
}
