//! What the user sees: each message of the peer as a line of stdout, and each
//! notice as a line of stderr; or, with `--jsonl`, each event as one JSON
//! object on stdout, with the peer's words as they came. On a terminal, the
//! peer's words are made safe by podssh's one definition of safe text: no
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

    /// A message of a user of an IRC channel, or to this client alone: a
    /// line of stdout.
    pub async fn said(&mut self, from: &str, to_me: bool, text: &str) {
        let line = if self.jsonl {
            serde_json::json!({ "event": "message", "from": from, "private": to_me, "text": text }).to_string()
        } else if to_me {
            format!("{} (to you): {}", safe(from), safe(text))
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

/// The peer's words, safe for a terminal, as each line that podssh prints
/// from a peer: each control character and each direction override goes,
/// and each run of whitespace is one space.
pub fn safe(text: &str) -> String {
    podssh_ws::text::one_line(text)
}
