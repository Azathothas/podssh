//! The role's mailbox table (T-086): the nameplates and the mailboxes of
//! podssh's AppID, in memory, as magic-wormhole-mailbox-server's
//! `server.py` keeps them in SQLite. A nameplate points to a mailbox with a
//! random id; each has two sides at most, and a third is refused
//! (`crowded`), which is the mailbox's part of a code's single use. A side
//! that released a nameplate cannot claim it again; a nameplate goes once
//! each side released it, a mailbox once each side closed it, and each of
//! them after 20 minutes, as a code lives 10. Each table, message and body
//! is bounded, so that no client fills the role.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::APPID;
use crate::session::secret::{Entropy, OsEntropy};

/// The sides of a nameplate and of a mailbox: the two ends of one code.
pub const SIDES: usize = 2;
/// The nameplates that `allocate` gives, from 1.
pub const ALLOCATED: u32 = 999;
/// The nameplates and the mailboxes held at once.
pub const HELD: usize = 4096;
/// The messages of one mailbox: a pairing adds six.
pub const MESSAGES: usize = 32;
/// The hex digits of one body.
pub const BODY_MOST: usize = 16 * 1024;
/// The bytes of a phase, of a side and of a nameplate.
pub const PHASE_MOST: usize = 32;
pub const SIDE_MOST: usize = 64;
pub const NAMEPLATE_MOST: usize = 40;
/// How long a nameplate and a mailbox live, at most.
pub const LIFE: Duration = Duration::from_secs(20 * 60);
/// The messages that wait for one client's writer.
pub const OUTBOX: usize = 256;

/// Where the messages to one client go.
pub type Outbox = mpsc::Sender<String>;

/// Each nameplate and mailbox of the role.
#[derive(Default)]
pub struct Table {
    state: Mutex<State>,
    serial: AtomicU64,
}

#[derive(Default)]
struct State {
    plates: HashMap<String, Plate>,
    boxes: HashMap<String, Boxed>,
}

struct Plate {
    mailbox: String,
    /// Each side, and whether it holds its claim.
    sides: Vec<(String, bool)>,
    made: Instant,
}

struct Boxed {
    /// Each side, and whether it holds the mailbox open.
    sides: Vec<(String, bool)>,
    messages: Vec<Value>,
    listeners: Vec<(u64, Outbox)>,
    made: Instant,
}

/// One client's connection: its side, and what it did once.
pub struct Conn {
    serial: u64,
    outbox: Outbox,
    side: Option<String>,
    allocated: bool,
    claimed: Option<String>,
    released: bool,
    opened: Option<String>,
    closed: bool,
}

type Answered = Result<Vec<Value>, String>;

impl Table {
    /// A new client, whose messages go to `outbox`.
    pub fn connection(&self, outbox: Outbox) -> Conn {
        let serial = self.serial.fetch_add(1, Ordering::SeqCst);
        Conn {
            serial,
            outbox,
            side: None,
            allocated: false,
            claimed: None,
            released: false,
            opened: None,
            closed: false,
        }
    }

    /// The answers to one command of `conn`, its `ack` first; an `error`
    /// with the command in `orig` for one that is refused.
    pub fn handle(&self, conn: &mut Conn, command: &Value) -> Vec<Value> {
        let mut answers = vec![json!({ "type": "ack", "id": command.get("id").cloned().unwrap_or(Value::Null) })];
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut state);
        let answered = match command["type"].as_str().unwrap_or_default() {
            "ping" => match command.get("ping") {
                Some(ping) => Ok(vec![json!({ "type": "pong", "pong": ping })]),
                None => Err("ping requires 'ping'".to_string()),
            },
            "bind" => bind_side(conn, command),
            _ if conn.side.is_none() => Err("must bind first".into()),
            "list" => Ok(vec![list(&state)]),
            "allocate" => allocate(&mut state, conn),
            "claim" => claim(&mut state, conn, command),
            "release" => release(&mut state, conn, command),
            "open" => open(&mut state, conn, command),
            "add" => add(&mut state, conn, command),
            "close" => close(&mut state, conn, command),
            _ => Err("unknown type".into()),
        };
        match answered {
            Ok(more) => answers.extend(more),
            Err(why) => answers.push(json!({ "type": "error", "error": why, "orig": command })),
        }
        answers
    }

    /// `conn` ended: it hears nothing more. Its sides stay until they are
    /// closed or their life ends, as a client may come back.
    pub fn gone(&self, conn: &Conn) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(boxed) = conn.opened.as_ref().and_then(|id| state.boxes.get_mut(id)) {
            boxed.listeners.retain(|(serial, _)| *serial != conn.serial);
        }
    }
}

/// The mailbox protocol's `bind`: this connection's AppID and side.
fn bind_side(conn: &mut Conn, command: &Value) -> Answered {
    if conn.side.is_some() {
        return Err("already bound".into());
    }
    let appid = command["appid"].as_str().ok_or("bind requires 'appid'")?;
    let side = command["side"].as_str().ok_or("bind requires 'side'")?;
    if appid != APPID {
        return Err(format!("this mailbox serves the AppID {APPID} alone"));
    }
    if side.is_empty() || side.len() > SIDE_MOST || !side.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!("a side is 1 to {SIDE_MOST} letters and digits"));
    }
    conn.side = Some(side.to_string());
    Ok(Vec::new())
}

fn list(state: &State) -> Value {
    let mut ids: Vec<&String> = state.plates.keys().collect();
    ids.sort();
    let nameplates: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
    json!({ "type": "nameplates", "nameplates": nameplates })
}

fn allocate(state: &mut State, conn: &mut Conn) -> Answered {
    if conn.allocated {
        return Err("you already allocated one, don't be greedy".into());
    }
    let free = (1..=ALLOCATED).map(|n| n.to_string()).find(|n| !state.plates.contains_key(n));
    let free = free.ok_or("no nameplate is free now; try again later")?;
    // Allocating claims, as the server does; the client's claim follows.
    claim_side(state, side_of(conn), &free)?;
    conn.allocated = true;
    Ok(vec![json!({ "type": "allocated", "nameplate": free })])
}

fn claim(state: &mut State, conn: &mut Conn, command: &Value) -> Answered {
    if conn.claimed.is_some() {
        return Err("only one claim per connection".into());
    }
    let nameplate = command["nameplate"].as_str().ok_or("claim requires 'nameplate'")?;
    if nameplate.is_empty() || nameplate.len() > NAMEPLATE_MOST || !nameplate.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("a nameplate is 1 to {NAMEPLATE_MOST} digits"));
    }
    conn.claimed = Some(nameplate.to_string());
    let mailbox = claim_side(state, side_of(conn), nameplate)?;
    Ok(vec![json!({ "type": "claimed", "mailbox": mailbox })])
}

/// The mailbox of `nameplate`, made with it when it is new, and `side` in
/// both: a third side is refused.
fn claim_side(state: &mut State, side: String, nameplate: &str) -> Result<String, String> {
    if !state.plates.contains_key(nameplate) {
        if state.plates.len() >= HELD || state.boxes.len() >= HELD {
            return Err("the mailbox holds as many codes as it takes; try again later".into());
        }
        let id = random_id()?;
        let boxed = Boxed { sides: Vec::new(), messages: Vec::new(), listeners: Vec::new(), made: Instant::now() };
        state.boxes.insert(id.clone(), boxed);
        let plate = Plate { mailbox: id, sides: Vec::new(), made: Instant::now() };
        state.plates.insert(nameplate.to_string(), plate);
    }
    let Some(plate) = state.plates.get_mut(nameplate) else { return Err("the nameplate is gone".into()) };
    let held = plate.sides.iter().find(|(s, _)| *s == side).map(|(_, held)| *held);
    match held {
        Some(false) => return Err("reclaimed".into()),
        Some(true) => {}
        None if plate.sides.len() >= SIDES => return Err("crowded".into()),
        None => plate.sides.push((side.clone(), true)),
    }
    let id = plate.mailbox.clone();
    open_side(state, &id, side)?;
    Ok(id)
}

/// `side` holds the mailbox `id` open; a third side is refused.
fn open_side(state: &mut State, id: &str, side: String) -> Result<(), String> {
    let Some(boxed) = state.boxes.get_mut(id) else { return Err("no such mailbox".into()) };
    match boxed.sides.iter().position(|(s, _)| *s == side) {
        Some(at) => boxed.sides[at].1 = true,
        None if boxed.sides.len() >= SIDES => return Err("crowded".into()),
        None => boxed.sides.push((side, true)),
    }
    Ok(())
}

fn release(state: &mut State, conn: &mut Conn, command: &Value) -> Answered {
    if conn.released {
        return Err("only one release per connection".into());
    }
    let nameplate = match (command["nameplate"].as_str(), conn.claimed.as_deref()) {
        (Some(named), Some(claimed)) if named != claimed => {
            return Err("release and claim must use same nameplate".into());
        }
        (Some(named), _) => named.to_string(),
        (None, Some(claimed)) => claimed.to_string(),
        (None, None) => return Err("release without nameplate must follow claim".into()),
    };
    conn.released = true;
    let side = side_of(conn);
    if let Some(plate) = state.plates.get_mut(&nameplate) {
        if let Some((_, held)) = plate.sides.iter_mut().find(|(s, _)| *s == side) {
            *held = false;
        }
        if !plate.sides.iter().any(|(_, held)| *held) {
            state.plates.remove(&nameplate);
        }
    }
    Ok(vec![json!({ "type": "released" })])
}

fn open(state: &mut State, conn: &mut Conn, command: &Value) -> Answered {
    if conn.opened.is_some() {
        return Err("only one open per connection".into());
    }
    let id = command["mailbox"].as_str().ok_or("open requires 'mailbox'")?.to_string();
    open_side(state, &id, side_of(conn))?;
    let Some(boxed) = state.boxes.get_mut(&id) else { return Err("no such mailbox".into()) };
    boxed.listeners.push((conn.serial, conn.outbox.clone()));
    let kept = boxed.messages.clone();
    conn.opened = Some(id);
    Ok(kept)
}

fn add(state: &mut State, conn: &mut Conn, command: &Value) -> Answered {
    let Some(id) = conn.opened.clone().filter(|_| !conn.closed) else {
        return Err("must open mailbox before adding".into());
    };
    let phase = command["phase"].as_str().ok_or("missing 'phase'")?;
    let body = command["body"].as_str().ok_or("missing 'body'")?;
    if phase.is_empty() || phase.len() > PHASE_MOST {
        return Err(format!("a phase is 1 to {PHASE_MOST} bytes"));
    }
    if body.len() > BODY_MOST || !body.len().is_multiple_of(2) || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("a body is hex, {BODY_MOST} digits at most"));
    }
    let Some(boxed) = state.boxes.get_mut(&id) else { return Err("the mailbox is gone".into()) };
    if boxed.messages.len() >= MESSAGES {
        return Err(format!("a mailbox holds {MESSAGES} messages at most"));
    }
    let id_of_add = command.get("id").cloned().unwrap_or(Value::Null);
    let message = json!({
        "type": "message", "side": side_of(conn), "phase": phase, "body": body, "id": id_of_add,
        "server_rx": now_secs()
    });
    boxed.messages.push(message.clone());
    // Each listener hears it, the sender too; one whose writer is full
    // hears no more, as its client lost the order of the messages.
    let text = stamped(message);
    boxed.listeners.retain(|(_, outbox)| outbox.try_send(text.clone()).is_ok());
    Ok(Vec::new())
}

fn close(state: &mut State, conn: &mut Conn, command: &Value) -> Answered {
    if conn.closed {
        return Err("only one close per connection".into());
    }
    let id = match (command["mailbox"].as_str(), conn.opened.as_deref()) {
        (Some(named), Some(opened)) if named != opened => return Err("open and close must use same mailbox".into()),
        (Some(named), _) => named.to_string(),
        (None, Some(opened)) => opened.to_string(),
        (None, None) => return Err("close without mailbox must follow open".into()),
    };
    conn.closed = true;
    let side = side_of(conn);
    if let Some(boxed) = state.boxes.get_mut(&id) {
        boxed.listeners.retain(|(serial, _)| *serial != conn.serial);
        if let Some((_, open)) = boxed.sides.iter_mut().find(|(s, _)| *s == side) {
            *open = false;
        }
        if !boxed.sides.iter().any(|(_, open)| *open) {
            state.boxes.remove(&id);
            state.plates.retain(|_, plate| plate.mailbox != id);
        }
    }
    Ok(vec![json!({ "type": "closed" })])
}

/// The nameplates and mailboxes past their life go, with their messages.
fn prune(state: &mut State) {
    state.plates.retain(|_, plate| plate.made.elapsed() < LIFE);
    state.boxes.retain(|_, boxed| boxed.made.elapsed() < LIFE);
    let State { plates, boxes } = state;
    plates.retain(|_, plate| boxes.contains_key(&plate.mailbox));
}

fn side_of(conn: &Conn) -> String {
    conn.side.clone().unwrap_or_default()
}

/// A mailbox's id: 16 random bytes in hex, so that none is opened by a
/// guess of it, past its nameplate.
fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    OsEntropy.fill(&mut bytes).map_err(|_| "the role has no random bytes".to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// `message` as text, with the time that it leaves the role.
pub fn stamped(mut message: Value) -> String {
    message["server_tx"] = json!(now_secs());
    message.to_string()
}

fn now_secs() -> f64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
