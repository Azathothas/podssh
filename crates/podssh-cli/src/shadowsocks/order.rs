//! The order in which a run tries the servers of the file: each line's
//! server, as the relay hosts are tried (T-220), and for a subscription its
//! servers: the kept list while it is younger than a day, then the list
//! fetched again once each kept server failed; a list that is older, or not
//! kept, is fetched first, and an older one is tried when the fetch fails.
//! Each server once, and at most [`MAX_FROM_LIST`] of each list, as a list
//! can hold hundreds and each silent one costs its wait.

use std::collections::VecDeque;

use podssh_ws::shadowsocks::Node;
use podssh_ws::Trust;

use super::subscription::{self, Subscription};
use super::{Entry, Servers};

/// The servers tried of each list that a subscription gives.
pub const MAX_FROM_LIST: usize = 16;

/// Where a run is in the file.
pub struct Order<'a> {
    entries: &'a [Entry],
    trust: &'a Trust,
    next: usize,
    queue: VecDeque<Node>,
    /// A subscription to fetch again once the queue is empty: its kept
    /// servers are in it.
    refetch: Option<&'a Subscription>,
    tried: Vec<Node>,
}

impl<'a> Order<'a> {
    pub fn new(servers: &'a Servers, trust: &'a Trust) -> Order<'a> {
        Order { entries: &servers.entries, trust, next: 0, queue: VecDeque::new(), refetch: None, tried: Vec::new() }
    }

    /// The next server to try, or `None` when each was tried. `say` takes
    /// each line of a list: its fetch, its failure, what it left out.
    pub async fn next(&mut self, say: &mut (dyn FnMut(&str) + Send)) -> Option<Node> {
        loop {
            if let Some(node) = self.queue.pop_front() {
                self.tried.push(node.clone());
                return Some(node);
            }
            if let Some(list) = self.refetch.take() {
                say(&format!(
                    "each server of the kept list of the subscription {} failed; podssh fetches it again",
                    list.shown()
                ));
                self.fetch(list, None, say).await;
                continue;
            }
            let entries = self.entries;
            let entry = entries.get(self.next)?;
            self.next += 1;
            match entry {
                Entry::Node(node) => self.enqueue(vec![node.clone()]),
                Entry::Subscription(list) => match subscription::kept(list) {
                    Some(kept) if kept.fresh && !kept.nodes.is_empty() => {
                        self.enqueue(kept.nodes);
                        self.refetch = Some(list);
                    }
                    Some(kept) => self.fetch(list, Some(kept.nodes), say).await,
                    None => self.fetch(list, None, say).await,
                },
            }
        }
    }

    /// Fetch `list` and queue its servers; when the fetch fails, the
    /// `older` list that was kept, if there is one.
    async fn fetch(&mut self, list: &Subscription, older: Option<Vec<Node>>, say: &mut (dyn FnMut(&str) + Send)) {
        match subscription::fetch(list, self.trust).await {
            Ok(fetched) => {
                for note in &fetched.notes {
                    say(note);
                }
                self.enqueue(fetched.nodes);
            }
            Err(why) => {
                say(&why);
                if let Some(nodes) = older.filter(|nodes| !nodes.is_empty()) {
                    say(&format!(
                        "podssh tries the list of the subscription {} that it kept more than a day ago",
                        list.shown()
                    ));
                    self.enqueue(nodes);
                }
            }
        }
    }

    /// The servers of `nodes` that were neither tried nor queued, at most
    /// [`MAX_FROM_LIST`] of them.
    fn enqueue(&mut self, nodes: Vec<Node>) {
        let mut taken = 0;
        for node in nodes {
            if taken == MAX_FROM_LIST {
                break;
            }
            let seen = self.tried.iter().chain(self.queue.iter()).any(|known| known.same_server(&node));
            if !seen {
                self.queue.push_back(node);
                taken += 1;
            }
        }
    }
}
