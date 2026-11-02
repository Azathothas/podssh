//! The names of owners and groups by their numbers, from the server
//! (`users-groups-by-id@openssh.com`, which OpenSSH's sftp-server offers since
//! 9.1), for the long lines of `sftp`'s `ls` (T-471). The request is two
//! strings, each a run of uint32 numbers; the reply two strings, each a run of
//! strings, one name for each number asked, empty for one that the server
//! does not know (`sftp-server.c` and `sftp-client.c` of OpenSSH 10.2p1).

use std::collections::BTreeMap;

use russh_sftp::protocol::Packet;

use super::{within, Sftp, SftpError};

/// The extension's name; OpenSSH's client takes it at version `1` alone.
pub const USERS_GROUPS: &str = "users-groups-by-id@openssh.com";

/// The names that the server gave, by number; a number that it does not
/// know has none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    pub users: BTreeMap<u32, String>,
    pub groups: BTreeMap<u32, String>,
}

/// The request's data: `uids` and `gids`, each as one string of numbers.
fn request(uids: &[u32], gids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for ids in [uids, gids] {
        out.extend_from_slice(&((ids.len() * 4) as u32).to_be_bytes());
        for id in ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
    }
    out
}

/// One SSH string of `data` at `at`, which moves past it.
fn string<'a>(data: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(data.get(*at..at.checked_add(4)?)?.try_into().ok()?) as usize;
    let start = at.checked_add(4)?;
    let text = data.get(start..start.checked_add(len)?)?;
    *at = start + len;
    Some(text)
}

/// The name of each of `ids`, from the run of strings `run`.
fn named(run: &[u8], ids: &[u32]) -> Option<BTreeMap<u32, String>> {
    let (mut at, mut out) = (0, BTreeMap::new());
    for id in ids {
        let name = string(run, &mut at)?;
        if !name.is_empty() {
            out.insert(*id, String::from_utf8_lossy(name).into_owned());
        }
    }
    Some(out)
}

/// The reply's data for `uids` and `gids`; `None` when it is not their form.
pub fn parse(data: &[u8], uids: &[u32], gids: &[u32]) -> Option<Names> {
    let mut at = 0;
    let (users, groups) = (string(data, &mut at)?, string(data, &mut at)?);
    Some(Names { users: named(users, uids)?, groups: named(groups, gids)? })
}

impl Sftp {
    /// Whether the server names owners and groups by number, at the version
    /// that OpenSSH's client takes.
    pub fn names_ids(&self) -> bool {
        self.extensions.get(USERS_GROUPS).map(String::as_str) == Some("1")
    }

    /// The names of the owners `uids` and the groups `gids`; `None` when the
    /// server offers no such request, or answers it with a status, as
    /// OpenSSH's client then shows the numbers.
    pub async fn users_groups(&self, uids: &[u32], gids: &[u32]) -> Result<Option<Names>, SftpError> {
        if !self.names_ids() {
            return Ok(None);
        }
        let what = "users-groups-by-id";
        match within(self.limits.metadata, what, self.raw.extended(USERS_GROUPS, request(uids, gids))).await? {
            Packet::ExtendedReply(reply) => parse(&reply.data, uids, gids)
                .map(Some)
                .ok_or_else(|| SftpError::Protocol(format!("{what}: a reply that is not two runs of names"))),
            Packet::Status(_) => Ok(None),
            _ => Err(SftpError::Protocol(format!("{what}: a reply of the wrong type"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run of SSH strings, as the server writes each.
    fn run(names: &[&str]) -> Vec<u8> {
        names.iter().flat_map(|n| (n.len() as u32).to_be_bytes().into_iter().chain(n.bytes())).collect()
    }

    #[test]
    fn the_request_is_two_runs_of_numbers() {
        let want: Vec<u8> = vec![0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 0, 4, 0, 0, 0, 7];
        assert_eq!(request(&[0, 1000], &[7]), want);
        assert_eq!(request(&[], &[]), vec![0u8; 8]);
    }

    #[test]
    fn the_reply_names_each_number_and_an_empty_name_is_none() {
        // As OpenSSH's sftp-server answers: a string of strings for each.
        let (users, groups) = (run(&["root", ""]), run(&["wheel"]));
        let mut data = (users.len() as u32).to_be_bytes().to_vec();
        data.extend(&users);
        data.extend((groups.len() as u32).to_be_bytes());
        data.extend(&groups);
        let names = parse(&data, &[0, 4242], &[10]).expect("its form");
        assert_eq!(names.users.get(&0).map(String::as_str), Some("root"));
        assert_eq!(names.users.get(&4242), None, "a number that the server does not know");
        assert_eq!(names.groups.get(&10).map(String::as_str), Some("wheel"));
        // A name short of the numbers asked, or a cut string, is not the form.
        assert_eq!(parse(&data, &[0, 4242, 5], &[10]), None);
        assert_eq!(parse(&data[..data.len() - 1], &[0, 4242], &[10]), None);
    }
}
