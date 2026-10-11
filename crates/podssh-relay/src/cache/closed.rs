//! Whether a file of Windows is closed to the other users of the host
//! (T-274): its owner, and whom its access list lets in. The rules are
//! those of OpenSSH for Windows (`check_secure_file_permission` in
//! `contrib/win32/win32compat/w32-sshfileperm.c`): the owner is the user,
//! SYSTEM, the Administrators or TrustedInstaller; an entry that lets
//! another principal change the file refuses it; and for a file that holds
//! a secret, so does an entry that lets another principal read it. A deny
//! entry only takes away, and an entry for the children alone
//! (inherit-only) does not apply to the file, so neither counts. Unlike
//! OpenSSH, the generic rights count too, and no account name is looked up,
//! which can wait on a domain controller: a principal is named by its SID,
//! with the well-known name of a few.

use super::Others;

/// SYSTEM, the Administrators and TrustedInstaller, which own the host.
const HOST: [&str; 3] = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

/// The rights that change a file: write, append, its extended attributes
/// and attributes, delete, its access list and its owner, and the generic
/// write and all.
pub(crate) const WRITE: u32 = 0x2 | 0x4 | 0x10 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;
/// The rights that read a file's data: read, its extended attributes, and
/// the generic read and all.
pub(crate) const READ: u32 = 0x1 | 0x8 | 0x8000_0000 | 0x1000_0000;

/// An entry of an access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub allow: bool,
    pub inherit_only: bool,
    pub sid: String,
    pub mask: u32,
}

/// The owner and the access list of a file, as SIDs; `entries` is `None`
/// for no list at all, which lets everyone in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Acl {
    pub owner: String,
    pub entries: Option<Vec<Entry>>,
}

/// Why `acl` lets in another principal than `user` beyond `others`.
pub(crate) fn judge(acl: &Acl, user: &str, others: Others) -> Result<(), String> {
    let trusted = |sid: &str| sid == user || HOST.contains(&sid);
    if !trusted(&acl.owner) {
        return Err(format!(
            "it is another user's: its owner is {}, not you, SYSTEM or the Administrators",
            name(&acl.owner)
        ));
    }
    let Some(entries) = &acl.entries else {
        return Err("others can change it: it has no access list, which lets everyone in".into());
    };
    for entry in entries.iter().filter(|e| e.allow && !e.inherit_only && !trusted(&e.sid)) {
        if entry.mask & WRITE != 0 {
            return Err(format!("others can change it: {} may write it", name(&entry.sid)));
        }
        if others == Others::NoAccess && entry.mask & READ != 0 {
            return Err(format!("others can read it: {} may read it", name(&entry.sid)));
        }
    }
    Ok(())
}

/// A SID, with its well-known name when it has one.
fn name(sid: &str) -> String {
    let known = match sid {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "the group Users",
        "S-1-5-32-546" => "the group Guests",
        "S-1-5-4" => "Interactive",
        "S-1-5-7" => "Anonymous",
        _ => return sid.to_string(),
    };
    format!("{known} ({sid})")
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1-2-3-1001";

    fn entry(sid: &str, mask: u32) -> Entry {
        Entry { allow: true, inherit_only: false, sid: sid.into(), mask }
    }

    /// The list of a file of the user's profile: the user, SYSTEM and the
    /// Administrators, each with full control.
    fn profile() -> Vec<Entry> {
        vec![entry(USER, 0x1F_01FF), entry("S-1-5-18", 0x1F_01FF), entry("S-1-5-32-544", 0x1F_01FF)]
    }

    #[test]
    fn closed_accepts_a_file_of_the_profile_owned_by_the_user_or_the_host() {
        for owner in [USER, "S-1-5-18", "S-1-5-32-544"] {
            let acl = Acl { owner: owner.into(), entries: Some(profile()) };
            assert_eq!(judge(&acl, USER, Others::NoAccess), Ok(()), "{owner}");
        }
    }

    #[test]
    fn closed_refuses_another_owner_and_no_list() {
        let theirs = Acl { owner: "S-1-5-21-1-2-3-1002".into(), entries: Some(profile()) };
        assert!(judge(&theirs, USER, Others::Read).unwrap_err().contains("another user's"));
        let open = Acl { owner: USER.into(), entries: None };
        assert!(judge(&open, USER, Others::Read).unwrap_err().contains("no access list"));
    }

    #[test]
    fn closed_refuses_a_writer_and_for_a_secret_a_reader() {
        // Write, append, the access list, the generic write, full control.
        for mask in [0x2, 0x4, 0x4_0000, 0x4000_0000, 0x1F_01FF] {
            let mut list = profile();
            list.push(entry("S-1-5-32-545", mask));
            let acl = Acl { owner: USER.into(), entries: Some(list) };
            let why = judge(&acl, USER, Others::Read).unwrap_err();
            assert!(why.contains("others can change it") && why.contains("the group Users"), "{mask:#x}: {why}");
        }
        let mut list = profile();
        list.push(entry("S-1-1-0", 0x12_0089));
        let acl = Acl { owner: USER.into(), entries: Some(list) };
        assert_eq!(judge(&acl, USER, Others::Read), Ok(()), "a reader of a file that holds no secret");
        assert!(judge(&acl, USER, Others::NoAccess).unwrap_err().contains("others can read it: Everyone"));
    }

    /// A deny entry, an entry for the children alone, and an entry that
    /// reads only attributes let nobody change or read the file.
    #[test]
    fn closed_ignores_what_does_not_open_the_file() {
        let mut list = profile();
        list.push(Entry { allow: false, inherit_only: false, sid: "S-1-1-0".into(), mask: 0x1F_01FF });
        list.push(Entry { allow: true, inherit_only: true, sid: "S-1-5-32-545".into(), mask: 0x1F_01FF });
        list.push(entry("S-1-5-11", 0x80));
        let acl = Acl { owner: USER.into(), entries: Some(list) };
        assert_eq!(judge(&acl, USER, Others::NoAccess), Ok(()));
    }
}
