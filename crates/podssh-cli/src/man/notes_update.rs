//! The notes of `podssh update` (T-375, T-396), apart from the others so
//! that each file stays short.

pub const UPDATE: &[&str] = &[
    "podssh update replaces this binary with the release's binary for its own target, and only when asked: \
     no other command looks for a release. It reads the newest release from GitHub's API, else from the \
     releases' Atom feed, through HTTPS_PROXY when it is set: a prerelease only when this binary is one, and \
     never one older than this build. --version TAG takes that release, an older one too. --check stops before \
     the binary: it names the release, checks its signature, and names the file that it would replace.",
    "Nothing is written before two checks. The release's SHA256SUMS against the signature that its workflow \
     made with Sigstore (SHA256SUMS.sigstore.json): the certificate that Fulcio gave the workflow release.yml \
     of this repository at that tag, by Sigstore's roots compiled into podssh, and Rekor's record of the \
     signature, with no other network. Then the binary's SHA-256 against its line. The new binary goes beside \
     the old one, with its mode, and runs there once, as podssh --version with no input, for 10 s at most: \
     when it does not start on this host, ends with another code than 0, or names another version than the \
     release's, it is removed and refused (65), as an installed node would not start again with it. Then the \
     old one is kept as podssh.prev beside it (a hard link, else a copy) and the new one goes over it in one \
     rename; on Windows the running file is renamed to podssh.prev.exe first, else to podssh.exe.old, which the \
     next run removes. A failure leaves the old binary as it was.",
    "--rollback puts back the binary that the last update kept, with no network: once podssh.prev answers \
     --version here, it goes over this binary in one rename, and this one is kept as podssh.prev in its \
     place, so that a second --rollback goes forward again. A run that started before, as an installed node, \
     goes on with its own binary until it starts again. With nothing kept the exit is 69; with a kept binary \
     that does not run here, 65, and nothing changes; with --check or --version, 64.",
    "Exit 0 when the binary was replaced, or there was nothing to do; 69 when GitHub, the release or one of \
     its files did not come; 65 when a check failed, the run of the new binary too; 73 when the binary could \
     not be replaced, as in a directory that this user cannot write; 78 when no release has a binary for this \
     system; 64 for a TAG that is no version. When Sigstore changes its roots, a binary of before refuses the \
     new releases: download the release by hand, as its message says.",
];
