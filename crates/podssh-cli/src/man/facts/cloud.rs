//! The variables of the roads of a cloud's own tunnel, `iap://` and
//! `eice://` (T-351), and of WARP's, `warp://` (T-352), out of `facts.rs` at
//! its 500 lines. Each one names a file or a setting, never a credential: a
//! credential is read from its file by the file's path alone.

/// The variables, as [`super::VARIABLES`] holds the others.
pub const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_IAP_TOKEN_FILE"],
        "The file of the token of an iap:// destination, which must be private (chmod 600): a token that \
      gcloud auth print-access-token printed, read again for each link of the session, so that a token \
      written there later serves a new link; or the JSON key of a service account (gcloud iam \
      service-accounts keys create), whose token podssh asks Google's token endpoint, oauth2.googleapis.com, \
      for, with a JWT that it signs (RS256), and renews before its end; or the credentials of gcloud auth \
      application-default login. The token goes in the upgrade's Authorization header alone; podssh never \
      prints it. A file that cannot be read, or holds no token, is a configuration error (78).",
    ),
    (
        &["GOOGLE_APPLICATION_CREDENTIALS"],
        "Google's own variable for the file of a key: read as PODSSH_IAP_TOKEN_FILE is, when that one is not \
      set.",
    ),
    (
        &["PODSSH_EICE_CREDENTIALS_FILE"],
        "The file of the credential of AWS for an eice:// destination, which must be private: the JSON that \
      aws configure export-credentials writes in its process format, or a shared credentials file, whose \
      profile is AWS_PROFILE's, else default. podssh signs a new URL with it for each tunnel, good for 60 s, as \
      aws-cli signs one; the URL carries the key's id, the signature and a temporary key's token, the one \
      URL of podssh that holds a credential (the operator's ruling Q51), and podssh never prints it.",
    ),
    (
        &["AWS_SHARED_CREDENTIALS_FILE", "AWS_PROFILE"],
        "AWS's own variables: the shared credentials file, read for eice:// when PODSSH_EICE_CREDENTIALS_FILE \
      is not set (else ~/.aws/credentials, when it is there), and the profile of either file (default when \
      it is not set).",
    ),
    (
        &["PODSSH_WARP_ACCEPT_TERMS"],
        "yes accepts Cloudflare's Terms (https://www.cloudflare.com/application/terms/), which a device of \
      WARP needs: with it, the first warp:// destination registers one device with Cloudflare's API, \
      api.cloudflareclient.com, through the proxy, and keeps its record in the cache (see FILES); later runs \
      read the record and register nothing. Unset, no or empty, a run with no record refuses (78) and names \
      it. Another word is a configuration error (78). A build with the feature warp.",
    ),
    (
        &["PODSSH_WARP_TEAM_TOKEN_FILE"],
        "The file of a team's token of a Cloudflare One organization, which must be private: the device \
      registers in that organization (its header CF-Access-Jwt-Assertion), not as an anonymous one. Read at \
      the registration alone; podssh never prints it.",
    ),
    (
        &["PODSSH_WARP_ENDPOINT"],
        "WARP's endpoint of HTTP/2 as ADDRESS:PORT, in place of 162.159.198.2:443; the device's pinned key \
      stays its own. Another value is a configuration error (78).",
    ),
    (
        &["PODSSH_TOR_PORTS"],
        "The ports that a first hop of a tor:// destination may have, which Arti reaches through the proxy: \
      a list such as 443,80, or any. Unset or empty: 443 alone when a proxy is set, as a cage's proxy allows \
      little more, and any port when none is. With PODSSH_TOR_BRIDGES it does not hold. Another value is a \
      configuration error (78). A build with the feature tor.",
    ),
    (
        &["PODSSH_TOR_BRIDGES"],
        "The file of the bridges of a tor:// destination, a bridge line a line as Tor gives them out, with or \
      without the word Bridge of a torrc; # begins a comment. Arti's first hops are then these bridges alone, \
      and PODSSH_TOR_PORTS does not hold. A line is a plain bridge, ADDRESS:PORT FINGERPRINT, or one of \
      meek_lite or webtunnel, which podssh speaks itself, in this process, through the proxy: meek_lite sends \
      Tor's bytes in POSTs to its url=, TLS to its front= with the front's name and Host the URL's host; \
      WebTunnel upgrades at its url=, then carries raw bytes. Each TLS is checked with podssh's trust \
      (--ca-file, SSL_CERT_FILE, CaFile, else the system's), and WebTunnel's cert= after that check, never in \
      its place. Arti asks each line for the bridge's fingerprint, so a line with none is refused, the \
      meek_lite line of Tor Browser among them; so is another transport (obfs4, snowflake), which would be \
      another program. A line that does not read, or a file that cannot be read, holds no bridge or is longer \
      than 64 KiB, is a configuration error (78). A build with the feature tor.",
    ),
    (
        &["PODSSH_TOR_NETWORK"],
        "The file of arti-client's configuration of another Tor network than Tor's own, as chutney writes it \
      (arti.toml): a private network, whose authorities, caches and rules of paths replace Tor's; the cache's \
      directories, the proxy and PODSSH_TOR_PORTS still hold. Its guards and its directory go apart from Tor's, \
      under the cache's tor/networks/ by a digest of the file. Unset or empty: Tor's network. A file that cannot be \
      read, or longer than 1 MiB, is a configuration error (78). A build with the feature tor.",
    ),
    (
        &["PODSSH_EICE_MAX_TUNNEL_DURATION"],
        "The longest life of an eice:// tunnel, aws-cli's maximum tunnel duration: whole seconds from 1 to \
      3600, which an IAM policy may require; unset, the endpoint's own hour. podssh cp goes on in a new \
      tunnel a twelfth of it before its end, 30 s at least. Another value is a configuration error (78).",
    ),
];
