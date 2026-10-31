//! The variables of the roads of a cloud's own tunnel, `iap://` and
//! `eice://` (T-351), out of `facts.rs` at its 500 lines. Each one names a
//! file or a setting, never a credential: a credential is read from its
//! file by the file's path alone.

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
        &["PODSSH_EICE_MAX_TUNNEL_DURATION"],
        "The longest life of an eice:// tunnel, aws-cli's maximum tunnel duration: whole seconds from 1 to \
      3600, which an IAM policy may require; unset, the endpoint's own hour. podssh cp goes on in a new \
      tunnel a twelfth of it before its end, 30 s at least. Another value is a configuration error (78).",
    ),
];
