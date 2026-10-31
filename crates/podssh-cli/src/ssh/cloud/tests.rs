//! The destinations of a cloud's tunnel (T-351): each form read, each bad
//! one refused by what is wrong, the names under which a host key is kept,
//! and the age at which a copy goes on in a new tunnel.

use super::*;

const DNS: &str = "eice-0123456789example.b67b86ba.ec2-instance-connect-endpoint.us-west-2.amazonaws.com";

#[test]
fn cloud_an_iap_destination_is_read() {
    let (user, road) = destination("iap://me@a-project/us-central1-a/a-vm:2222").unwrap().unwrap();
    assert_eq!(user.as_deref(), Some("me"));
    assert_eq!(road.shown(), "iap://a-project/us-central1-a/a-vm");
    assert_eq!((road.host().as_str(), road.port(), road.word()), ("a-vm", 2222, "iap"));
    let (user, road) = destination("iap://example.com:a-project/europe-west1-b/vm/").unwrap().unwrap();
    assert_eq!((user, road.port()), (None, 22));
    assert_eq!(road.shown(), "iap://example.com:a-project/europe-west1-b/vm");
    assert_eq!(destination("a-vm").unwrap(), None);
    assert_eq!(destination("cf://ssh.example.org").unwrap(), None);
    for bad in [
        "iap://",
        "iap://a-project/us-central1-a",
        "iap://a-project/us-central1-a/a-vm/extra",
        "iap://@a-project/us-central1-a/a-vm",
        "iap://a-project/us-central1-a/A-VM",
        "iap://a-project/us-central1-a/a-vm:0",
        "iap://a-project/us-central1-a/a-vm:http",
    ] {
        assert!(destination(bad).is_err(), "{bad}");
    }
}

#[test]
fn cloud_an_eice_destination_is_read() {
    let (user, road) = destination(&format!("eice://ec2-user@{DNS}/10.0.1.5")).unwrap().unwrap();
    assert_eq!(user.as_deref(), Some("ec2-user"));
    assert_eq!(road.shown(), "eice://eice-0123456789example/10.0.1.5");
    assert_eq!((road.host().as_str(), road.port()), ("10.0.1.5", 22));
    let (_, road) = destination(&format!("eice://{DNS}/[2600:1f14::1]:2222")).unwrap().unwrap();
    assert_eq!(road.shown(), "eice://eice-0123456789example/[2600:1f14::1]");
    assert_eq!((road.port(), road.word()), (2222, "eice"));
    let (_, road) = destination(&format!("eice://{DNS}/10.0.1.5:443")).unwrap().unwrap();
    assert_eq!(road.port(), 443);
    for bad in [
        format!("eice://{DNS}"),
        format!("eice://{DNS}/"),
        format!("eice://{DNS}/host.example"),
        format!("eice://{DNS}/[2600:1f14::1"),
        format!("eice://{DNS}/[2600:1f14::1]x"),
        format!("eice://{DNS}/10.0.1.5:99999"),
        "eice://vpce-1.ec2-instance-connect-endpoint.us-west-2.amazonaws.com/10.0.1.5".to_string(),
    ] {
        assert!(destination(&bad).is_err(), "{bad}");
    }
}

/// EICE's tunnel ends at its duration: a copy goes on in a new one before,
/// by a twelfth of it and 30 s at least; IAP's sessions have no such end.
#[test]
fn cloud_a_copy_goes_on_before_the_tunnel_s_end() {
    let (_, road) = destination(&format!("eice://{DNS}/10.0.1.5")).unwrap().unwrap();
    assert_eq!(road.age_limit(), Some(Duration::from_secs(3300)));
    let Road::Eice { endpoint, mut target } = road else { panic!("eice") };
    target.max_duration = Some(600);
    let shorter = Road::Eice { endpoint: endpoint.clone(), target: target.clone() };
    assert_eq!(shorter.age_limit(), Some(Duration::from_secs(550)));
    target.max_duration = Some(20);
    assert_eq!(Road::Eice { endpoint, target }.age_limit(), None, "too short to go on in");
    let (_, iap) = destination("iap://a-project/us-central1-a/a-vm").unwrap().unwrap();
    assert_eq!(iap.age_limit(), None);
}

#[test]
fn cloud_a_duration_is_whole_seconds_to_an_hour() {
    assert_eq!(eice::max_duration(None), Ok(None));
    assert_eq!(eice::max_duration(Some(" ")), Ok(None));
    assert_eq!(eice::max_duration(Some("3600")), Ok(Some(3600)));
    assert_eq!(eice::max_duration(Some("1")), Ok(Some(1)));
    for bad in ["0", "3601", "1h", "-5"] {
        assert!(eice::max_duration(Some(bad)).is_err(), "{bad}");
    }
}
