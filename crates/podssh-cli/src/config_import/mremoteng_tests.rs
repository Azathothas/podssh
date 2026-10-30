use super::*;

fn input(xml: &str) -> Vec<Input> {
    vec![Input { name: "confCons.xml".into(), bytes: xml.as_bytes().to_vec() }]
}

/// A file of the shape that mRemoteNG 2.8 writes, with the attributes that
/// the reader takes.
fn file(nodes: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Connections Name=\"Connections\" Export=\"False\" \
         EncryptionEngine=\"AES\" BlockCipherMode=\"GCM\" KdfIterations=\"10000\" FullFileEncryption=\"false\" \
         Protected=\"made-up\" ConfVersion=\"2.8\">{nodes}</Connections>"
    )
}

fn by_label(read: &Read) -> BTreeMap<&str, &Session> {
    read.sessions.iter().map(|s| (s.label.as_str(), s)).collect()
}

#[test]
fn a_connection_inherits_its_user_and_port_through_two_folders() {
    let xml = file(
        r#"<Node Name="Lab" Type="Container" Protocol="SSH2" Port="2222" Username="ops" Password="enc-a">
             <Node Name="Web" Type="Container" InheritPort="true" InheritUsername="true" InheritProtocol="true" Protocol="RDP">
               <Node Name="web1" Type="Connection" Hostname="web1.example" InheritProtocol="true" InheritPort="true" InheritUsername="true" Password="enc-b" PuttySession="Default Settings"/>
               <Node Name="web2" Type="Connection" Hostname="web2.example" Protocol="SSH2" Port="22" Username="alice" PuttySession="Strong"/>
             </Node>
           </Node>"#,
    );
    let read = read(&input(&xml)).unwrap();
    let s = by_label(&read);
    let web1 = s["web1"];
    assert_eq!(web1.folder.as_deref(), Some("Lab/Web"));
    assert_eq!(
        (web1.host.as_deref(), web1.port.as_deref(), web1.user.as_deref()),
        (Some("web1.example"), Some("2222"), Some("ops"))
    );
    assert!(web1.notes.is_empty(), "{:?}", web1.notes);
    assert_eq!(s["web2"].user.as_deref(), Some("alice"));
    assert!(s["web2"].notes[0].contains("PuTTY session Strong"), "{:?}", s["web2"].notes);
    assert_eq!(read.secrets, 2, "each password counted, never read");
    assert!(read.sessions.iter().all(|s| s.label != "Lab" && s.label != "Web"), "no session of a folder");
}

#[test]
fn a_tunnel_is_a_jump_its_own_tunnel_first() {
    let xml = file(
        r#"<Node Name="far" Type="Connection" Protocol="SSH2" Hostname="far.example" Username="me" SSHTunnelConnectionName="mid"/>
           <Node Name="mid" Type="Connection" Protocol="SSH2" Hostname="mid.example" Port="2200" SSHTunnelConnectionName="edge"/>
           <Node Name="edge" Type="Connection" Protocol="SSH2" Hostname="edge.example" Username="gw"/>
           <Node Name="rdp-tunnel" Type="Connection" Protocol="SSH2" Hostname="x.example" SSHTunnelConnectionName="desk"/>
           <Node Name="desk" Type="Connection" Protocol="RDP" Hostname="desk.example"/>
           <Node Name="loop1" Type="Connection" Protocol="SSH2" Hostname="l1.example" SSHTunnelConnectionName="loop2"/>
           <Node Name="loop2" Type="Connection" Protocol="SSH2" Hostname="l2.example" SSHTunnelConnectionName="loop1"/>"#,
    );
    let read = read(&input(&xml)).unwrap();
    let s = by_label(&read);
    assert_eq!(s["far"].jump.as_deref(), Some("gw@edge.example,mid.example:2200"));
    assert_eq!(s["mid"].jump.as_deref(), Some("gw@edge.example"));
    assert_eq!(s["edge"].jump, None);
    assert!(s["rdp-tunnel"].jump.is_none() && s["rdp-tunnel"].notes[0].contains("desk is not an SSH connection"));
    assert!(s["loop1"].notes[0].contains("more than 8 tunnels"), "{:?}", s["loop1"].notes);
}

#[test]
fn ssh1_another_protocol_and_another_type_are_named() {
    let xml = file(
        r#"<Node Name="old" Type="Connection" Protocol="SSH1" Hostname="old.example"/>
           <Node Name="desk" Type="Connection" Protocol="RDP" Hostname="desk.example" Password="enc" RDGatewayPassword="enc-g"/>
           <Node Name="strange" Type="Root"/>
           <Node Name="opts" Type="Connection" Protocol="SSH2" Hostname="o.example" SSHOptions="-pw made-up"/>"#,
    );
    let read = read(&input(&xml)).unwrap();
    let s = by_label(&read);
    assert!(s["old"].not_ssh.as_deref().unwrap().contains("SSH1"));
    assert_eq!(s["desk"].not_ssh.as_deref(), Some("RDP"));
    assert!(s["strange"].not_ssh.as_deref().unwrap().contains("type Root"));
    assert!(s["opts"].notes[0].contains("SSHOptions is not imported"));
    assert!(!format!("{:?}", read.sessions).contains("made-up"), "no value of SSHOptions is kept");
    assert_eq!(read.secrets, 2);
}

#[test]
fn a_file_encrypted_whole_and_another_xml_are_refused() {
    let whole = file("").replace("FullFileEncryption=\"false\"", "FullFileEncryption=\"True\"");
    let why = read(&input(&whole)).unwrap_err();
    assert!(why.contains("FullFileEncryption") && why.contains("export the connections"), "{why}");
    let other = read(&input("<?xml version=\"1.0\"?><sessions/>")).unwrap_err();
    assert!(other.contains("no Connections element"), "{other}");
    let broken = read(&input("<Connections><Node")).unwrap_err();
    assert!(broken.contains("not the XML of mRemoteNG's connections"), "{broken}");
}
