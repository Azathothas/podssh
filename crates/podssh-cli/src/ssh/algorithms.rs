//! The keywords of a restriction that podssh applies (T-505, Q71):
//! `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`,
//! `PubkeyAcceptedAlgorithms` (and `PubkeyAcceptedKeyTypes`),
//! `CASignatureAlgorithms` and `RequiredRSASize`. Each list is assembled
//! as it is read (`podssh_ssh::algorithms::assemble`), so that a list that
//! leaves nothing is refused with its place: 64 on the command line, 78 in
//! a file. The first value of each keyword holds, as in OpenSSH, and a
//! later one is not read.

use podssh_ssh::algorithms::{self, Algorithms, Assembled, Kind};

use super::given::{Given, Place};

/// The lists given so far, each with the value and the place that gave it.
#[derive(Debug, Default, Clone)]
pub struct Lists {
    lists: Vec<(Kind, Given, Assembled)>,
    required_rsa_size: Option<(Given, u32)>,
}

impl Lists {
    /// Read `name`, whose lowercase is `key`, when it is one of these
    /// keywords: `Ok(false)` for another keyword.
    pub fn apply(&mut self, key: &str, name: &str, value: &str, place: &Place) -> Result<bool, String> {
        if key == "requiredrsasize" {
            let bits = value.parse::<u32>().map_err(|_| format!("-o {name}={value}: not a number of bits"))?;
            if self.required_rsa_size.is_none() {
                self.required_rsa_size = Some((Given::new(name, value, place), bits));
            }
            return Ok(true);
        }
        let Some(kind) = Kind::of_keyword(key) else { return Ok(false) };
        if self.lists.iter().any(|(k, ..)| *k == kind) {
            return Ok(true);
        }
        let assembled = algorithms::assemble(kind, value).map_err(|why| match place {
            Place::CommandLine => format!("-o {name}={value}: {why}"),
            // The command line's list goes before the file's line.
            Place::Line { .. } => {
                format!("-o {name}={value}: {why}; -o {}=LIST on the command line goes past it", kind.keyword())
            }
        })?;
        self.lists.push((kind, Given::new(name, value, place), assembled));
        Ok(true)
    }

    /// These lists, then `file`'s for each keyword that these left unset.
    pub fn then(mut self, file: Lists) -> Lists {
        for entry in file.lists {
            if !self.lists.iter().any(|(k, ..)| *k == entry.0) {
                self.lists.push(entry);
            }
        }
        if self.required_rsa_size.is_none() {
            self.required_rsa_size = file.required_rsa_size;
        }
        self
    }

    /// What the connection applies.
    pub fn chosen(&self) -> Algorithms {
        let mut out = Algorithms::default();
        for (kind, _, assembled) in &self.lists {
            out.set(*kind, assembled.names.clone());
        }
        out.required_rsa_size = self.required_rsa_size.as_ref().map(|(_, bits)| *bits);
        out
    }

    /// The notes for `-v`: each name of a list that podssh does not speak,
    /// and leaves out, with the place of the list.
    pub fn notes(&self) -> Vec<String> {
        self.lists
            .iter()
            .filter(|(.., assembled)| !assembled.dropped.is_empty())
            .map(|(_, given, assembled)| {
                format!(
                    "{} {} ({}): podssh does not speak {}, and leaves it out",
                    given.name,
                    given.value,
                    given.place.shown(),
                    assembled.dropped.join(",")
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_list_holds_and_a_bad_one_names_its_place_and_the_way_past_it() {
        let mut lists = Lists::default();
        let file = Place::line("/f", 3, false);
        assert!(lists.apply("ciphers", "Ciphers", "aes128-ctr,3des-cbc", &Place::CommandLine).unwrap());
        // A later one is not read, so a list that would leave nothing is no error.
        assert!(lists.apply("ciphers", "Ciphers", "3des-cbc", &file).unwrap());
        assert!(!lists.apply("port", "Port", "22", &file).unwrap());
        assert_eq!(lists.chosen().ciphers, Some(vec!["aes128-ctr".to_string()]));
        assert_eq!(
            lists.notes(),
            ["Ciphers aes128-ctr,3des-cbc (-o): podssh does not speak 3des-cbc, and leaves it out"]
        );
        let err = Lists::default().apply("macs", "MACs", "umac-64@openssh.com", &file).unwrap_err();
        assert!(err.contains("MACs=umac-64@openssh.com") && err.contains("-o MACs=LIST"), "{err}");
        let err = Lists::default().apply("macs", "MACs", "umac-64@openssh.com", &Place::CommandLine).unwrap_err();
        assert!(!err.contains("goes past it"), "{err}");
        assert!(Lists::default().apply("requiredrsasize", "RequiredRSASize", "big", &file).is_err());
    }

    #[test]
    fn the_command_lines_lists_go_before_a_files_and_the_old_name_is_the_same_keyword() {
        let mut cli = Lists::default();
        cli.apply("pubkeyacceptedkeytypes", "PubkeyAcceptedKeyTypes", "ssh-ed25519", &Place::CommandLine).unwrap();
        let mut file = Lists::default();
        let at = Place::line("/f", 1, false);
        file.apply("pubkeyacceptedalgorithms", "PubkeyAcceptedAlgorithms", "rsa-sha2-512", &at).unwrap();
        file.apply("requiredrsasize", "RequiredRSASize", "3072", &at).unwrap();
        let chosen = cli.then(file).chosen();
        assert_eq!(chosen.pubkey, Some(vec!["ssh-ed25519".to_string()]));
        assert_eq!(chosen.required_rsa_size, Some(3072));
    }
}
