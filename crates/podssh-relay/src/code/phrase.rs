//! A code: the mailbox's nameplate, then words of the PGP list
//! (`super::words`), joined by hyphens, as magic-wormhole writes one
//! (`7-crossover-clockwork-adroitness`). The nameplate is the mailbox's to
//! see; the words are the secret, 8 bits each, which SPAKE2 takes with the
//! nameplate as one password. While it lives a code is a credential: no
//! `Debug` shows its words, and its text is wiped on drop.

use std::fmt;

use zeroize::Zeroizing;

use super::{words, WORDS};
use crate::session::secret::{Entropy, NoRandom};

/// The longest nameplate taken: the mailbox gives 1 to 3 digits, and up to 6
/// when 999 are in use.
pub const NAMEPLATE_MOST: usize = 12;
/// The most words that a typed code may have: magic-wormhole gives 2 by
/// default, podssh 3.
pub const WORDS_MOST: usize = 8;
/// The longest line read as a code.
pub const TYPED_MOST: usize = 256;

/// A code, the nameplate and its words.
pub struct Code {
    text: Zeroizing<String>,
    /// The bytes of the nameplate at the start of the text.
    nameplate: usize,
}

impl Code {
    /// A new code for `nameplate`: [`WORDS`] words, each of a random byte.
    pub fn make(nameplate: &str, entropy: &mut dyn Entropy) -> Result<Code, NoRandom> {
        let mut bytes = Zeroizing::new([0u8; WORDS]);
        entropy.fill(&mut bytes[..])?;
        let mut text = Zeroizing::new(nameplate.to_string());
        for (at, byte) in bytes.iter().enumerate() {
            text.push('-');
            text.push_str(words::word(at, *byte));
        }
        Ok(Code { text, nameplate: nameplate.len() })
    }

    /// The code that a person typed: its nameplate, then its words, each of
    /// the list of its place, by hyphens or spaces, in any case. A refusal
    /// says which part is wrong, and never echoes a word.
    pub fn parse(typed: &str) -> Result<Code, String> {
        if typed.len() > TYPED_MOST {
            return Err(format!("a code is a few words, not {} bytes", typed.len()));
        }
        let parts: Vec<&str> = typed.trim().split(['-', ' ', '\t']).filter(|p| !p.is_empty()).collect();
        let Some((nameplate, said)) = parts.split_first() else {
            return Err("no code came: it is a number and words, as 7-crossover-clockwork-adroitness".into());
        };
        if !nameplate_ok(nameplate) {
            return Err("a code begins with its number, the digits before the first word".into());
        }
        if said.is_empty() || said.len() > WORDS_MOST {
            return Err(format!("a code has 1 to {WORDS_MOST} words after its number, and this one {}", said.len()));
        }
        let mut text = Zeroizing::new(nameplate.to_string());
        for (at, typed) in said.iter().enumerate() {
            let Some(word) = words::find(at, typed) else {
                let which = if at.is_multiple_of(2) { "odd" } else { "even" };
                return Err(format!(
                    "word {} of the code is not one of the {which} words of its list: check it, or ask for the \
                     code again",
                    at + 1
                ));
            };
            text.push('-');
            text.push_str(word);
        }
        Ok(Code { text, nameplate: nameplate.len() })
    }

    /// The nameplate, which the mailbox sees.
    pub fn nameplate(&self) -> &str {
        &self.text[..self.nameplate]
    }

    /// The password of SPAKE2: the whole code, as magic-wormhole takes it.
    pub fn password(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The code as a person reads it, for a terminal and nowhere else.
    pub fn for_terminal(&self) -> &str {
        &self.text
    }

    /// The words after the nameplate.
    pub fn words(&self) -> usize {
        self.text.split('-').count().saturating_sub(1)
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The nameplate alone: the words are the secret.
        write!(f, "Code({}-...)", self.nameplate())
    }
}

/// Whether `text` is a nameplate that podssh takes: decimal digits, as the
/// mailbox gives them.
pub fn nameplate_ok(text: &str) -> bool {
    !text.is_empty() && text.len() <= NAMEPLATE_MOST && text.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u8);

    impl Entropy for Fixed {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), NoRandom> {
            buf.fill(self.0);
            Ok(())
        }
    }

    #[test]
    fn a_new_code_is_its_nameplate_and_three_words_odd_first() {
        let code = Code::make("7", &mut Fixed(0)).unwrap();
        assert_eq!(code.for_terminal(), "7-adroitness-aardvark-adroitness");
        assert_eq!((code.nameplate(), code.words()), ("7", 3));
        assert_eq!(code.password(), b"7-adroitness-aardvark-adroitness");
        assert_eq!(format!("{code:?}"), "Code(7-...)");
        let random = Code::make("42", &mut crate::session::OsEntropy).unwrap();
        assert!(random.for_terminal().starts_with("42-") && random.words() == 3);
    }

    #[test]
    fn a_typed_code_is_read_in_any_case_with_hyphens_or_spaces() {
        let typed = [
            "7-crossover-clockwork-adroitness",
            " 7 Crossover CLOCKWORK adroitness\n",
            "7--crossover-clockwork-adroitness",
        ];
        for typed in typed {
            let code = Code::parse(typed).unwrap();
            assert_eq!(code.for_terminal(), "7-crossover-clockwork-adroitness", "{typed:?}");
        }
        // magic-wormhole's own default: two words.
        assert_eq!(Code::parse("4-crossover-clockwork").unwrap().words(), 2);
    }

    #[test]
    fn a_wrong_code_is_refused_by_its_part_and_no_word_is_echoed() {
        for (typed, says) in [
            ("", "no code came"),
            ("crossover-clockwork", "begins with its number"),
            ("7", "1 to 8 words"),
            ("7-clockwork-crossover", "word 1 of the code is not one of the odd words"),
            ("7-crossover-secretword", "word 2 of the code is not one of the even words"),
            ("1234567890123-crossover", "begins with its number"),
        ] {
            let refused = Code::parse(typed).unwrap_err();
            assert!(refused.contains(says), "{typed:?}: {refused}");
            // No word that was typed comes back; the refusal of no code
            // names a fixed example, which nobody typed.
            for word in typed.split('-').filter(|w| w.chars().all(char::is_alphabetic) && !w.is_empty()) {
                assert!(!refused.contains(word), "{typed:?} echoed {word:?}: {refused}");
            }
        }
        assert!(Code::parse(&"7-crossover".repeat(40)).unwrap_err().contains("bytes"));
    }
}
