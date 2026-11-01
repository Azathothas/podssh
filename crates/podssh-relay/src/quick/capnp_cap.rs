//! Capabilities in a message: a pointer of the kind "other" whose upper half
//! is the capability's index in the table of its payload, as Cap'n Proto's
//! encoding writes an interface. A server of one capability writes it in
//! the answer to a bootstrap (T-411).

use super::{At, Builder, Malformed, Struct};

/// The lower half of a capability's pointer: the kind "other", 3, and 30
/// bits of 0.
const CAPABILITY: u64 = 3;

impl Builder {
    /// The capability `index` of the payload's table, in pointer `i` of
    /// `parent`.
    pub fn set_capability(&mut self, parent: At, i: u16, index: u32) {
        let slot = Self::slot(parent, i);
        self.words[slot] = CAPABILITY | (u64::from(index) << 32);
    }
}

impl Struct<'_> {
    /// The index in the table of capabilities of the capability in
    /// pointer `i`.
    pub fn get_capability(&self, i: u16) -> Result<Option<u32>, Malformed> {
        let Some(slot) = self.slot(i) else { return Ok(None) };
        let word = self.msg.word(self.seg, slot)?;
        match word {
            0 => Ok(None),
            w if w & 3 == 3 && (w as u32) == CAPABILITY as u32 => Ok(Some((w >> 32) as u32)),
            _ => Err(Malformed("a capability was expected")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Builder, Message};

    #[test]
    fn a_capability_written_reads_as_its_index_and_a_text_does_not() {
        let (mut b, root) = Builder::new(0, 2);
        b.set_capability(root, 0, 5);
        b.set_text(root, 1, "not a capability");
        let frame = b.frame();
        // The pointer as the encoding has it: the kind 3, then the index.
        assert_eq!(frame[16..24], (3u64 | 5 << 32).to_le_bytes());
        let message = Message::read(&frame).unwrap();
        let root = message.root().unwrap();
        assert_eq!(root.get_capability(0), Ok(Some(5)));
        assert!(root.get_capability(1).is_err());
        assert_eq!(root.get_capability(2), Ok(None), "past the pointers: none");
    }
}
