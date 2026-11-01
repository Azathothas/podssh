//! The few shapes of Cap'n Proto that a quick tunnel's registration needs
//! (T-300), written by hand as libcfd writes them, with no code generator
//! and no C: a message of structs, lists, texts and data, and the framing of
//! a stream (a table of segments, then the segments).
//!
//! The builder writes one segment, as a small message needs. The reader
//! takes any number of segments and follows far pointers, as the edge's
//! encoder may split a message; it counts the words that it reads, so that
//! a message that points at itself in a loop ends in an error. A list of
//! structs is read as its elements are asked for ([`StructList`]): a few
//! words can count 2^30 - 1 elements of no size (T-403).

/// The most words that a reader reads in one message, as capnp's own limit.
const BUDGET: u64 = 8 * 1024 * 1024;
/// The most words read of a message of the control stream, or of a stream's
/// request: the edge's are some hundreds of bytes, and a request is 64 KiB
/// at most, so a list that counts more elements is refused (T-403).
pub const CONTROL_BUDGET: u64 = 64 * 1024;
/// The most segments of one message, and the most bytes of one frame.
const MAX_SEGMENTS: usize = 512;
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// A message that does not read as Cap'n Proto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a malformed Cap'n Proto message: {}", self.0)
    }
}

impl std::error::Error for Malformed {}

/// The element size of a list pointer.
const BYTE: u64 = 2;
const POINTER: u64 = 6;
const COMPOSITE: u64 = 7;

/// A struct in a message being built: where its data and its pointers are.
#[derive(Debug, Clone, Copy)]
pub struct At {
    data: usize,
    data_words: u16,
    ptrs: usize,
    ptr_count: u16,
}

/// A message of one segment, built front to back.
pub struct Builder {
    words: Vec<u64>,
}

impl Builder {
    /// A message whose root is a struct of `data_words` and `ptr_count`.
    pub fn new(data_words: u16, ptr_count: u16) -> (Builder, At) {
        let mut b = Builder { words: vec![0] };
        let at = b.alloc_struct(data_words, ptr_count);
        b.point_struct(0, at);
        (b, at)
    }

    fn alloc(&mut self, words: usize) -> usize {
        let at = self.words.len();
        self.words.resize(at + words, 0);
        at
    }

    fn alloc_struct(&mut self, data_words: u16, ptr_count: u16) -> At {
        let data = self.alloc(usize::from(data_words) + usize::from(ptr_count));
        At { data, data_words, ptrs: data + usize::from(data_words), ptr_count }
    }

    fn offset(ptr: usize, target: usize) -> u64 {
        let words = target as i64 - (ptr as i64 + 1);
        ((words as u64) & 0x3fff_ffff) << 2
    }

    fn point_struct(&mut self, ptr: usize, at: At) {
        // A struct of no size points at its own pointer, as capnp writes it.
        let offset =
            if at.data_words == 0 && at.ptr_count == 0 { 0x3fff_ffff << 2 } else { Self::offset(ptr, at.data) };
        self.words[ptr] = offset | (u64::from(at.data_words) << 32) | (u64::from(at.ptr_count) << 48);
    }

    fn point_list(&mut self, ptr: usize, target: usize, size: u64, count: u64) {
        self.words[ptr] = 1 | Self::offset(ptr, target) | (size << 32) | (count << 35);
    }

    fn slot(parent: At, i: u16) -> usize {
        assert!(i < parent.ptr_count, "pointer {i} of a struct of {}", parent.ptr_count);
        parent.ptrs + usize::from(i)
    }

    /// A new struct in pointer `i` of `parent`.
    pub fn init_struct(&mut self, parent: At, i: u16, data_words: u16, ptr_count: u16) -> At {
        let slot = Self::slot(parent, i);
        let at = self.alloc_struct(data_words, ptr_count);
        self.point_struct(slot, at);
        at
    }

    /// A list of `count` structs in pointer `i` of `parent`, each of
    /// `data_words` and `ptr_count`: its elements.
    pub fn init_struct_list(&mut self, parent: At, i: u16, count: u32, data_words: u16, ptr_count: u16) -> Vec<At> {
        let slot = Self::slot(parent, i);
        let each = usize::from(data_words) + usize::from(ptr_count);
        let tag = self.alloc(1 + each * count as usize);
        self.point_list(slot, tag, COMPOSITE, (each * count as usize) as u64);
        self.words[tag] = (u64::from(count) << 2) | (u64::from(data_words) << 32) | (u64::from(ptr_count) << 48);
        (0..count as usize)
            .map(|k| {
                let data = tag + 1 + k * each;
                At { data, data_words, ptrs: data + usize::from(data_words), ptr_count }
            })
            .collect()
    }

    fn bytes_at(&mut self, slot: usize, bytes: &[u8], nul: bool) {
        let len = bytes.len() + usize::from(nul);
        let start = self.alloc(len.div_ceil(8));
        for (k, b) in bytes.iter().enumerate() {
            self.words[start + k / 8] |= u64::from(*b) << (8 * (k % 8));
        }
        self.point_list(slot, start, BYTE, len as u64);
    }

    /// Text in pointer `i` of `parent`, with the NUL that Text ends with.
    pub fn set_text(&mut self, parent: At, i: u16, text: &str) {
        let slot = Self::slot(parent, i);
        self.bytes_at(slot, text.as_bytes(), true);
    }

    /// Data in pointer `i` of `parent`.
    pub fn set_data(&mut self, parent: At, i: u16, data: &[u8]) {
        let slot = Self::slot(parent, i);
        self.bytes_at(slot, data, false);
    }

    /// A list of texts in pointer `i` of `parent`.
    pub fn set_text_list(&mut self, parent: At, i: u16, texts: &[&str]) {
        let slot = Self::slot(parent, i);
        let start = self.alloc(texts.len());
        self.point_list(slot, start, POINTER, texts.len() as u64);
        for (k, text) in texts.iter().enumerate() {
            self.bytes_at(start + k, text.as_bytes(), true);
        }
    }

    fn set_bits(&mut self, at: At, bit: usize, width: usize, value: u64) {
        assert!(bit + width <= usize::from(at.data_words) * 64, "bit {bit} of a data section of {}", at.data_words);
        let word = &mut self.words[at.data + bit / 64];
        let shift = bit % 64;
        let mask = if width == 64 { u64::MAX } else { ((1u64 << width) - 1) << shift };
        *word = (*word & !mask) | ((value << shift) & mask);
    }

    /// The field of `bytes` bytes at byte `offset` of the data section, as
    /// the schema numbers it in units of its own size times that size.
    pub fn set_u8(&mut self, at: At, byte: usize, value: u8) {
        self.set_bits(at, byte * 8, 8, u64::from(value));
    }

    pub fn set_u16(&mut self, at: At, byte: usize, value: u16) {
        self.set_bits(at, byte * 8, 16, u64::from(value));
    }

    pub fn set_u32(&mut self, at: At, byte: usize, value: u32) {
        self.set_bits(at, byte * 8, 32, u64::from(value));
    }

    pub fn set_u64(&mut self, at: At, byte: usize, value: u64) {
        self.set_bits(at, byte * 8, 64, value);
    }

    pub fn set_bit(&mut self, at: At, bit: usize, value: bool) {
        self.set_bits(at, bit, 1, u64::from(value));
    }

    /// The message, framed for a stream: one segment.
    pub fn frame(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.words.len() * 8);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(self.words.len() as u32).to_le_bytes());
        for word in &self.words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// The length of the first frame of `bytes` once its table is there: its
/// table and its segments. `None` while the table itself is not complete.
pub fn frame_len(bytes: &[u8]) -> Result<Option<usize>, Malformed> {
    let Some(head) = bytes.get(..4) else { return Ok(None) };
    let count = u32::from_le_bytes(head.try_into().unwrap()) as usize + 1;
    if count > MAX_SEGMENTS {
        return Err(Malformed("too many segments"));
    }
    let table = (4 + 4 * count).div_ceil(8) * 8;
    if bytes.len() < 4 + 4 * count {
        return Ok(None);
    }
    // In u64: 512 segments of 2^32 words each pass a usize of 32 bits.
    let mut words = 0u64;
    for k in 0..count {
        let at = 4 + 4 * k;
        words += u64::from(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()));
    }
    let len = table as u64 + words * 8;
    if len > MAX_FRAME as u64 {
        return Err(Malformed("a frame larger than the limit"));
    }
    Ok(Some(len as usize))
}

/// A message read from a whole frame.
pub struct Message<'a> {
    segments: Vec<&'a [u8]>,
    budget: std::cell::Cell<u64>,
}

impl<'a> Message<'a> {
    /// The message of `frame`, which [`frame_len`] measured, read within
    /// capnp's own limit of words.
    pub fn read(frame: &'a [u8]) -> Result<Message<'a>, Malformed> {
        Self::read_within(frame, BUDGET)
    }

    /// The message of `frame`, read within `budget` words: a list, a loop of
    /// pointers or a struct that would read more ends in an error.
    pub fn read_within(frame: &'a [u8], budget: u64) -> Result<Message<'a>, Malformed> {
        let len = frame_len(frame)?.ok_or(Malformed("a frame cut short"))?;
        if frame.len() < len {
            return Err(Malformed("a frame cut short"));
        }
        let count = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize + 1;
        let mut at = (4 + 4 * count).div_ceil(8) * 8;
        let mut segments = Vec::with_capacity(count);
        for k in 0..count {
            let words = u32::from_le_bytes(frame[4 + 4 * k..8 + 4 * k].try_into().unwrap()) as usize;
            segments.push(&frame[at..at + words * 8]);
            at += words * 8;
        }
        Ok(Message { segments, budget: std::cell::Cell::new(budget) })
    }

    fn word(&self, seg: usize, at: usize) -> Result<u64, Malformed> {
        let segment = self.segments.get(seg).ok_or(Malformed("a pointer to a segment that is not there"))?;
        let bytes = segment.get(at * 8..at * 8 + 8).ok_or(Malformed("a pointer out of its segment"))?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn spend(&self, words: u64) -> Result<(), Malformed> {
        let left = self.budget.get().checked_sub(words.max(1)).ok_or(Malformed("more words read than the limit"))?;
        self.budget.set(left);
        Ok(())
    }

    fn in_segment(&self, seg: usize, start: usize, words: usize) -> Result<(), Malformed> {
        // A segment that is not there is malformed, an empty object in it
        // too: a far pointer can name any segment.
        let len = self.segments.get(seg).ok_or(Malformed("a pointer to a segment that is not there"))?.len() / 8;
        if start.checked_add(words).is_some_and(|end| end <= len) {
            Ok(())
        } else {
            Err(Malformed("an object out of its segment"))
        }
    }

    /// The root struct.
    pub fn root(&'a self) -> Result<Struct<'a>, Malformed> {
        self.struct_at(0, 0)?.ok_or(Malformed("no root"))
    }

    /// The pointer at word `at` of segment `seg`, with far pointers
    /// followed: the segment of the object, where the object starts, and the
    /// word that tells its kind and size.
    fn resolve(&self, seg: usize, at: usize) -> Result<Option<(usize, usize, u64)>, Malformed> {
        let word = self.word(seg, at)?;
        if word == 0 {
            return Ok(None);
        }
        if word & 3 != 2 {
            let offset = ((word as u32 as i32) >> 2) as i64;
            let start = at as i64 + 1 + offset;
            let start = usize::try_from(start).map_err(|_| Malformed("a pointer before its segment"))?;
            return Ok(Some((seg, start, word)));
        }
        let double = word & 4 != 0;
        let pad = ((word as u32) >> 3) as usize;
        let pad_seg = (word >> 32) as usize;
        let landing = self.word(pad_seg, pad)?;
        if !double {
            if landing & 3 == 2 {
                return Err(Malformed("a far pointer to a far pointer"));
            }
            return self.resolve(pad_seg, pad);
        }
        if landing & 7 != 2 {
            return Err(Malformed("a double far pointer whose pad is not a single far pointer"));
        }
        let tag = self.word(pad_seg, pad + 1)?;
        let object_seg = (landing >> 32) as usize;
        let object = ((landing as u32) >> 3) as usize;
        Ok(Some((object_seg, object, tag)))
    }

    fn struct_at(&'a self, seg: usize, at: usize) -> Result<Option<Struct<'a>>, Malformed> {
        let Some((seg, start, word)) = self.resolve(seg, at)? else { return Ok(None) };
        if word & 3 != 0 {
            return Err(Malformed("a struct was expected"));
        }
        let data_words = (word >> 32) as u16;
        let ptr_count = (word >> 48) as u16;
        let words = usize::from(data_words) + usize::from(ptr_count);
        if words == 0 {
            return Ok(Some(Struct { msg: self, seg, data: 0, data_words: 0, ptrs: 0, ptr_count: 0 }));
        }
        self.in_segment(seg, start, words)?;
        self.spend(words as u64)?;
        Ok(Some(Struct { msg: self, seg, data: start, data_words, ptrs: start + usize::from(data_words), ptr_count }))
    }

    /// The bytes of the list of bytes whose pointer is at word `at`.
    fn bytes_at(&self, seg: usize, at: usize) -> Result<Option<&'a [u8]>, Malformed> {
        let Some((seg, start, size, count)) = self.list_at(seg, at)? else { return Ok(None) };
        if size != BYTE {
            return Err(Malformed("a list of bytes was expected"));
        }
        let words = (count as usize).div_ceil(8);
        self.in_segment(seg, start, words)?;
        self.spend(words as u64)?;
        let segment: &'a [u8] = self.segments.get(seg).ok_or(Malformed("a pointer to a segment that is not there"))?;
        Ok(Some(&segment[start * 8..start * 8 + count as usize]))
    }

    /// The text whose pointer is at word `at`, without its NUL.
    fn text_at(&self, seg: usize, at: usize) -> Result<Option<&'a str>, Malformed> {
        let Some(bytes) = self.bytes_at(seg, at)? else { return Ok(None) };
        let (nul, text) = bytes.split_last().ok_or(Malformed("a text with no NUL"))?;
        if *nul != 0 {
            return Err(Malformed("a text with no NUL"));
        }
        std::str::from_utf8(text).map(Some).map_err(|_| Malformed("a text that is not UTF-8"))
    }

    /// A list pointer: its segment, its start, its element size and count.
    fn list_at(&self, seg: usize, at: usize) -> Result<Option<(usize, usize, u64, u64)>, Malformed> {
        let Some((seg, start, word)) = self.resolve(seg, at)? else { return Ok(None) };
        if word & 3 != 1 {
            return Err(Malformed("a list was expected"));
        }
        Ok(Some((seg, start, (word >> 32) & 7, word >> 35)))
    }
}

/// A struct of a message being read. A field past the end of its section
/// reads as its default, zero, as an older schema's struct is shorter.
#[derive(Clone, Copy)]
pub struct Struct<'a> {
    msg: &'a Message<'a>,
    seg: usize,
    data: usize,
    data_words: u16,
    ptrs: usize,
    ptr_count: u16,
}

impl<'a> Struct<'a> {
    fn bits(&self, bit: usize, width: usize) -> u64 {
        if bit + width > usize::from(self.data_words) * 64 {
            return 0;
        }
        let word = self.msg.word(self.seg, self.data + bit / 64).unwrap_or(0) >> (bit % 64);
        if width == 64 {
            word
        } else {
            word & ((1u64 << width) - 1)
        }
    }

    pub fn u8(&self, byte: usize) -> u8 {
        self.bits(byte * 8, 8) as u8
    }

    pub fn u16(&self, byte: usize) -> u16 {
        self.bits(byte * 8, 16) as u16
    }

    pub fn u32(&self, byte: usize) -> u32 {
        self.bits(byte * 8, 32) as u32
    }

    pub fn u64(&self, byte: usize) -> u64 {
        self.bits(byte * 8, 64)
    }

    pub fn bit(&self, bit: usize) -> bool {
        self.bits(bit, 1) == 1
    }

    fn slot(&self, i: u16) -> Option<usize> {
        (i < self.ptr_count).then(|| self.ptrs + usize::from(i))
    }

    /// The struct in pointer `i`, if one is set.
    pub fn get_struct(&self, i: u16) -> Result<Option<Struct<'a>>, Malformed> {
        match self.slot(i) {
            Some(slot) => self.msg.struct_at(self.seg, slot),
            None => Ok(None),
        }
    }

    /// The data in pointer `i`.
    pub fn get_data(&self, i: u16) -> Result<Option<&'a [u8]>, Malformed> {
        match self.slot(i) {
            Some(slot) => self.msg.bytes_at(self.seg, slot),
            None => Ok(None),
        }
    }

    /// The text in pointer `i`, without its NUL.
    pub fn get_text(&self, i: u16) -> Result<Option<&'a str>, Malformed> {
        match self.slot(i) {
            Some(slot) => self.msg.text_at(self.seg, slot),
            None => Ok(None),
        }
    }

    /// The texts of the list of texts in pointer `i`; a text that is not
    /// set reads as empty.
    pub fn get_text_list(&self, i: u16) -> Result<Vec<&'a str>, Malformed> {
        let Some(slot) = self.slot(i) else { return Ok(Vec::new()) };
        let Some((seg, start, size, count)) = self.msg.list_at(self.seg, slot)? else { return Ok(Vec::new()) };
        if size != POINTER {
            return Err(Malformed("a list of pointers was expected"));
        }
        self.msg.in_segment(seg, start, count as usize)?;
        self.msg.spend(count)?;
        (0..count as usize).map(|k| Ok(self.msg.text_at(seg, start + k)?.unwrap_or_default())).collect()
    }

    /// The index in the table of capabilities of the capability in
    /// pointer `i`.
    pub fn get_capability(&self, i: u16) -> Result<Option<u32>, Malformed> {
        let Some(slot) = self.slot(i) else { return Ok(None) };
        let word = self.msg.word(self.seg, slot)?;
        match word {
            0 => Ok(None),
            w if w & 3 == 3 && (w as u32) == 3 => Ok(Some((w >> 32) as u32)),
            _ => Err(Malformed("a capability was expected")),
        }
    }

    /// The list of structs in pointer `i`, whose elements are made as they
    /// are asked for. It is charged its words, or a word for each element
    /// where that is more, as capnp charges a list of elements of no size:
    /// so its count is within the message's budget (T-403).
    pub fn get_struct_list(&self, i: u16) -> Result<StructList<'a>, Malformed> {
        let Some(slot) = self.slot(i) else { return Ok(StructList::none(self.msg)) };
        let Some((seg, tag, size, words)) = self.msg.list_at(self.seg, slot)? else {
            return Ok(StructList::none(self.msg));
        };
        if size != COMPOSITE {
            return Err(Malformed("a list of structs was expected"));
        }
        self.msg.in_segment(seg, tag, 1 + words as usize)?;
        let head = self.msg.word(seg, tag)?;
        if head & 3 != 0 {
            return Err(Malformed("the tag of a list of structs is not a struct pointer"));
        }
        let count = u64::from((head as u32) >> 2);
        let data_words = (head >> 32) as u16;
        let ptr_count = (head >> 48) as u16;
        // In u64: 2^30 elements of 2^17 words each pass a usize of 32 bits.
        let each = u64::from(data_words) + u64::from(ptr_count);
        if each * count > words {
            return Err(Malformed("a list of structs longer than its words"));
        }
        self.msg.spend(words.max(count))?;
        Ok(StructList { msg: self.msg, seg, first: tag + 1, count: count as usize, data_words, ptr_count })
    }
}

#[path = "capnp_list.rs"]
mod list;
pub use list::{Elements, StructList};

#[cfg(test)]
#[path = "capnp_tests.rs"]
pub(crate) mod tests;
