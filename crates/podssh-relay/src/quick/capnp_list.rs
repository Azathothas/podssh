//! A list of structs of a message being read, whose elements are made as
//! they are asked for (T-403). A list of a few words can count 2^30 - 1
//! elements of no size: a vector of each, made at once, held hundreds of MB
//! for some bytes of the edge's (cfrs's GitHub #5 found the same, 80 MiB
//! from 96 bytes). The count itself is charged to the message's budget.

use super::{Message, Struct};

/// The structs of a list in a message being read. It holds no element, and
/// is `Copy`: it owns no memory, whatever its count.
#[derive(Clone, Copy)]
pub struct StructList<'a> {
    pub(super) msg: &'a Message<'a>,
    pub(super) seg: usize,
    /// The first word of the first element, after the list's tag.
    pub(super) first: usize,
    pub(super) count: usize,
    pub(super) data_words: u16,
    pub(super) ptr_count: u16,
}

impl<'a> StructList<'a> {
    /// A list that is not set: no element.
    pub(super) fn none(msg: &'a Message<'a>) -> StructList<'a> {
        StructList { msg, seg: 0, first: 0, count: 0, data_words: 0, ptr_count: 0 }
    }

    /// The count of elements, as the list's tag gives it.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Element `k`, if the list has one. The reader checked that the words
    /// of each element are in the segment.
    pub fn get(&self, k: usize) -> Option<Struct<'a>> {
        if k >= self.count {
            return None;
        }
        let each = usize::from(self.data_words) + usize::from(self.ptr_count);
        let data = self.first + k * each;
        Some(Struct {
            msg: self.msg,
            seg: self.seg,
            data,
            data_words: self.data_words,
            ptrs: data + usize::from(self.data_words),
            ptr_count: self.ptr_count,
        })
    }

    /// The elements, in order.
    pub fn iter(&self) -> Elements<'a> {
        Elements { list: *self, next: 0 }
    }
}

impl<'a> IntoIterator for StructList<'a> {
    type Item = Struct<'a>;
    type IntoIter = Elements<'a>;

    fn into_iter(self) -> Elements<'a> {
        Elements { list: self, next: 0 }
    }
}

/// The elements of a [`StructList`], each made when it is reached.
#[derive(Clone)]
pub struct Elements<'a> {
    list: StructList<'a>,
    next: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Struct<'a>;

    fn next(&mut self) -> Option<Struct<'a>> {
        let element = self.list.get(self.next)?;
        self.next += 1;
        Some(element)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.list.count - self.next;
        (left, Some(left))
    }

    /// A jump, not a walk: the elements skipped are not made.
    fn nth(&mut self, n: usize) -> Option<Struct<'a>> {
        self.next = self.next.saturating_add(n).min(self.list.count);
        self.next()
    }
}

impl ExactSizeIterator for Elements<'_> {}
