use core::ops::Index;
use core::slice::SliceIndex;

use super::Slice;

/// Maintains an ordered slice.
///
/// Highly inefficient for anything but its logarithmic query time.
pub struct Ordered<'a, T> {
    inner: Slice<'a, T>,
    start: usize,
}

impl<'a, T> Ordered<'a, T> {
    pub fn new(slice: Slice<'a, T>) -> Self {
        Ordered {
            inner: slice,
            start: 0,
        }
    }

    /// Get a mutable reference to the element that would be pushed next.
    pub fn init(&mut self) -> Option<&mut T> {
        self.inner.as_mut_slice().get_mut(self.start)
    }

    /// Insert the next element.
    ///
    /// Returns the index at which the element was insert and `None` if there was no element to
    /// insert.
    pub fn push(&mut self) -> Option<usize>
        where T: Ord,
    {
        let next = self.inner.as_slice().get(self.start)?;
        let idx = self.ordered_slice()
            .binary_search(next)
            .unwrap_or_else(|x| x);
        let moving = self.start - idx;
        self.start += 1;
        // NLL, implicit drop of next.
        self.inner[idx..self.start]
            .rotate_left(moving);
        Some(idx)
    }

    /// Remove the element at the specified index.
    ///
    /// Returns `Some(())` if successful and `None` if the index was not valid.
    pub fn pop(&mut self, idx: usize) -> Option<()> {
        // Find out how many we need to move and check validity.
        let moving = self.start
            .checked_sub(idx)?
            .checked_sub(1)?;
        self.inner[idx..self.start]
            .rotate_right(moving);
        self.start -= 1;
        Some(())
    }

    /// The ordered region in the slice.
    pub fn ordered_slice(&self) -> &[T] {
        &self.inner.as_slice()[..self.start]
    }

    /// Retrieve part of the ordered range if possible.
    ///
    /// This is a non-panicking variant of index access.
    pub fn get<I>(&self, idx: I) -> Option<&I::Output>
        where I: SliceIndex<[T]>
    {
        self.ordered_slice().get(idx)
    }
}

impl<T, I: SliceIndex<[T]>> Index<I> for Ordered<'_, T> {
    type Output = I::Output;

    fn index(&self, idx: I) -> &I::Output {
        self.ordered_slice().index(idx)
    }
}
