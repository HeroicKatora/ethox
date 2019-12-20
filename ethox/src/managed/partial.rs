use core::ops::{Deref, DerefMut};
use core::slice::SliceIndex;

use crate::wire::{Reframe, Payload, PayloadError, PayloadMut, payload};

/// Refer to a part of some container.
///
/// Useful to create a dynamically sized storage over a statically sized backing buffer. This
/// covers both byte buffers, such as packets, or general type buffers to be used similar to a
/// vector.
///
/// # Usage
///
/// Use a slice as a backing storage, logically initializing it gradually. Contrary to `Vec` the
/// methods `push` and `pop` return a mutable reference to their element after they have succeeded
/// instead of operating on values. They only change the logical length when called.
///
/// ```
/// # use ethox::managed::Partial;
/// let mut elements = [0; 16];
/// let mut storage = Partial::new(&mut elements[..]);
///
/// for el in 0..10 {
///     // Note that this drops an instance. That may be undesired.
///     *storage.push().unwrap() = el;
/// }
/// ```
///
/// This is useful as a generic payload representation as well. Resizing it is as simple as setting
/// the current length unless the request can not be fulfilled with the current buffer size. Only
/// in that case will it resize the underlying buffer.
// TODO: implement PartialEq, Eq, PartialOrd, Ord
#[derive(Clone, Debug)]
pub struct Partial<C> {
    inner: C,
    end: usize,
}

impl<C> Partial<C> {
    /// Make an instance that initially refers to an empty part.
    pub fn new(container: C) -> Self {
        Partial {
            inner: container,
            end: 0,
        }
    }

    /// Get a reference to the underlying buffer.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Get a mutable reference to the underlying buffer.
    pub fn inner_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    /// Unwrap the inner buffer.
    pub fn into_inner(self) -> C {
        self.inner
    }

    /// Set the length to which to refer.
    ///
    /// This does not check that the underlying storage actually has the claimed length. Setting a
    /// wrong value will typically lead to panicking later on.
    pub fn set_len_unchecked(&mut self, len: usize) {
        self.end = len;
    }

    /// Get the claimed length.
    ///
    /// Does not validate that a slice of the claimed length can actually be referred to.
    pub fn len(&self) -> usize {
        self.end
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.end == 0
    }

    /// Simply increase the length.
    pub fn inc(&mut self) {
        self.end += 1;
    }

    /// Simply decrease the length.
    pub fn dec(&mut self) {
        self.end -= 1;
    }
}

impl<C, T> Partial<C>
    where C: Deref<Target=[T]>
{
    /// Construct an instance referring to all of the inner container.
    ///
    /// This sets the Partial's length based on the slice to which the container dereferences. If
    /// the containers impl of `Deref` is not consistent then some later calls may panic (but not
    /// this constructor).
    pub fn new_full(inner: C) -> Self {
        let end = inner.len();
        Partial {
            inner,
            end,
        }
    }

    /// Check how many elements can be referred to at most.
    ///
    /// This results in the length of the underlying container, not its capacity since the
    /// `Partial` is not aware of reallocation or other behaviour to change the underlying
    /// containers length.
    pub fn capacity(&self) -> usize {
        self.inner.len()
    }

    /// Get the logically active elements as a slice.
    pub fn as_slice(&self) -> &[T] {
        &self.inner[..self.end]
    }

    /// Retrieve the logical path of the underlying container if possible.
    ///
    /// This is a non-panicking variant of index access.
    pub fn get<'a, I>(&'a self, idx: I) -> Option<&'a I::Output>
        where I: SliceIndex<[T]>, T: 'a,
    {
        self.as_slice().get(idx)
    }
}

impl<C, T> Partial<C>
    where C: Deref<Target=[T]> + DerefMut,
{
    /// Get a mutable reference to the element that would be pushed next.
    pub fn init(&mut self) -> Option<&mut T> {
        self.inner.get_mut(self.end)
    }

    /// Insert the next element at some position.
    ///
    /// # Panics
    ///
    /// This method panics if the `pos` is larger than the current length.
    pub fn insert_at(&mut self, pos: usize) -> Option<&mut T> {
        // All of the current slice until end is rotated.
        let rotation = self.end.checked_sub(pos)
            .expect("Index out of bounds");
        // How to swallow the new element
        let new_end = self.end.checked_add(1)?;
        // Rotate the slice.
        self.inner
            .get_mut(pos..new_end)?
            .rotate_left(rotation);
        // Update. Not done before so that the state is consistent.
        self.end = new_end;
        // We know that this is should be valid.
        Some(self.inner
            .get_mut(pos)
            .unwrap())
    }

    /// Insert behind the last element.
    pub fn push(&mut self) -> Option<&mut T> {
        self.insert_at(self.end)
    }

    /// Remove the element at a position.
    pub fn remove_at(&mut self, pos: usize) -> Option<&mut T> {
        // Can we even pop an element?
        let new_end = self.end.checked_sub(1)?;
        // Popped element is moved over all remaining elements.
        let rotation = new_end.checked_sub(pos)?;
        self.inner
            .get_mut(pos..self.end)?
            .rotate_right(rotation);
        // Update. Not done before so that the state is consistent.
        self.end = new_end;
        // We know that this is should be valid.
        Some(self.inner
            .get_mut(self.end)
            .unwrap())
    }

    /// Remove the last element.
    pub fn pop(&mut self) -> Option<&mut T> {
        self.remove_at(self.end.wrapping_sub(1))
    }

    /// Get the logically active elements as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.inner[..self.end]
    }

    /// Retrieve the logical path of the underlying container if possible.
    ///
    /// This is a non-panicking variant of index access.
    pub fn get_mut<'a, I>(&'a mut self, idx: I) -> Option<&'a mut I::Output>
        where I: SliceIndex<[T]>, T: 'a,
    {
        self.as_mut_slice().get_mut(idx)
    }
}


impl<C, T> Deref for Partial<C>
    where C: Deref<Target=[T]>
{
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<C, T> DerefMut for Partial<C>
    where C: Deref<Target=[T]> + DerefMut
{
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<C, T> AsRef<[T]> for Partial<C> where C: AsRef<[T]> {
    fn as_ref(&self) -> &[T] {
        &self.inner.as_ref()[..self.end]
    }
}

impl<C, T> AsMut<[T]> for Partial<C> where C: AsMut<[T]> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.inner.as_mut()[..self.end]
    }
}

impl<C: Payload> Payload for Partial<C> {
    fn payload(&self) -> &payload {
        self.inner
            .payload()
            .as_slice()[..self.end]
            .into()
    }
}

impl<C: PayloadMut> PayloadMut for Partial<C> {
    fn payload_mut(&mut self) -> &mut payload {
        let len = self.end;
        let slice = self.inner
            .payload_mut()
            .as_mut_slice();
        (&mut slice[..len]).into()
    }

    fn resize(&mut self, len: usize) -> Result<(), PayloadError> {
        if len <= self.inner.payload().len() {
            self.end = len;
            Ok(())
        } else {
            self.inner.resize(len)?;
            self.end = len;
            Ok(())
        }
    }

    fn reframe(&mut self, reframe: Reframe) -> Result<(), PayloadError> {
        self.resize(reframe.length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_operation() {
        const SIZE: usize = 4;
        let mut slice = [0; SIZE];
        let mut partial = Partial::new(&mut slice[..]);
        for i in 0..SIZE {
            let element = partial.push().expect("Enough space");
            *element = i;
        }

        assert_eq!(partial.len(), 4);
        assert_eq!(partial.as_slice(), &[0, 1, 2, 3]);

        for i in (0..SIZE).rev() {
            let element = partial.pop().expect("Still one left");
            assert_eq!(*element, i);
        }

        // Now we can no longer access any element.
        assert_eq!(partial.get(0), None);
        assert_eq!(partial.get_mut(0), None);
    }

    #[test]
    fn inserts() {
        const SIZE: usize = 4;
        let mut slice = [0; SIZE];
        let mut partial = Partial::new(&mut slice[..]);

        // Assigns the eventual index.
        *partial.insert_at(0).unwrap() = 2;
        *partial.insert_at(0).unwrap() = 0;
        *partial.insert_at(1).unwrap() = 1;
        *partial.insert_at(3).unwrap() = 3;

        assert!(partial.insert_at(0).is_none());
        assert!(partial.insert_at(1).is_none());
        assert!(partial.insert_at(2).is_none());
        assert!(partial.insert_at(3).is_none());
        assert!(partial.insert_at(4).is_none());

        assert_eq!(partial.as_slice(), [0, 1, 2, 3]);
    }

    #[test]
    #[should_panic]
    fn insert_at_invalid() {
        let mut slice = [0; 1];
        let mut partial = Partial::new(&mut slice[..]);
        // Out of logical bounds.
        partial.insert_at(1);
    }

    #[test]
    #[should_panic]
    fn insert_at_oob() {
        let mut slice = [0; 1];
        let mut partial = Partial::new(&mut slice[..]);
        assert!(partial.push().is_some());
        assert!(partial.len() == 1);
        // Out of physical bounds.
        let _x = partial.insert_at(2);
        eprintln!("Found a place but shouldn't have: {:?}", _x);
    }
}
