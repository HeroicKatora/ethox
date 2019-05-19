use core::ops::{Deref, DerefMut};
use crate::wire::{Payload, PayloadError, PayloadMut, payload};

pub struct Partial<C> {
    inner: C,
    part: usize,
}

impl<C> Partial<C> {
    pub fn as_empty(inner: C) -> Self {
        Partial {
            inner,
            part: 0,
        }
    }

    pub fn set_len_unchecked(&mut self, len: usize) {
        self.part = len;
    }

    pub fn len(&self) -> usize {
        self.part
    }
}

impl<C, T> Partial<C>
    where C: Deref<Target=[T]>
{
    pub fn as_full(inner: C) -> Self {
        let part = inner.len();
        Partial {
            inner,
            part,
        }
    }
}

impl<C, T> Deref for Partial<C>
    where C: Deref<Target=[T]>
{
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.inner.deref()[..self.part]
    }
}

impl<C, T> DerefMut for Partial<C>
    where C: Deref<Target=[T]> + DerefMut
{
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.inner.deref_mut()[..self.part]
    }
}

impl<C, T> AsRef<[T]> for Partial<C> where C: AsRef<[T]> {
    fn as_ref(&self) -> &[T] {
        &self.inner.as_ref()[..self.part]
    }
}

impl<C, T> AsMut<[T]> for Partial<C> where C: AsMut<[T]> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.inner.as_mut()[..self.part]
    }
}

impl<C: Payload> Payload for Partial<C> {
    fn payload(&self) -> &payload {
        self.inner
            .payload()
            .as_slice()[..self.part]
            .into()
    }
}

impl<C: PayloadMut> PayloadMut for Partial<C> {
    fn payload_mut(&mut self) -> &mut payload {
        let len = self.part;
        let slice = self.inner
            .payload_mut()
            .as_mut_slice();
        (&mut slice[..len]).into()
    }

    fn resize(&mut self, len: usize) -> Result<(), PayloadError> {
        if len <= self.inner.payload().len() {
            self.part = len;
            Ok(())
        } else {
            self.inner.resize(len)?;
            self.part = len;
            Ok(())
        }
    }
}
