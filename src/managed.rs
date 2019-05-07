use core::ops;
use core::slice;

/// A list of mutable objects.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slice<'a, T: 'a> {
    /// A single inline instance.
    ///
    /// Great when a static lifetime is required but no dynamic allocation should take place. It
    /// should be obvious that the slice managed by this has length one.
    One(T),

    /// An allocated list of objects.
    #[cfg(feature = "std")]
    Many(Vec<T>),

    /// A list of objects living in borrowed memory.
    ///
    /// Best used when allocation is to be avoided at all costs but a dynamic length is required.
    Borrowed(&'a mut [T]),
}

impl<'a, T: 'a> Slice<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Slice::One(t) => slice::from_ref(t),
            #[cfg(feature = "std")]
            Slice::Many(vec) => vec.as_slice(),
            Slice::Borrowed(slice) => slice,
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            Slice::One(t) => slice::from_mut(t),
            #[cfg(feature = "std")]
            Slice::Many(vec) => vec.as_mut_slice(),
            Slice::Borrowed(slice) => slice,
        }
    }
}

impl<T> From<T> for Slice<'_, T> {
    fn from(t: T) -> Self {
        Slice::One(t)
    }
}

impl<T> From<Option<T>> for Slice<'_, T> {
    fn from(t: Option<T>) -> Self {
        match t {
            None => Slice::Borrowed(<&mut [T]>::default()),
            Some(t) => Slice::One(t),
        }
    }
}

#[cfg(feature = "std")]
impl<T> From<Vec<T>> for Slice<'_, T> {
    fn from(t: Vec<T>) -> Self {
        Slice::Many(t)
    }
}

impl<'a, T> From<&'a mut [T]> for Slice<'a, T> {
    fn from(t: &'a mut [T]) -> Self {
        Slice::Borrowed(t)
    }
}

impl<T> ops::Deref for Slice<'_, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> ops::DerefMut for Slice<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}
