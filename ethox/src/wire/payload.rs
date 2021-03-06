//! Newtype wrappers of the fundamental byte-buffer `[u8]`.
use core::ops;

use crate::managed::Slice;

/// A specialized, internal variant of `Borrow<payload>`.
///
/// This ensures that the implementation is also consistent and always resolves to the same memory
/// region, an implementation detail that other parts of the crate could rely upon. The guarantee
/// is that the values in the referred to byte region will not appear differently, which is trivial
/// when we guarantee that the byte region is part of our object and does not change.
pub trait Payload {
    /// Get the bytes wrapped in the `payload` newtype.
    ///
    /// [`payload`]: struct.payload.html
    fn payload(&self) -> &payload;
}

/// A specialized, internal variant of `BorrowMut<payload>`.
///
/// This ensures that the implementation is also consistent and always resolves to the same memory
/// region, an implementation detail that other parts of the crate could rely upon. The guarantee
/// is that the values in the referred to byte region will not appear differently, which is trivial
/// when we guarantee that the byte region is part of our object and does not change.
pub trait PayloadMut: Payload {
    /// Resize the payload.
    ///
    /// New bytes will be intialized with some value, likely `0` but not guaranteed.
    fn resize(&mut self, length: usize) -> Result<(), Error>;

    /// Resize the payload while keeping some data.
    ///
    /// Should either fully work or outright fail. The given range of payload data must be
    /// logically unchanged. In particular it should also be placed at the same relative position
    /// in the payload.
    ///
    /// The implementation only ever has to preserve the overlap between `keep` and the current and
    /// the new payload length. It is valid to pass in `0..usize::MAX` to keep all of the payload
    /// which fits into the resize length. When resized to a larger frame the initialization should
    /// be `0` but this must not be relied upon.
    fn reframe(&mut self, reframe: Reframe) -> Result<(), Error>;

    /// Retrieve the mutable, inner payload.
    fn payload_mut(&mut self) -> &mut payload;
}

/// Groups parameters and utilities for payload reframing.
///
/// The term reframing means changing the outer embedding of a payload while preserving at least
/// some part of its content. In contrast, resizing need never provide any guarantees besides a
/// correct size. Intermediate layers will have to propagate a reframing call downwards and in the
/// process overestimate the preserved region. Some utility methods for this case are provided.
pub struct Reframe {
    /// The desired length.
    pub length: usize,
    /// The range in the current payload whose content must be preserved.
    pub range: ops::Range<usize>,
}

byte_wrapper! {
    /// A dynamically sized type representing a packet payload.
    ///
    /// This type is seemingly just a `[u8]`. It is a newtype wrapper so that this crate can freely
    /// implement traits for it but also restrict the standard trait implementations to not be
    /// available.
    ///
    /// To create a `payload` use the provided `From` trait impls, to convert it back you can use
    /// either of the synonyms `as_bytes` or `as_slice`, and their mutable variants.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct payload([u8]);
}

/// Error variants for resizing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// Indicates the requested length could not be provided.
    ///
    /// The exact cause will depend on circumstances: the resource might be exhausted; the size
    /// could be too small; or it is required that the size be divisible by a certain constant.
    BadSize,
}

impl payload {
    /// Converts this payload to a standard byte slice. This is a no-op pointer conversion.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Converts this payload to a mutable byte slice. This is a no-op pointer conversion.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Converts this payload to a standard byte slice. This is a no-op pointer conversion.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Converts this payload to a mutable byte slice. This is a no-op pointer conversion.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Reframe {
    /// Modify to include a header structure.
    pub fn within_header(&mut self, header: usize) {
        self.range.start = 0;
        self.range.end += header;
        self.length += header;
    }
}

impl<'a> From<&'a [u8]> for &'a payload {
    fn from(val: &'a [u8]) -> &'a payload {
        payload::__from_macro_new_unchecked(val)
    }
}

impl<'a> From<&'a mut [u8]> for &'a mut payload {
    fn from(val: &'a mut [u8]) -> &'a mut payload {
        payload::__from_macro_new_unchecked_mut(val)
    }
}

impl<'a> From<&'a payload> for &'a [u8] {
    fn from(val: &'a payload) -> &'a [u8] {
        val.as_slice()
    }
}

impl<'a> From<&'a mut payload> for &'a mut [u8] {
    fn from(val: &'a mut payload) -> &'a mut [u8] {
        val.as_mut_slice()
    }
}

impl AsRef<[u8]> for payload {
    fn as_ref(&self) -> &[u8] {
        self.into()
    }
}

impl AsMut<[u8]> for payload {
    fn as_mut(&mut self) -> &mut [u8] {
        self.into()
    }
}

impl ops::Deref for payload {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl ops::DerefMut for payload {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Payload for [u8] {
    fn payload(&self) -> &payload {
        self.into()
    }
}

impl PayloadMut for [u8] {
    fn payload_mut(&mut self) -> &mut payload {
        self.into()
    }

    fn resize(&mut self, len: usize) -> Result<(), Error> {
        if self.len() == len {
            Ok(())
        } else {
            Err(Error::BadSize)
        }
    }

    fn reframe(&mut self, reframe: Reframe) -> Result<(), Error> {
        self.resize(reframe.length)
    }
}

impl Payload for payload {
    fn payload(&self) -> &payload {
        self
    }
}

impl PayloadMut for payload {
    fn payload_mut(&mut self) -> &mut payload {
        self
    }

    fn resize(&mut self, len: usize) -> Result<(), Error> {
        self.as_mut_slice().resize(len)
    }

    fn reframe(&mut self, reframe: Reframe) -> Result<(), Error> {
        self.resize(reframe.length)
    }
}

impl<P: Payload + ?Sized> Payload for &'_ P {
    fn payload(&self) -> &payload {
        (**self).payload()
    }
}

impl<P: Payload + ?Sized> Payload for &'_ mut P {
    fn payload(&self) -> &payload {
        (**self).payload()
    }
}

impl<P: PayloadMut + ?Sized> PayloadMut for &'_ mut P {
    fn payload_mut(&mut self) -> &mut payload {
        (**self).payload_mut()
    }

    fn resize(&mut self, length: usize) -> Result<(), Error> {
        (**self).resize(length)
    }

    fn reframe(&mut self, reframe: Reframe) -> Result<(), Error> {
        (**self).reframe(reframe)
    }
}

impl Payload for Slice<'_, u8> {
    fn payload(&self) -> &payload {
        self.as_slice().into()
    }
}

impl PayloadMut for Slice<'_, u8> {
    fn payload_mut(&mut self) -> &mut payload {
        self.as_mut_slice().into()
    }
    
    fn resize(&mut self, length: usize) -> Result<(), Error> {
        let inner = core::mem::replace(self, Slice::empty());

        let result;
        let inner = match inner {
            // Not the requested length.
            Slice::One(one) if length != 1 => {
                result = Err(Error::BadSize);
                Slice::One(one)
            },
            // Can fulfil exactly.
            Slice::One(one) => {
                result = Ok(());
                Slice::One(one)
            },
            Slice::Many(mut vec) => {
                vec.resize(length, 0);
                result = Ok(());
                Slice::Many(vec)
            },
            Slice::Borrowed(inner) => {
                if inner.len() >= length {
                    result = Ok(());
                    Slice::Borrowed(&mut inner[..length])
                } else {
                    result = Err(Error::BadSize);
                    Slice::Borrowed(inner)
                }
            },
        };

        core::mem::replace(self, inner);
        result
    }

    fn reframe(&mut self, reframe: Reframe) -> Result<(), Error> {
        // We always preserve the full prefix.
        self.resize(reframe.length)
    }
}

mod std_impls {
    use crate::alloc::vec::Vec;
    use super::{Error, Reframe, Payload, PayloadMut, payload};

    impl Payload for Vec<u8> {
        fn payload(&self) -> &super::payload {
            self.as_slice().into()
        }
    }

    impl PayloadMut for Vec<u8> {
        fn payload_mut(&mut self) -> &mut payload {
            self.as_mut_slice().into()
        }

        fn resize(&mut self, length: usize) -> Result<(), Error> {
            Ok(self.resize(length, 0u8))
        }

        fn reframe(&mut self, reframe: Reframe) -> Result<(), Error> {
            // We always preserve the full prefix.
            PayloadMut::resize(self, reframe.length)
        }
    }
}
