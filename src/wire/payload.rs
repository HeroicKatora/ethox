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
    fn resize(&mut self, _: usize) -> Result<(), Error>;

    /// Retrieve the mutable, inner payload.
    fn payload_mut(&mut self) -> &mut payload;
}

/// A dynamically sized type representing a packet payload.
///
/// This type is seemingly just a `[u8]`. It is a newtype wrapper so that this crate can freely
/// implement traits for it but also restrict the standard trait implementations to not be
/// available.
byte_wrapper!(payload);

/// Error variants for resizing.
pub enum Error {
    BadSize,
}

impl payload {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
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
            Slice::One(one) => {
                result = Err(Error::BadSize);
                Slice::One(one)
            },
            #[cfg(any(test, feature = "std"))]
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
}

#[cfg(any(feature = "std", test))]
mod std_impls {
    impl super::Payload for Vec<u8> {
        fn payload(&self) -> &super::payload {
            self.as_slice().into()
        }
    }

    impl super::PayloadMut for Vec<u8> {
        fn payload_mut(&mut self) -> &mut super::payload {
            self.as_mut_slice().into()
        }

        fn resize(&mut self, length: usize) -> Result<(), super::Error> {
            Ok(self.resize(length, 0u8))
        }
    }
}
