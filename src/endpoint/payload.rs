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
pub trait PayloadMut {
    fn payload_mut(&mut self) -> &mut payload;
}

/// A dynamically sized type representing a packet payload.
///
/// This type is seemingly just a `[u8]`. It is a newtype wrapper so that this crate can freely
/// implement traits for it but also restrict the standard trait implementations to not be
/// available.
#[allow(non_snake_case)]
pub struct payload([u8]);

impl<'a> From<&'a [u8]> for &'a payload {
    fn from(val: &'a [u8]) -> &'a payload {
        unimplemented!()
    }
}

impl<'a> From<&'a mut [u8]> for &'a mut payload {
    fn from(val: &'a mut [u8]) -> &'a mut payload {
        unimplemented!()
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
}
