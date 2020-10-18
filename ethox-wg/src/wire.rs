use core::{convert::TryFrom, ops};
use ethox::wire::{Error, Payload, PayloadMut, payload};
use ethox::byte_wrapper;

use super::{
    CryptConnection,
    PreHandshake,
    PostInitHandshake,
    PostResponseHandshake,
    This,
    UnspecifiedCryptoFailure,
};

/// A read/writer wrapper for a sealed Wireguard packet buffer.
///
/// Try to unseal it by providing your own private key.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T> {
    buffer: T,
    repr: Repr,
}

mod field {
    #![allow(non_snake_case)]
    type Field = core::ops::Range<usize>;

    pub(crate) const TYPE: Field = 0..1;
    pub(crate) const INIT_SENDER: Field = 4..8;
    pub(crate) const INIT_EPHEMERAL: Field = 8..40;
    pub(crate) const INIT_STATIC: Field = 40..88; //40+32+16
    pub(crate) const INIT_TIMESTAMP: Field = 88..116; //88+12+16
    pub(crate) const INIT_MAC1: Field = MAC1(116);
    pub(crate) const INIT_MAC2: Field = MAC2(116);

    pub(crate) const RESP_SENDER: Field = 4..8;
    pub(crate) const RESP_RECEIVER: Field = 8..12;
    pub(crate) const RESP_EPHEMERAL: Field = 12..44;
    pub(crate) const RESP_EMPTY: Field = 44..60; //44+0+16
    pub(crate) const RESP_MAC1: Field = MAC1(60);
    pub(crate) const RESP_MAC2: Field = MAC2(60);

    pub(crate) const DATA_RECEIVER: Field = 4..8;
    pub(crate) const DATA_COUNTER: Field = 8..16;
    pub(crate) const fn DATA_MESSAGE(len: usize) -> Field { 16..len }

    pub(crate) const COOKIE_RECEIVER: Field = 4..8;
    pub(crate) const COOKIE_NONCE: Field = 8..32;
    pub(crate) const COOKIE_COOKIE: Field = 32..64; //32+16+16

    pub(crate) const fn MAC1(datalen: usize) -> Field {
        datalen..datalen+16
    }
    pub(crate) const fn MAC2(datalen: usize) -> Field {
        datalen+16..datalen+32
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Type {
    Init = 0x1,
    Response = 0x2,
    Cookie = 0x3,
    Data = 0x4,
}

/// The repr is for the non-crypto fields of a Wireguard packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr {
    Init {
        sender: u32,
    },
    Response {
        sender: u32,
        receiver: u32,
    },
    Cookie {
        receiver: u32,
    },
    Data {
        receiver: u32,
        datalen: usize,
    },
}

byte_wrapper! {
    #[derive(Debug, PartialEq, Eq)]
    pub struct wireguard([u8]);
}

impl wireguard {
    pub const MSG_INIT: u8 = 1;
    pub const MSG_RESPOND: u8 = 2;
    pub const MSG_COOKIE: u8 = 3;
    pub const MSG_DATA: u8 = 4;

    /// Imbue a raw octet buffer with IPv4 packet structure.
    pub fn new_unchecked(data: &[u8]) -> &Self {
        Self::__from_macro_new_unchecked(data)
    }

    /// Imbue a mutable octet buffer with IPv4 packet structure.
    pub fn new_unchecked_mut(data: &mut [u8]) -> &mut Self {
        Self::__from_macro_new_unchecked_mut(data)
    }

    pub fn new_checked(data: &[u8]) -> Result<&Self, Error> {
        Self::new_unchecked(data).check_len()?;
        Ok(Self::new_unchecked(data))
    }

    pub fn new_checked_mut(data: &mut [u8]) -> Result<&mut Self, Error> {
        Self::new_checked(&data[..])?;
        Ok(Self::new_unchecked_mut(data))
    }

    /// Unwrap the packet as a raw byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Unwrap the packet as a mutable raw byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    /// Returns `Err(Error::Malformed)` if the length field has a value smaller
    /// than the header length.
    ///
    /// The result of this check is invalidated by calling [set_len].
    ///
    /// [set_len]: #method.set_len
    pub fn check_len(&self) -> Result<Type, Error> {
        if self.0.get(0).is_none() {
            return Err(Error::Truncated);
        }

        let assumed_len = match self.wg_type() {
            Some(Type::Init) => field::INIT_MAC2.end,
            Some(Type::Response) => field::RESP_MAC2.end,
            Some(Type::Cookie) => field::COOKIE_COOKIE.end,
            Some(Type::Data) /* data */ => {
                // Any length divisible by 16 (the padding) is okay.
                if self.0.len() % 16 != 0 {
                    return Err(Error::Malformed)
                }

                // But at least an empty package must be there.
                field::DATA_MESSAGE(0).end
            },
            None => return Err(Error::Malformed),
        };

        if self.0.len() < assumed_len {
            Err(Error::Truncated)
        } else {
            Ok(self.wg_type().unwrap())
        }
    }

    /// Get the message type.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn wg_type(&self) -> Option<Type> {
        Some(match self.as_bytes()[0] {
            0x1 => Type::Init,
            0x2 => Type::Response,
            0x3 => Type::Cookie,
            0x4 => Type::Data,
            _ => return None,
        })
    }

    /// Get the init sender field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_sender(&self) -> u32 {
        let bytes: &[u8] = &self.as_bytes()[field::INIT_SENDER];
        let bytes: &[u8; 4] = TryFrom::try_from(bytes).unwrap();
        u32::from_le_bytes(*bytes)
    }

    /// Get the init ephemeral field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_ephemeral(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::INIT_EPHEMERAL]
    }

    /// Get the init static field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_static(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::INIT_STATIC]
    }

    /// Get all bytes before the init mac1 field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_pre_mac1(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[..field::INIT_MAC1.start]
    }

    /// Get the init mac1 field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_mac1(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::INIT_MAC1]
    }

    /// Get all bytes before the init mac2 field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_pre_mac2(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[..field::INIT_MAC2.start]
    }

    /// Get the init mac2 field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_mac2(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::INIT_MAC2]
    }

    /// Get the init timestamp field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_timestamp(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::INIT_TIMESTAMP]
    }

    /// Get the response sender field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn response_sender(&self) -> u32 {
        let bytes: &[u8] = &self.as_bytes()[field::RESP_SENDER];
        let bytes: &[u8; 4] = TryFrom::try_from(bytes).unwrap();
        u32::from_le_bytes(*bytes)
    }

    /// Get the response receiver field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn response_receiver(&self) -> u32 {
        let bytes: &[u8] = &self.as_bytes()[field::RESP_RECEIVER];
        let bytes: &[u8; 4] = TryFrom::try_from(bytes).unwrap();
        u32::from_le_bytes(*bytes)
    }

    /// Get the response ephemeral field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn resp_ephemeral(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::RESP_EPHEMERAL]
    }

    /// Get the response empty field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn resp_empty(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::RESP_EMPTY]
    }

    /// Get the cookie receiver field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn cookie_receiver(&self) -> u32 {
        let bytes: &[u8] = &self.as_bytes()[field::COOKIE_RECEIVER];
        let bytes: &[u8; 4] = TryFrom::try_from(bytes).unwrap();
        u32::from_le_bytes(*bytes)
    }

    /// Get the data receiver field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn data_receiver(&self) -> u32 {
        let bytes: &[u8] = &self.as_bytes()[field::DATA_RECEIVER];
        let bytes: &[u8; 4] = TryFrom::try_from(bytes).unwrap();
        u32::from_le_bytes(*bytes)
    }

    /// Get the data nonce counter field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn data_counter(&self) -> u64 {
        let bytes: &[u8] = &self.as_bytes()[field::DATA_COUNTER];
        let bytes: &[u8; 8] = TryFrom::try_from(bytes).unwrap();
        u64::from_le_bytes(*bytes)
    }

    /// Set the data nonce counter field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn set_data_counter(&mut self, counter: u64) {
        let bytes: &mut [u8] = &mut self.as_bytes_mut()[field::DATA_COUNTER];
        let bytes: &mut [u8; 8] = TryFrom::try_from(bytes).unwrap();
        *bytes = counter.to_le_bytes();
    }

    /// Get the length of the contained data payload.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to to calculate this.
    pub fn data_payload(&self) -> &[u8] {
        let field = field::DATA_MESSAGE(self.as_bytes().len());
        &self.as_bytes()[field]
    }

    /// Get the length of the contained data payload.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to to calculate this.
    pub fn data_payload_mut(&mut self) -> &mut [u8] {
        let field = field::DATA_MESSAGE(self.as_bytes().len());
        &mut self.as_bytes_mut()[field]
    }
}

impl Repr {
    pub fn parse(packet: &wireguard) -> Result<Repr, Error> {
        Ok(match packet.check_len()? {
            Type::Init => Repr::Init {
                sender: packet.init_sender(),
            },
            Type::Response => Repr::Response {
                sender: packet.response_sender(),
                receiver: packet.response_receiver(),
            },
            Type::Cookie => Repr::Cookie {
                receiver: packet.cookie_receiver(),
            },
            Type::Data => Repr::Data {
                receiver: packet.data_receiver(),
                datalen: packet.data_payload().len(),
            },
        })
    }

    pub fn payload_offset() -> usize {
        field::DATA_MESSAGE(0).start
    }

    pub fn len_for_payload(len: usize) -> usize {
        // Round up to  next multiple of 128.
        let padded = len + len.wrapping_neg() & 127;
        field::DATA_MESSAGE(padded).end
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            Repr::Init { .. } => field::INIT_MAC2.end,
            Repr::Response { .. } => field::RESP_MAC2.end,
            Repr::Cookie { .. } => field::COOKIE_COOKIE.end,
            Repr::Data { datalen, .. } => field::DATA_MESSAGE(*datalen).end,
        }
    }
}

impl<T: Payload> Packet<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self, Error> {
        let frame = wireguard::new_checked(buffer.payload())?;
        let repr = Repr::parse(frame)?;
        Ok(Packet {
            buffer,
            repr,
        })
    }

    /// Constructs a frame with assumed representation.
    ///
    /// The validity of the frame is never a safety invariant but wrong data can still lead to
    /// inconsistent handling. In particular, wrong assumptions on the length may panic at runtime
    /// due to bounds checks.
    pub fn new_unchecked(buffer: T, repr: Repr) -> Self {
        Packet {
            buffer,
            repr,
        }
    }

    /// Get an immutable reference to the whole buffer.
    ///
    /// Useful if the buffer is some other packet encapsulation.
    pub fn get_ref(&self) -> &T {
        &self.buffer
    }

    /// Get the repr of the underlying frame.
    pub fn repr(&self) -> Repr {
        self.repr
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: PayloadMut> Packet<T> {
    pub fn consume_init(mut self, this: &mut This, hs: &PreHandshake)
        -> Result<PostInitHandshake, Self>
    {
        let wg = wireguard::new_unchecked_mut(self.buffer.payload_mut());
        match this.read_init(hs, wg) {
            Ok(post) => Ok(post),
            Err(UnspecifiedCryptoFailure) => Err(self),
        }
    }

    pub fn consume_response(mut self, this: &mut This, hs: &PostInitHandshake)
        -> Result<PostResponseHandshake, Self>
    {
        let wg = wireguard::new_unchecked_mut(self.buffer.payload_mut());
        match this.read_response(hs, wg) {
            Ok(post) => Ok(post),
            Err(UnspecifiedCryptoFailure) => Err(self),
        }
    }

    /// Unseal the packet.
    /// Note that you can do this at most once as it _will_ consume the nonce on success!
    pub fn unseal(mut self, this: &mut This, state: &mut CryptConnection)
        -> Result<Unsealed<T>, Self>
    {
        let wg = wireguard::new_unchecked_mut(self.buffer.payload_mut());
        match this.unseal(state, wg) {
            Ok(()) => Ok(Unsealed {
                repr: self.repr,
                buffer: self.buffer,
            }),
            Err(UnspecifiedCryptoFailure) => Err(self),
        }
    }
}

impl<T: Payload> ops::Deref for Packet<T> {
    type Target = wireguard;

    fn deref(&self) -> &wireguard {
        // We checked the length at construction.
        wireguard::new_unchecked(self.buffer.payload())
    }
}

impl<T: Payload> Payload for Unsealed<T> {
    fn payload(&self) -> &payload {
        wireguard::new_unchecked(self.buffer.payload())
            .data_payload()
            .into()
    }
}

#[derive(Debug, PartialEq, Clone)]
struct Sealed<T> {
    buffer: T,
    repr: Repr,
}

/// An unsealed Wireguard message.
///
/// Seal it with the key of the recipient.
#[derive(Debug, PartialEq, Clone)]
pub struct Unsealed<T> {
    buffer: T,
    repr: Repr,
}

impl<T> Unsealed<T> {
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: Payload> ops::Deref for Unsealed<T> {
    type Target = wireguard;

    fn deref(&self) -> &wireguard {
        // We checked the length at construction.
        wireguard::new_unchecked(self.buffer.payload())
    }
}
