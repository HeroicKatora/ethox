use ethox::wire::{ip::Address, Error};
use ethox::byte_wrapper;

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
pub enum Repr {
    Init {
        sender: Address,
    },
    Response {
    },
    Cookie {
    },
    Data {
        receiver: Address,
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
    pub fn check_len(&self) -> Result<(), Error> {
        let assumed_len = match self.0.get(0) {
            // FIXME: use associated constant if possible..
            Some(1) /* init */ => field::INIT_MAC2.end,
            Some(2) /* respond */ => field::RESP_MAC2.end,
            Some(3) /* cookie */ => field::COOKIE_COOKIE.end,
            Some(4) /* data */ => {
                // Any length divisible by 16 (the padding) is okay.
                if self.0.len() % 16 != 0 {
                    return Err(Error::Malformed)
                }

                // But at least an empty package must be there.
                field::DATA_MESSAGE(0).end
            },
            None => return Err(Error::Truncated),
            _ => return Err(Error::Malformed),
        };

        if self.0.len() < assumed_len {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
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

    /// Get the init timestamp field.
    ///
    /// # Panics
    /// This will not verify if the message has the right length to contain this field.
    pub fn init_timestamp(&mut self) -> &mut [u8] {
        &mut self.as_bytes_mut()[field::INIT_TIMESTAMP]
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
}

impl Repr {
    pub fn parse(packet: &wireguard) -> Result<Repr, Error> {
        todo!()
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
#[derive(Debug, PartialEq, Clone)]
struct Sealed<T> {
    buffer: T,
    repr: Repr,
}

/// An unsealed Wireguard message.
///
/// Seal it with the key of the recipient.
#[derive(Debug, PartialEq, Clone)]
struct Unsealed<T> {
    buffer: T,
    repr: Repr,
}
