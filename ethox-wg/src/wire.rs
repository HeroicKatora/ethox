use ethox::wire::ip::Address;

/// A read/write wrapper around a Wireguard packet buffer.
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
    FirstMessage {
        sender: Address,
    },
    Transport {
        receiver: Address,
        counter: u64,
    }
}

struct wireguard([u8]);

/// A sealed Wireguard message.
///
/// Try to unseal it by providing a private key.
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
