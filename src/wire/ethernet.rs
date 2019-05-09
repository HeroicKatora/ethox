use core::ops;
use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use crate::wire::{self, Error, Result, Payload, PayloadMut, payload};

enum_with_unknown! {
    /// Ethernet protocol type.
    pub enum EtherType(u16) {
        Ipv4 = 0x0800,
        Arp  = 0x0806,
        Ipv6 = 0x86DD,
        JumboFrame = 0x8870,
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Arp  => write!(f, "ARP"),
            EtherType::JumboFrame => write!(f, "JumboFrame"),
            EtherType::Unknown(id) => write!(f, "0x{:04x}", id)
        }
    }
}

/// A six-octet Ethernet II address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 6]);

impl Address {
    /// The broadcast address.
    pub const BROADCAST: Address = Address([0xff; 6]);

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() ||
          self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Query whether the "multicast" bit in the OUI is set.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }
}

/// A read/write wrapper around an Ethernet II frame buffer.
#[derive(Debug, Clone)]
pub struct Frame<T: Payload> {
    buffer: T,
    repr: Repr,
}

/// A byte sequence representing an Ethernet II frame.
byte_wrapper!(ethernet);

mod field {
    use crate::wire::field::*;

    pub const DESTINATION: Field =  0..6;
    pub const SOURCE:      Field =  6..12;
    pub const ETHERTYPE:   Field = 12..14;
    pub const PAYLOAD:     Rest  = 14..;
}

impl ethernet {
    pub fn new_unchecked(data: &[u8]) -> &Self {
        Self::__from_macro_new_unchecked(data)
    }

    pub fn new_unchecked_mut(data: &mut [u8]) -> &mut Self {
        Self::__from_macro_new_unchecked_mut(data)
    }

    pub fn new_checked(data: &[u8]) -> Result<&Self> {
        Self::new_unchecked(data).check_len()?;
        Ok(Self::new_unchecked(data))
    }

    pub fn new_checked_mut(data: &mut [u8]) -> Result<&mut Self> {
        Self::new_checked(&data[..])?;
        Ok(Self::new_unchecked_mut(data))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let len = self.0.len();
        if len < field::PAYLOAD.start {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Return the length of a frame header.
    pub fn header_len() -> usize {
        field::PAYLOAD.start
    }

    /// Return the length of a buffer required to hold a packet with the payload
    /// of a given length.
    pub fn buffer_len(payload_len: usize) -> usize {
        field::PAYLOAD.start + payload_len
    }

    /// Return the destination address field.
    pub fn dst_addr(&self) -> Address {
        Address::from_bytes(&self.0[field::DESTINATION])
    }

    /// Return the source address field.
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.0[field::SOURCE])
    }

    /// Return the EtherType field, without checking for 802.1Q.
    pub fn ethertype(&self) -> EtherType {
        let raw = NetworkEndian::read_u16(&self.0[field::ETHERTYPE]);
        EtherType::from(raw)
    }

    /// Set the destination address field.
    pub fn set_dst_addr(&mut self, value: Address) {
        self.0[field::DESTINATION].copy_from_slice(value.as_bytes())
    }

    /// Set the source address field.
    pub fn set_src_addr(&mut self, value: Address) {
        self.0[field::SOURCE].copy_from_slice(value.as_bytes())
    }

    /// Set the EtherType field.
    pub fn set_ethertype(&mut self, value: EtherType) {
        NetworkEndian::write_u16(&mut self.0[field::ETHERTYPE], value.into())
    }

    /// Return the payload as a byte slice.
    pub fn payload(&self) -> &[u8] {
        &self.0[field::PAYLOAD]
    }

    /// Return the payload as a mutable byte slice.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[field::PAYLOAD]
    }
}

impl AsRef<[u8]> for ethernet {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for ethernet {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl wire::sealed::Sealed for ethernet { }

impl Payload for ethernet {
    fn payload(&self) -> &payload {
        self.payload().into()
    }
}

impl<T: Payload> Frame<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let frame = ethernet::new_checked(buffer.payload())?;
        let repr = Repr::parse(frame)?;
        Ok(Frame {
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
        Frame {
            buffer,
            repr,
        }
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

impl<'a, T: Payload + ?Sized> Frame<&'a T> {
    /// Return a pointer to the payload, without checking for 802.1Q.
    #[inline]
    pub fn payload_bytes(&self) -> &'a [u8] {
        &self.buffer.payload()[field::PAYLOAD]
    }
}

impl<T: Payload> ops::Deref for Frame<T> {
    type Target = ethernet;

    fn deref(&self) -> &ethernet {
        // We checked the length at construction.
        ethernet::new_unchecked(self.buffer.payload())
    }
}

impl<T: Payload> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.payload().into()
    }
}

impl<T: Payload> wire::sealed::Sealed for Frame<T> { }

impl<T: Payload> Payload for Frame<T> {
    fn payload(&self) -> &payload {
        ethernet::payload(self).into()
    }
}

impl<T: Payload> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthernetII src={} dst={} type={}",
               self.src_addr(), self.dst_addr(), self.ethertype())
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl PrettyPrint for ethernet {
    fn pretty_print(buffer: &[u8], f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        let frame = match Frame::new_checked(buffer) {
            Err(err)  => return write!(f, "{}({})", indent, err),
            Ok(frame) => frame
        };
        write!(f, "{}{}", indent, frame)?;

        match frame.ethertype() {
            EtherType::Arp => {
                indent.increase(f)?;
                super::ArpPacket::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            EtherType::Ipv4 => {
                indent.increase(f)?;
                super::Ipv4Packet::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            EtherType::Ipv6 => {
                indent.increase(f)?;
                super::Ipv6Packet::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            _ => Ok(())
        }
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_addr:    Address,
    pub dst_addr:    Address,
    pub ethertype:   EtherType,
}

impl Repr {
    /// Parse an Ethernet II frame and return a high-level representation.
    pub fn parse(frame: &ethernet) -> Result<Repr> {
        frame.check_len()?;
        Ok(Repr {
            src_addr: frame.src_addr(),
            dst_addr: frame.dst_addr(),
            ethertype: frame.ethertype(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::PAYLOAD.start
    }

    /// Emit a high-level representation into an Ethernet II frame.
    pub fn emit(&self, frame: &mut ethernet) {
        frame.set_src_addr(self.src_addr);
        frame.set_dst_addr(self.dst_addr);
        frame.set_ethertype(self.ethertype);
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(Address::BROADCAST.is_local());
    }
}

#[cfg(test)]
mod test_ipv4 {
    // Tests that are valid only with "proto-ipv4"
    use super::*;

    static FRAME_BYTES: [u8; 64] =
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
         0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
         0x08, 0x00,
         0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 50] =
        [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let frame = ethernet::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(frame.dst_addr(), Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.ethertype(), EtherType::Ipv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 64];
        let frame = ethernet::new_unchecked_mut(&mut bytes);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv4);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(frame.as_bytes(), &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
mod test_ipv6 {
    // Tests that are valid only with "proto-ipv6"
    use super::*;

    static FRAME_BYTES: [u8; 54] =
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
         0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
         0x86, 0xdd,
         0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

    static PAYLOAD_BYTES: [u8; 40] =
        [0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

    #[test]
    fn test_deconstruct() {
        let frame = ethernet::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(frame.dst_addr(), Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.ethertype(), EtherType::Ipv6);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 54];
        let frame = ethernet::new_unchecked_mut(&mut bytes);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv6);
        assert_eq!(PAYLOAD_BYTES.len(), frame.payload_mut().len());
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(frame.as_bytes(), &FRAME_BYTES[..]);
    }
}
