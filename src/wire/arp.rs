use byteorder::{ByteOrder, NetworkEndian};
use core::{fmt, ops};

use super::Payload;
use super::{Error, Result};

pub use super::EthernetProtocol as Protocol;
pub use super::EthernetAddress as Address;
pub use super::Ipv4Address as IpAddress;

enum_with_unknown! {
    /// ARP hardware type.
    pub enum Hardware(u16) {
        Ethernet = 1
    }
}

enum_with_unknown! {
    /// ARP operation type.
    pub enum Operation(u16) {
        Request = 1,
        Reply = 2
    }
}

/// A read/write wrapper around an Address Resolution Protocol (ARP) packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T> {
    buffer: T,
    repr: Repr,
}

byte_wrapper!{
    /// A byte sequence representing an ARP packet.
    #[derive(Debug, PartialEq, Eq)]
    pub struct arp([u8]);
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const HTYPE: Field = 0..2;
    pub const PTYPE: Field = 2..4;
    pub const HLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OPER: Field = 6..8;

    #[inline]
    pub fn SHA(hardware_len: u8, _protocol_len: u8) -> Field {
        let start = OPER.end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub fn SPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SHA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    #[inline]
    pub fn THA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SPA(hardware_len, protocol_len).end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub fn TPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = THA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }
}

impl arp {
    /// Imbue a raw octet buffer with ARP packet structure.
    pub fn new_unchecked(buffer: &[u8]) -> &arp {
        Self::__from_macro_new_unchecked(buffer)
    }

    /// Imbue a mutable octet buffer with ARP packet structure.
    pub fn new_unchecked_mut(buffer: &mut [u8]) -> &mut arp {
        Self::__from_macro_new_unchecked_mut(buffer)
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(data: &[u8]) -> Result<&arp> {
        let packet = Self::new_unchecked(data);
        packet.check_len()?;
        Ok(packet)
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
    ///
    /// The result of this check is invalidated by calling [set_hardware_len] or
    /// [set_protocol_len].
    ///
    /// [set_hardware_len]: #method.set_hardware_len
    /// [set_protocol_len]: #method.set_protocol_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.0.len();
        if len < field::OPER.end {
            Err(Error::Truncated)
        } else if len < field::TPA(self.hardware_len(), self.protocol_len()).end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Return the hardware type field.
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        let raw = NetworkEndian::read_u16(&self.0[field::HTYPE]);
        Hardware::from(raw)
    }

    /// Return the protocol type field.
    #[inline]
    pub fn protocol_type(&self) -> Protocol {
        let raw = NetworkEndian::read_u16(&self.0[field::PTYPE]);
        Protocol::from(raw)
    }

    /// Return the hardware length field.
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        self.0[field::HLEN]
    }

    /// Return the protocol length field.
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        self.0[field::PLEN]
    }

    /// Return the operation field.
    #[inline]
    pub fn operation(&self) -> Operation {
        let raw = NetworkEndian::read_u16(&self.0[field::OPER]);
        Operation::from(raw)
    }

    /// Return the source hardware address field.
    pub fn source_hardware_addr(&self) -> Address {
        Address::from_bytes(&self.0[field::SHA(self.hardware_len(), self.protocol_len())])
    }

    /// Return the source protocol address field.
    pub fn source_protocol_addr(&self) -> IpAddress {
        IpAddress::from_bytes(&self.0[field::SPA(self.hardware_len(), self.protocol_len())])
    }

    /// Return the target hardware address field.
    pub fn target_hardware_addr(&self) -> Address {
        Address::from_bytes(&self.0[field::THA(self.hardware_len(), self.protocol_len())])
    }

    /// Return the target protocol address field.
    pub fn target_protocol_addr(&self) -> IpAddress {
        IpAddress::from_bytes(&self.0[field::TPA(self.hardware_len(), self.protocol_len())])
    }

    /// Set the hardware type field.
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        NetworkEndian::write_u16(&mut self.0[field::HTYPE], value.into())
    }

    /// Set the protocol type field.
    #[inline]
    pub fn set_protocol_type(&mut self, value: Protocol) {
        NetworkEndian::write_u16(&mut self.0[field::PTYPE], value.into())
    }

    /// Set the hardware length field.
    #[inline]
    pub fn set_hardware_len(&mut self, value: u8) {
        self.0[field::HLEN] = value
    }

    /// Set the protocol length field.
    #[inline]
    pub fn set_protocol_len(&mut self, value: u8) {
        self.0[field::PLEN] = value
    }

    /// Set the operation field.
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        NetworkEndian::write_u16(&mut self.0[field::OPER], value.into())
    }

    /// Set the source hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_source_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.0[field::SHA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the source protocol address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_source_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.0[field::SPA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the target hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_target_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.0[field::THA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the target protocol address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_target_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.0[field::TPA(hardware_len, protocol_len)].copy_from_slice(value)
    }
}

impl AsRef<[u8]> for arp {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for arp {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<T: Payload> Packet<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let repr = {
            let packet = arp::new_checked(buffer.payload())?;
            Repr::parse(packet)?
        };
        Ok(Packet { buffer, repr })
    }

    /// Get an immutable reference to the whole buffer.
    ///
    /// Useful if the buffer is some other packet encapsulation.
    pub fn get_ref(&self) -> &T {
        &self.buffer
    }

    /// Get the repr of the packet header.
    pub fn repr(&self) -> Repr {
        self.repr
    }

    /// Create a new packet without checking the representation.
    ///
    /// Misuse may lead to panics from out-of-bounds access or other subtle inconsistencies. Since
    /// the representation might not represent the actual content in the payload, this also might
    /// mean that seemingly inconsistent values are returned. The usage is still memory safe
    /// though.
    pub fn new_unchecked(buffer: T, repr: Repr) -> Self {
        Packet { buffer, repr }
    }

    /// Return the raw underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: Payload> ops::Deref for Packet<T> {
    type Target = arp;

    fn deref(&self) -> &arp {
        // We checked the length at construction.
        arp::new_unchecked(self.buffer.payload())
    }
}

impl<T: Payload> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.payload().into()
    }
}

use super::{EthernetAddress, Ipv4Address};

/// A high-level representation of an Address Resolution Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr {
    /// An Ethernet and IPv4 Address Resolution Protocol packet.
    EthernetIpv4 {
        operation: Operation,
        source_hardware_addr: EthernetAddress,
        source_protocol_addr: Ipv4Address,
        target_hardware_addr: EthernetAddress,
        target_protocol_addr: Ipv4Address,
    },
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Repr {
    /// Parse an Address Resolution Protocol packet and return a high-level representation,
    /// or return `Err(Error::Unrecognized)` if the packet is not recognized.
    pub fn parse(packet: &arp) -> Result<Repr> {
        match (
            packet.hardware_type(),
            packet.protocol_type(),
            packet.hardware_len(),
            packet.protocol_len(),
            packet.operation(),
        ) {
            (Hardware::Ethernet, Protocol::Ipv4, 6, 4, Operation::Request) => {
                Ok(Repr::EthernetIpv4 {
                    operation: packet.operation(),
                    source_hardware_addr: packet.source_hardware_addr(),
                    source_protocol_addr: packet.source_protocol_addr(),
                    target_hardware_addr: packet.target_hardware_addr(),
                    target_protocol_addr: packet.target_protocol_addr(),
                })
            },
            _ => Err(Error::Unrecognized),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::EthernetIpv4 { .. } => field::TPA(6, 4).end,
            &Repr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Emit a high-level representation into an Address Resolution Protocol packet.
    pub fn emit(&self, packet: &mut arp) {
        match self {
            &Repr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                packet.set_hardware_type(Hardware::Ethernet);
                packet.set_protocol_type(Protocol::Ipv4);
                packet.set_hardware_len(6);
                packet.set_protocol_len(4);
                packet.set_operation(operation);
                packet.set_source_hardware_addr(source_hardware_addr.as_bytes());
                packet.set_source_protocol_addr(source_protocol_addr.as_bytes());
                packet.set_target_hardware_addr(target_hardware_addr.as_bytes());
                packet.set_target_protocol_addr(target_protocol_addr.as_bytes());
            },
            &Repr::__Nonexhaustive => unreachable!(),
        }
    }
}

impl<T: Payload> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            _ => {
                write!(f, "ARP (unrecognized)")?;
                write!(
                    f,
                    " htype={:?} ptype={:?} hlen={:?} plen={:?} op={:?}",
                    self.hardware_type(),
                    self.protocol_type(),
                    self.hardware_len(),
                    self.protocol_len(),
                    self.operation()
                )?;
                write!(
                    f,
                    " sha={:?} spa={:?} tha={:?} tpa={:?}",
                    self.source_hardware_addr(),
                    self.source_protocol_addr(),
                    self.target_hardware_addr(),
                    self.target_protocol_addr()
                )?;
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Repr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => write!(
                f,
                "ARP type=Ethernet+IPv4 src={}/{} tgt={}/{} op={:?}",
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
                operation,
            ),
            &Repr::__Nonexhaustive => unreachable!(),
        }
    }
}

use super::pretty_print::{PrettyIndent, PrettyPrint};

impl PrettyPrint for arp {
    fn pretty_print(
        buffer: &[u8],
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        match Packet::new_checked(buffer) {
            Err(err) => write!(f, "{}({})", indent, err),
            Ok(packet) => write!(f, "{}{}", indent, packet),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[rustfmt::skip]
    static PACKET_BYTES: [u8; 28] = [
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x01,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x41, 0x42, 0x43, 0x44,
    ];

    #[test]
    fn test_deconstruct() {
        let packet = arp::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.protocol_type(), Protocol::Ipv4);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.protocol_len(), 4);
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(
            packet.source_hardware_addr(),
            EthernetAddress::from_bytes(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(packet.source_protocol_addr(),  Ipv4Address::from_bytes(&[0x21, 0x22, 0x23, 0x24]));
        assert_eq!(
            packet.target_hardware_addr(),
            EthernetAddress::from_bytes(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
        );
        assert_eq!(packet.target_protocol_addr(),  Ipv4Address::from_bytes(&[0x41, 0x42, 0x43, 0x44]));
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 28];
        let packet = arp::new_unchecked_mut(&mut bytes);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_protocol_type(Protocol::Ipv4);
        packet.set_hardware_len(6);
        packet.set_protocol_len(4);
        packet.set_operation(Operation::Request);
        packet.set_source_hardware_addr(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        packet.set_source_protocol_addr(&[0x21, 0x22, 0x23, 0x24]);
        packet.set_target_hardware_addr(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        packet.set_target_protocol_addr(&[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(packet.as_bytes(), &PACKET_BYTES[..]);
    }

    fn packet_repr() -> Repr {
        Repr::EthernetIpv4 {
            operation: Operation::Request,
            source_hardware_addr: EthernetAddress::from_bytes(&[
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            ]),
            source_protocol_addr: Ipv4Address::from_bytes(&[0x21, 0x22, 0x23, 0x24]),
            target_hardware_addr: EthernetAddress::from_bytes(&[
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            ]),
            target_protocol_addr: Ipv4Address::from_bytes(&[0x41, 0x42, 0x43, 0x44]),
        }
    }

    #[test]
    fn test_parse() {
        let packet = arp::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let mut bytes = vec![0xa5; 28];
        let mut packet = arp::new_unchecked_mut(&mut bytes);
        packet_repr().emit(&mut packet);
        assert_eq!(packet.as_bytes(), &PACKET_BYTES[..]);
    }
}
