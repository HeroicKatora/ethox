use core::ops;
use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, IpProtocol, IpAddress, Result};
use super::{Payload, PayloadError, PayloadMut, payload};
use super::ip::checksum;

/// A read/write wrapper around an User Datagram Protocol packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T> {
    buffer: T,
    repr: Repr,
}

byte_wrapper!(udp);

mod field {
    #![allow(non_snake_case)]
    use crate::wire::field::Field;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH:   Field = 4..6;
    pub const CHECKSUM: Field = 6..8;

    pub fn PAYLOAD(length: u16) -> Field {
        CHECKSUM.end..(length as usize)
    }
}

impl udp {
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
    /// Returns `Err(Error::Malformed)` if the length field has a value smaller
    /// than the header length.
    ///
    /// The result of this check is invalidated by calling [set_len].
    ///
    /// [set_len]: #method.set_len
    pub fn check_len(&self) -> Result<()> {
        let buffer_len = self.0.len();
        if buffer_len < field::CHECKSUM.end {
            Err(Error::Truncated)
        } else {
            let field_len = self.len() as usize;
            if buffer_len < field_len {
                Err(Error::Truncated)
            } else if field_len < field::CHECKSUM.end {
                Err(Error::Malformed)
            } else {
                Ok(())
            }
        }
    }

    /// Return the source port field.
    #[inline]
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::DST_PORT])
    }

    /// Return the length field.
    #[inline]
    pub fn len(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::LENGTH])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::CHECKSUM])
    }

    /// Set the source port field.
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::SRC_PORT], value)
    }

    /// Set the destination port field.
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::DST_PORT], value)
    }

    /// Set the length field.
    #[inline]
    pub fn set_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::LENGTH], value)
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::CHECKSUM], value)
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: IpAddress, dst_addr: IpAddress) {
        self.set_checksum(0);
        let checksum = {
            !checksum::combine(&[
                checksum::pseudo_header(&src_addr, &dst_addr, IpProtocol::Udp,
                                        self.len() as u32),
                checksum::data(&self.0[..self.len() as usize])
            ])
        };
        // UDP checksum value of 0 means no checksum; if the checksum really is zero,
        // use all-ones, which indicates that the remote end must verify the checksum.
        // Arithmetically, RFC 1071 checksums of all-zeroes and all-ones behave identically,
        // so no action is necessary on the remote end.
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum })
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self, src_addr: IpAddress, dst_addr: IpAddress) -> bool {
        if cfg!(fuzzing) { return true }

        checksum::combine(&[
            checksum::pseudo_header(&src_addr, &dst_addr, IpProtocol::Udp,
                                    self.len() as u32),
            checksum::data(&self.0[..self.len() as usize])
        ]) == !0
    }

    pub fn payload_slice(&self) -> &[u8] {
        let len = self.len();
        &self.0[field::PAYLOAD(len)]
    }

    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.0[field::PAYLOAD(len)]
    }
}

impl<T: Payload> Packet<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T, checksum: Checksum) -> Result<Self> {
        let frame = udp::new_checked(buffer.payload())?;
        let repr = Repr::parse(frame, checksum)?;
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

    /// Get the repr of the underlying frame.
    pub fn repr(&self) -> Repr {
        self.repr
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the payload as a mutable byte slice.
    pub fn payload_mut_slice(&mut self) -> &mut [u8] where T: PayloadMut {
        // Keeps header values unchanged.
        udp::new_unchecked_mut(self.buffer.payload_mut())
            .payload_mut_slice()
    }
}

impl AsRef<[u8]> for udp {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for udp {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<'a, T: Payload + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload_slice(&self) -> &'a [u8] {
        udp::new_unchecked(self.buffer.payload())
            .payload_slice()
    }
}

impl<T: Payload + PayloadMut> Packet<T> {
    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        udp::new_unchecked_mut(self.buffer.payload_mut())
            .payload_mut_slice()
    }
}

impl<T: Payload> ops::Deref for Packet<T> {
    type Target = udp;

    fn deref(&self) -> &udp {
        // We checked the length at construction.
        udp::new_unchecked(self.buffer.payload())
    }
}

impl<T: Payload> Payload for Packet<T> {
    fn payload(&self) -> &payload {
        self.payload_slice().into()
    }
}

impl<T: Payload + PayloadMut> PayloadMut for Packet<T> {
    fn payload_mut(&mut self) -> &mut payload {
        udp::new_unchecked_mut(self.buffer.payload_mut())
            .payload_mut_slice()
            .into()
    }

    fn resize(&mut self, length: usize) -> core::result::Result<(), PayloadError> {
        unimplemented!()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an User Datagram Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

pub enum Checksum {
    Manual {
        src_addr: IpAddress,
        dst_addr: IpAddress,
    },
    Ignored,
}

impl Repr {
    /// Parse an User Datagram Protocol packet and return a high-level representation.
    pub fn parse(packet: &udp, checksum: Checksum) -> Result<Repr> {
        packet.check_len()?;

        // Destination port cannot be omitted (but source port can be).
        if packet.dst_port() == 0 { return Err(Error::Malformed) }
        // Valid checksum is expected...
        if let Checksum::Manual { src_addr, dst_addr } = checksum {
            match (src_addr, dst_addr) {
                // ... except on UDP-over-IPv4, where it can be omitted.
                (IpAddress::Ipv4(_), IpAddress::Ipv4(_)) if packet.checksum() == 0 => { }
                _ if !packet.verify_checksum(src_addr, dst_addr) => return Err(Error::WrongChecksum),
                _ => (),
            }
        }

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            length: packet.len(),
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        self.length.into()
    }

    /// Emit a high-level representation into an User Datagram Protocol packet.
    ///
    /// FIXME: This requires the correct packet data for calculating the checksum. However, the
    /// payload slice returned from the packet will only be valid after the length is correctly
    /// filled in.
    pub fn emit(&self, packet: &mut udp, checksum: Checksum) {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_len(self.length);

        if let Checksum::Manual { src_addr, dst_addr, } = checksum {
            packet.fill_checksum(src_addr, dst_addr)
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

impl Checksum {
    pub fn for_pseudo_header<A, B>(src_addr: A, dst_addr: B) -> Self
        where A: Into<IpAddress>, B: Into<IpAddress>
    {
        Checksum::Manual {
            src_addr: src_addr.into(),
            dst_addr: dst_addr.into(),
        }
    }
}

impl<T: Payload> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.repr)
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let payload_len = usize::from(self.length)
            .checked_sub(field::CHECKSUM.end);
        if let Some(payload_len) = payload_len {
            write!(f, "UDP src={} dst={} len={}",
                self.src_port, self.dst_port, payload_len)
        } else {
            write!(f, "UDP src={} dst={} len=??",
                self.src_port, self.dst_port)
        }
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl PrettyPrint for udp {
    fn pretty_print(buffer: &[u8], f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        match Packet::new_checked(buffer, Checksum::Ignored) {
            Err(err)   => write!(f, "{}({})", indent, err),
            Ok(packet) => write!(f, "{}{}", indent, packet)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::wire::Ipv4Address;
    use super::*;

    const SRC_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 1]);
    const DST_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 2]);

    static PACKET_BYTES: [u8; 12] =
        [0xbf, 0x00, 0x00, 0x35,
         0x00, 0x0c, 0x12, 0x4d,
         0xaa, 0x00, 0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = udp::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x124d);
        assert_eq!(packet.payload_slice(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(SRC_ADDR.into(), DST_ADDR.into()));
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 12];
        let packet = udp::new_unchecked_mut(&mut bytes);
        packet.set_src_port(48896);
        packet.set_dst_port(53);
        packet.set_len(12);
        packet.set_checksum(0xffff);
        packet.payload_mut_slice().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(SRC_ADDR.into(), DST_ADDR.into());
        assert_eq!(packet.as_bytes(), &PACKET_BYTES[..]);
    }

    #[test]
    fn test_impossible_len() {
        let mut bytes = vec![0; 12];
        let packet = udp::new_unchecked_mut(&mut bytes);
        packet.set_len(4);
        assert_eq!(packet.check_len(), Err(Error::Malformed));
    }

    #[test]
    fn test_zero_checksum() {
        let mut bytes = vec![0; 8];
        let packet = udp::new_unchecked_mut(&mut bytes);
        packet.set_src_port(1);
        packet.set_dst_port(31881);
        packet.set_len(8);
        packet.fill_checksum(SRC_ADDR.into(), DST_ADDR.into());
        assert_eq!(packet.checksum(), 0xffff);
    }

    fn packet_repr() -> Repr {
        Repr {
            src_port: 48896,
            dst_port: 53,
            length: PACKET_BYTES.len() as u16,
        }
    }

    #[test]
    fn test_parse() {
        let packet = udp::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(
            packet,
            Checksum::for_pseudo_header(SRC_ADDR, DST_ADDR),
        ).unwrap();
        assert_eq!(repr, packet_repr());
        assert_eq!(packet.payload_slice(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let packet = udp::new_unchecked_mut(&mut bytes);
        repr.emit(packet, Checksum::Ignored);
        packet.payload_mut_slice().copy_from_slice(&PAYLOAD_BYTES[..]);
        repr.emit(packet,
            Checksum::for_pseudo_header(SRC_ADDR, DST_ADDR));
        assert_eq!(packet.as_bytes(), &PACKET_BYTES[..]);
        assert_eq!(packet.payload_slice(), &PAYLOAD_BYTES[..]);
    }
}
