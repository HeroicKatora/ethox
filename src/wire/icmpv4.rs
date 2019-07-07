use core::{fmt, ops};
use byteorder::{ByteOrder, NetworkEndian};

use super::{Payload, PayloadMut};
use super::{Error, Checksum, Result};
use super::ip::checksum;
use super::{Ipv4Packet, Ipv4Repr, ipv4_packet};

enum_with_unknown! {
    /// Internet protocol control message type.
    pub doc enum Message(u8) {
        /// Echo reply
        EchoReply      =  0,
        /// Destination unreachable
        DstUnreachable =  3,
        /// Message redirect
        Redirect       =  5,
        /// Echo request
        EchoRequest    =  8,
        /// Router advertisement
        RouterAdvert   =  9,
        /// Router solicitation
        RouterSolicit  = 10,
        /// Time exceeded
        TimeExceeded   = 11,
        /// Parameter problem
        ParamProblem   = 12,
        /// Timestamp
        Timestamp      = 13,
        /// Timestamp reply
        TimestampReply = 14,
        /// Extended Echo Request
        ExtendedEcho   = 42,
        /// Extended Echo Reply
        ExtendedReply  = 43,
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Message::EchoReply      => write!(f, "echo reply"),
            Message::DstUnreachable => write!(f, "destination unreachable"),
            Message::Redirect       => write!(f, "message redirect"),
            Message::EchoRequest    => write!(f, "echo request"),
            Message::RouterAdvert   => write!(f, "router advertisement"),
            Message::RouterSolicit  => write!(f, "router solicitation"),
            Message::TimeExceeded   => write!(f, "time exceeded"),
            Message::ParamProblem   => write!(f, "parameter problem"),
            Message::Timestamp      => write!(f, "timestamp"),
            Message::TimestampReply => write!(f, "timestamp reply"),
            Message::ExtendedEcho   => write!(f, "extended echo request"),
            Message::ExtendedReply  => write!(f, "extended echo reply"),
            Message::Unknown(id)    => write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub doc enum DstUnreachable(u8) {
        /// Destination network unreachable
        NetUnreachable   =  0,
        /// Destination host unreachable
        HostUnreachable  =  1,
        /// Destination protocol unreachable
        ProtoUnreachable =  2,
        /// Destination port unreachable
        PortUnreachable  =  3,
        /// Fragmentation required, and DF flag set
        FragRequired     =  4,
        /// Source route failed
        SrcRouteFailed   =  5,
        /// Destination network unknown
        DstNetUnknown    =  6,
        /// Destination host unknown
        DstHostUnknown   =  7,
        /// Source host isolated
        SrcHostIsolated  =  8,
        /// Network administratively prohibited
        NetProhibited    =  9,
        /// Host administratively prohibited
        HostProhibited   = 10,
        /// Network unreachable for ToS
        NetUnreachToS    = 11,
        /// Host unreachable for ToS
        HostUnreachToS   = 12,
        /// Communication administratively prohibited
        CommProhibited   = 13,
        /// Host precedence violation
        HostPrecedViol   = 14,
        /// Precedence cutoff in effect
        PrecedCutoff     = 15
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DstUnreachable::NetUnreachable =>
                write!(f, "destination network unreachable"),
            DstUnreachable::HostUnreachable =>
                write!(f, "destination host unreachable"),
            DstUnreachable::ProtoUnreachable =>
                write!(f, "destination protocol unreachable"),
            DstUnreachable::PortUnreachable =>
                write!(f, "destination port unreachable"),
            DstUnreachable::FragRequired =>
                write!(f, "fragmentation required, and DF flag set"),
            DstUnreachable::SrcRouteFailed =>
                write!(f, "source route failed"),
            DstUnreachable::DstNetUnknown =>
                write!(f, "destination network unknown"),
            DstUnreachable::DstHostUnknown =>
                write!(f, "destination host unknown"),
            DstUnreachable::SrcHostIsolated =>
                write!(f, "source host isolated"),
            DstUnreachable::NetProhibited =>
                write!(f, "network administratively prohibited"),
            DstUnreachable::HostProhibited =>
                write!(f, "host administratively prohibited"),
            DstUnreachable::NetUnreachToS =>
                write!(f, "network unreachable for ToS"),
            DstUnreachable::HostUnreachToS =>
                write!(f, "host unreachable for ToS"),
            DstUnreachable::CommProhibited =>
                write!(f, "communication administratively prohibited"),
            DstUnreachable::HostPrecedViol =>
                write!(f, "host precedence violation"),
            DstUnreachable::PrecedCutoff =>
                write!(f, "precedence cutoff in effect"),
            DstUnreachable::Unknown(id) =>
                write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Redirect Message".
    pub doc enum Redirect(u8) {
        /// Redirect Datagram for the Network
        Net     = 0,
        /// Redirect Datagram for the Host
        Host    = 1,
        /// Redirect Datagram for the ToS & network
        NetToS  = 2,
        /// Redirect Datagram for the ToS & host
        HostToS = 3
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Time Exceeded".
    pub doc enum TimeExceeded(u8) {
        /// TTL expired in transit
        TtlExpired  = 0,
        /// Fragment reassembly time exceeded
        FragExpired = 1
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Parameter Problem".
    pub doc enum ParamProblem(u8) {
        /// Pointer indicates the error
        AtPointer     = 0,
        /// Missing a required option
        MissingOption = 1,
        /// Bad length
        BadLength     = 2
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T> {
    buffer: T,
    repr: Repr,
}

byte_wrapper! {
    #[derive(Debug, PartialEq, Eq)]
    pub struct icmpv4([u8]);
}

mod field {
    use crate::wire::field::Field;

    pub const TYPE:       usize = 0;
    pub const CODE:       usize = 1;
    pub const CHECKSUM:   Field = 2..4;

    pub const UNUSED:     Field = 4..8;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
}

impl icmpv4 {
    /// Imbue a raw octet buffer with IPv4 packet structure.
    pub fn new_unchecked(buffer: &[u8]) -> &icmpv4 {
        Self::__from_macro_new_unchecked(buffer)
    }

    /// Imbue a mutable octet buffer with IPv4 packet structure.
    pub fn new_unchecked_mut(buffer: &mut [u8]) -> &mut icmpv4 {
        Self::__from_macro_new_unchecked_mut(buffer)
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(data: &[u8]) -> Result<&icmpv4> {
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
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        if self.0.len() < field::HEADER_END {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        Message::from(self.0[field::TYPE])
    }

    /// Return the message code field.
    #[inline]
    pub fn msg_code(&self) -> u8 {
        self.0[field::CODE]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::ECHO_SEQNO])
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::EchoRequest    => field::ECHO_SEQNO.end,
            Message::EchoReply      => field::ECHO_SEQNO.end,
            Message::DstUnreachable => field::UNUSED.end,
            _ => field::UNUSED.end // make a conservative assumption
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) { return true }

        checksum::data(self.as_bytes()) == !0
    }

    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        self.0[field::TYPE] = value.into();
    }

    /// Set the message code field.
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        self.0[field::CODE] = value;
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::CHECKSUM], value);
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::ECHO_IDENT], value);
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::ECHO_SEQNO], value);
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(&self.0);
        self.set_checksum(checksum);
    }

    /// Return the payload as a byte slice.
    pub fn payload_slice(&self) -> &[u8] {
        &self.0[field::HEADER_END..]
    }

    /// Return the payload as a mutable byte slice.
    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[field::HEADER_END..]
    }
}

impl AsRef<[u8]> for icmpv4 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for icmpv4 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<T: Payload> Packet<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T, checksum: Checksum) -> Result<Packet<T>> {
        let repr = {
            let packet = icmpv4::new_checked(buffer.payload())?;
            Repr::parse(packet, checksum)?
        };
        Ok(Packet {
            buffer,
            repr,
        })
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
        Packet {
            buffer,
            repr,
        }
    }
}

impl<T: PayloadMut> Packet<T> {
    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        icmpv4::new_unchecked_mut(self.buffer.payload_mut())
            .payload_mut_slice()
    }

    /// Recalculate the checksum if necessary.
    ///
    /// Note that the checksum test can be elided even in a checked parse of the ipv4 frame. This
    /// provides in opportunity to recalculate it if necessary even though the header structure is
    /// not otherwise mutably accessible while in `Packet` representation.
    pub fn fill_checksum(&mut self, checksum: Checksum) {
        if checksum.manual() {
            icmpv4::new_unchecked_mut(self.buffer.payload_mut())
                .fill_checksum()
        }
    }
}

impl<T> Packet<T> {
    /// Return the raw underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: Payload> ops::Deref for Packet<T> {
    type Target = icmpv4;

    fn deref(&self) -> &icmpv4 {
        // We checked the length at construction.
        icmpv4::new_unchecked(self.buffer.payload())
    }
}

/// A high-level representation of an Internet Control Message Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr {
    EchoRequest {
        ident:  u16,
        seq_no: u16,
        payload: usize,
    },
    EchoReply {
        ident:  u16,
        seq_no: u16,
        payload: usize,
    },
    DstUnreachable {
        reason: DstUnreachable,
        header: Ipv4Repr,
    },
    #[doc(hidden)]
    __Nonexhaustive
}

impl Repr {
    /// Get the echo reply request if this is an echo request.
    pub fn echo_reply(self) -> Option<Repr> {
        match self {
            Repr::EchoRequest { ident, seq_no, payload, } =>
                Some(Repr::EchoReply { ident, seq_no, payload, }),
            _ => None,
        }
    }

    /// Parse an Internet Control Message Protocol version 4 packet and return
    /// a high-level representation.
    pub fn parse(packet: &icmpv4, checksum: Checksum)
        -> Result<Repr>
    {
        // Valid checksum is expected.
        if checksum.manual() && !packet.verify_checksum() { return Err(Error::WrongChecksum) }

        match (packet.msg_type(), packet.msg_code()) {
            (Message::EchoRequest, 0) => {
                Ok(Repr::EchoRequest {
                    ident:  packet.echo_ident(),
                    seq_no: packet.echo_seq_no(),
                    payload: packet.payload_slice().len(),
                })
            },

            (Message::EchoReply, 0) => {
                Ok(Repr::EchoReply {
                    ident:  packet.echo_ident(),
                    seq_no: packet.echo_seq_no(),
                    payload: packet.payload_slice().len(),
                })
            },

            (Message::DstUnreachable, code) => {
                let ip_packet = Ipv4Packet::new_checked(packet.payload_slice(), checksum)?;

                let payload = ip_packet.payload_slice();
                // RFC 792 requires exactly eight bytes to be returned.
                // We allow more, since there isn't a reason not to, but require at least eight.
                if payload.len() < 8 { return Err(Error::Truncated) }

                Ok(Repr::DstUnreachable {
                    reason: DstUnreachable::from(code),
                    header: Ipv4Repr {
                        src_addr: ip_packet.src_addr(),
                        dst_addr: ip_packet.dst_addr(),
                        protocol: ip_packet.protocol(),
                        payload_len: payload.len(),
                        hop_limit: ip_packet.hop_limit(),
                    },
                })
            }

            // Unknown types are not as specified in the standard and iana registry.
            (Message::Unknown(_), _) => Err(Error::Unrecognized),
            // Others are just not supported (yet). // TODO: more reprs.
            _ => Err(Error::Unsupported),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            Repr::EchoRequest { payload, .. } |
            Repr::EchoReply { payload, .. } => {
                field::HEADER_END + payload
            },
            Repr::DstUnreachable { header, .. } => {
                // Be strict in what to emit. Exactly eight beytes as required.
                field::HEADER_END + header.buffer_len() + 8
            }
            Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 4
    /// packet.
    pub fn emit(&self, packet: &mut icmpv4, checksum: Checksum) {
        packet.set_msg_code(0);
        match self {
            &Repr::EchoRequest { ident, seq_no, payload: _ } => {
                packet.set_msg_type(Message::EchoRequest);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
            },

            &Repr::EchoReply { ident, seq_no, payload: _ } => {
                packet.set_msg_type(Message::EchoReply);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
            },

            &Repr::DstUnreachable { reason, header, } => {
                packet.set_msg_type(Message::DstUnreachable);
                packet.set_msg_code(reason.into());

                let ip_packet = ipv4_packet::new_unchecked_mut(packet.payload_mut_slice());
                header.emit(ip_packet, checksum);
            },

            &Repr::__Nonexhaustive => unreachable!()
        }

        if checksum.manual() {
            packet.fill_checksum()
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

impl<T: Payload> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(&self, Checksum::Manual) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "ICMPv4 ({})", err)?;
                write!(f, " type={:?}", self.msg_type())?;
                match self.msg_type() {
                    Message::DstUnreachable =>
                        write!(f, " code={:?}", DstUnreachable::from(self.msg_code())),
                    _ => write!(f, " code={}", self.msg_code())
                }
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Repr::EchoRequest { ident, seq_no, payload } =>
                write!(f, "ICMPv4 echo request id={} seq={} len={}",
                       ident, seq_no, payload),
            &Repr::EchoReply { ident, seq_no, payload } =>
                write!(f, "ICMPv4 echo reply id={} seq={} len={}",
                       ident, seq_no, payload),
            &Repr::DstUnreachable { reason, .. } =>
                write!(f, "ICMPv4 destination unreachable ({})",
                       reason),
            &Repr::__Nonexhaustive => unreachable!()
        }
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl PrettyPrint for icmpv4 {
    fn pretty_print(buffer: &[u8], f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        let packet = match icmpv4::new_checked(buffer) {
            Err(err)   => return write!(f, "{}({})", indent, err),
            Ok(packet) => packet
        };

        // Verify the packet content
        let repr = match Repr::parse(packet, Checksum::Ignored) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(ip_repr) => ip_repr,
        };

        write!(f, "{}{}", indent, repr)?;
        match packet.msg_type() {
            Message::DstUnreachable => {
                indent.increase(f)?;
                ipv4_packet::pretty_print(packet.payload_slice(), f, indent)
            }
            _ => Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static ECHO_PACKET_BYTES: [u8; 12] =
        [0x08, 0x00, 0x8e, 0xfe,
         0x12, 0x34, 0xab, 0xcd,
         0xaa, 0x00, 0x00, 0xff];

    static ECHO_DATA_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_echo_deconstruct() {
        let packet = icmpv4::new_unchecked(&ECHO_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x8efe);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.payload_slice(), &ECHO_DATA_BYTES[..]);
        assert_eq!(packet.verify_checksum(), true);
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = vec![0xa5; 12];
        let packet = icmpv4::new_unchecked_mut(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.payload_mut_slice().copy_from_slice(&ECHO_DATA_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(packet.as_bytes(), &ECHO_PACKET_BYTES[..]);
    }

    fn echo_packet_repr() -> Repr {
        Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            payload: ECHO_DATA_BYTES.len(),
        }
    }

    #[test]
    fn test_echo_parse() {
        let packet = icmpv4::new_unchecked(&ECHO_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, Checksum::Manual).unwrap();
        assert_eq!(repr, echo_packet_repr());
    }

    #[test]
    fn test_echo_emit() {
        let repr = echo_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = icmpv4::new_unchecked_mut(&mut bytes);
        repr.emit(&mut packet, Checksum::Manual);
        packet.payload_mut_slice().copy_from_slice(&ECHO_DATA_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(packet.as_bytes(), &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_check_len() {
        let bytes = [0x08, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00];
        assert_eq!(Packet::new_checked(&bytes[..0], Checksum::Ignored), Err(Error::Truncated));
        assert_eq!(Packet::new_checked(&bytes[..4], Checksum::Ignored), Err(Error::Truncated));
        Packet::new_checked(&bytes[..], Checksum::Ignored).unwrap();
    }
}
