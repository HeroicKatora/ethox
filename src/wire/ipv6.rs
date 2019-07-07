use core::{fmt, ops};
use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result, Payload, PayloadError, PayloadMut, Reframe, payload};
use super::{Ipv4Address, EthernetAddress};
use super::ip::pretty_print_ip_payload;
pub use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv6. See [RFC 8200 § 5].
///
/// [RFC 8200 § 5]: https://tools.ietf.org/html/rfc8200#section-5
pub const MIN_MTU: usize = 1280;

/// A sixteen-octet IPv6 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 16]);

/// A 64-bit interface ID.
///
/// This is an instance of an `EUI-64` address. A universally administered IEEE 802 address or an
/// EUI-64 is signified by a 0 in the U/L bit position (the next-to-lower-order bit of the most
/// significant byte), while a globally unique IPv6 Interface Identifier is signified by a 1 in the
/// corresponding position.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct InterfaceId(pub [u8; 8]);

enum_with_unknown! {
    /// IPv6 multicast scope.
    pub enum Scope(u8) {
        InterfaceLocal = 1,
        LinkLocal = 2,
        AdminLocal = 4,
        SiteLocal = 5,
        OrganizationLocal = 8,
        Global = 0xE,
        ReservedToGlobal = 0xF,
    }
}

impl Address {
    /// The [unspecified address].
    ///
    /// [unspecified address]: https://tools.ietf.org/html/rfc4291#section-2.5.2
    pub const UNSPECIFIED: Address = Address([0x00; 16]);

    /// The link-local [all routers multicast address].
    ///
    /// [all routers multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const LINK_LOCAL_ALL_NODES: Address =
        Address([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    /// The link-local [all nodes multicast address].
    ///
    /// [all nodes multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const LINK_LOCAL_ALL_ROUTERS: Address =
        Address([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);

    /// The [loopback address].
    ///
    /// [loopback address]: https://tools.ietf.org/html/rfc4291#section-2.5.3
    pub const LOOPBACK: Address =
        Address([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    /// Construct an IPv6 address from parts.
    pub fn new(
        a0: u16, a1: u16, a2: u16, a3: u16,
        a4: u16, a5: u16, a6: u16, a7: u16,
    ) -> Address {
        let mut addr = [0u8; 16];
        NetworkEndian::write_u16(&mut addr[0..2], a0);
        NetworkEndian::write_u16(&mut addr[2..4], a1);
        NetworkEndian::write_u16(&mut addr[4..6], a2);
        NetworkEndian::write_u16(&mut addr[6..8], a3);
        NetworkEndian::write_u16(&mut addr[8..10], a4);
        NetworkEndian::write_u16(&mut addr[10..12], a5);
        NetworkEndian::write_u16(&mut addr[12..14], a6);
        NetworkEndian::write_u16(&mut addr[14..16], a7);
        Address(addr)
    }

    /// Construct an IPv6 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not sixteen octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Construct an IPv6 address from a sequence of words, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not 8 words long.
    pub fn from_parts(data: &[u16]) -> Address {
        assert!(data.len() >= 8);
        let mut bytes = [0; 16];
        for word_idx in 0..8 {
            let byte_idx = word_idx * 2;
            NetworkEndian::write_u16(&mut bytes[byte_idx..(byte_idx + 2)], data[word_idx]);
        }
        Address(bytes)
    }

    /// Construct an IPv6 address as a mapped ipv4 address.
    ///
    /// There are some security considerations to take into account. Note that the resulting IPv6
    /// address is always classified as a unicast address even though the source address may not
    /// be! This can create confusion when the IPv4 broadcast address `255.255.255.255` is mapped
    /// or when the scope of an otherwise node-local address such as `127.0.0.1` is involuntarily
    /// expanded.
    pub const fn from_mapped_ipv4(addr: Ipv4Address) -> Address {
        let Ipv4Address([a, b, c, d]) = addr;
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d])
    }

    /// Create the address from a permanent ethernet address.
    ///
    /// The address is only valid for link-local scope. See [`from_advertised_id`] for potentially
    /// globally unique unicast addresses from router advertisements.
    pub const fn from_link_local_id(id: InterfaceId) -> Address {
        let InterfaceId([a, b, c, d, e, f, g, h]) = id;
        Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, a, b, c, d, e, f, g, h])
    }

    /// Return the reserved multicast address for a given scope.
    ///
    /// These addresses must never be assigned to a group or interface.
    // FIXME: const as soon as `match` is const (required for `into`)
    pub fn reserved_multicast(scope: Scope) -> Self {
        Address([0xff, scope.into(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Return the multicast address for a given scope identifying all nodes.
    // FIXME: const as soon as `match` is const (required for `into`)
    pub fn all_nodes_multicast(scope: Scope) -> Self {
        Address([0xff, scope.into(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    /// Create an address by merging the routing prefix, subnet and interface id.
    ///
    /// Returns `None` if the prefix length of the subnet prefix does not have a length of 64 bits.
    pub fn from_global_unicast_id(net: Subnet, id: InterfaceId) -> Option<Address> {
        if net.prefix != 64 {
            return None;
        }

        let mut addr = net.address;
        addr.0[8..16].copy_from_slice(&id.0[..]);
        Some(addr)
    }

    /// Write a IPv6 address to the given slice.
    ///
    /// # Panics
    /// The function panics if `data` is not 8 words long.
    pub fn write_parts(&self, data: &mut [u16]) {
        assert!(data.len() >= 8);
        for i in 0..8 {
            let byte_idx = i * 2;
            data[i] = NetworkEndian::read_u16(&self.0[byte_idx..(byte_idx + 2)]);
        }
    }

    /// Return an IPv6 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the IPv6 address is an [unicast address].
    ///
    /// [unicast address]: https://tools.ietf.org/html/rfc4291#section-2.5
    pub fn is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }

    /// Query whether the IPv6 address is a [multicast address].
    ///
    /// [multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// Query whether the IPv6 address is the [unspecified address].
    ///
    /// [unspecified address]: https://tools.ietf.org/html/rfc4291#section-2.5.2
    pub fn is_unspecified(&self) -> bool {
        self.0 == [0x00; 16]
    }

    /// Query whether the IPv6 address is in the [link-local] scope.
    ///
    /// [link-local]: https://tools.ietf.org/html/rfc4291#section-2.5.6
    pub fn is_link_local(&self) -> bool {
        self.0[0..8] == [0xfe, 0x80, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00]
    }

    /// Query whether the IPv6 address is the [loopback address].
    ///
    /// [loopback address]: https://tools.ietf.org/html/rfc4291#section-2.5.3
    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    /// Query whether the IPv6 address is an [IPv4 mapped IPv6 address].
    ///
    /// [IPv4 mapped IPv6 address]: https://tools.ietf.org/html/rfc4291#section-2.5.5.2
    pub fn is_ipv4_mapped(&self) -> bool {
        self.0[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
    }

    /// Convert an IPv4 mapped IPv6 address to an IPv4 address.
    pub fn as_ipv4(&self) -> Option<Ipv4Address> {
        if self.is_ipv4_mapped() {
            Some(Ipv4Address([self.0[12], self.0[13], self.0[14], self.0[15]]))
        } else {
            None
        }
    }

    /// Mask the address to some prefix length.
    ///
    /// # Panics
    /// This function panics if `prefix` is greater than 128.
    pub fn mask(&self, prefix: u8) -> Address {
        assert!(prefix <= 128);
        let mut bytes = self.0;
        for (i, part) in bytes.iter_mut().enumerate() {
            // Remaining bits in this part.
            let bits = prefix
                .saturating_sub((i*8) as u8)
                .min(8);
            *part &= !0xffu8
                .checked_shr(bits.into())
                .unwrap_or(0);
        }
        Address(bytes)
    }

    /// The solicited node for the given unicast address.
    ///
    /// # Panics
    /// This function panics if the given address is not
    /// unicast.
    pub fn solicited_node_multicast(&self) -> Address {
        assert!(self.is_unicast());
        let mut bytes = [0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        bytes[14..].copy_from_slice(&self.0[14..]);
        Address(bytes)
    }

    /// Determine if traffic to the dst address should be accepted.
    ///
    /// Provided that some node has been assigned the IPv6 address given by self, check all
    /// required addresses to which we must react to determine if the packet should be considered
    /// as destined to the local host.
    pub fn accepts(self, addr: Address) -> bool {
        self == addr
            || Address::all_nodes_multicast(Scope::InterfaceLocal) == addr
            || Address::all_nodes_multicast(Scope::LinkLocal) == addr
            || Address::all_nodes_multicast(Scope::Global) == addr
            || (self.is_unicast() && self.solicited_node_multicast() == addr)
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv6Addr> for Address {
    fn from(x: ::std::net::Ipv6Addr) -> Address {
        Address(x.octets())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv6Addr {
    fn from(Address(x): Address) -> ::std::net::Ipv6Addr {
        x.into()
    }
}

impl InterfaceId {
    /// Form an interface id from a unique address.
    ///
    /// This method should only be used when the address is formed from a vendor/hardware provided
    /// address whose guarantee of global uniqueness was specified at the time of its assignment.
    pub const fn from_vendor_ether(addr: EthernetAddress) -> Self {
        let EthernetAddress([a, b, c, d, e, f]) = addr;
        InterfaceId([a ^ 0x2, b, c, 0xff, 0xfe, d, e, f])
    }

    /// Form an interface id from a generated address.
    ///
    /// This method should only be used when the address was generated in such a way that its
    /// global uniqueness can not be guaranteed. This is the case when it was generated randomly.
    pub const fn from_generated_ether(addr: EthernetAddress) -> Self {
        let EthernetAddress([a, b, c, d, e, f]) = addr;
        Self::from_generated_bytes([a, b, c, 0xff, 0xfe, d, e, f])
    }

    /// Form an interface id from generated bytes.
    ///
    /// This method should only be used when the address was generated in such a way that its
    /// global uniqueness can not be guaranteed. This is the case when it was generated randomly.
    pub const fn from_generated_bytes(mut bytes: [u8; 8]) -> Self {
        bytes[0] &= !0x2;
        InterfaceId(bytes)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_ipv4_mapped() {
            return write!(f, "::ffff:{}.{}.{}.{}", self.0[12], self.0[13], self.0[14], self.0[15])
        }

        // The string representation of an IPv6 address should
        // collapse a series of 16 bit sections that evaluate
        // to 0 to "::"
        //
        // See https://tools.ietf.org/html/rfc4291#section-2.2
        // for details.
        enum State {
            Head,
            HeadBody,
            Tail,
            TailBody
        }
        let mut words = [0u16; 8];
        self.write_parts(&mut words);
        let mut state = State::Head;
        for word in words.iter() {
            state = match (*word, &state) {
                // Once a u16 equal to zero write a double colon and
                // skip to the next non-zero u16.
                (0, &State::Head) | (0, &State::HeadBody) => {
                    write!(f, "::")?;
                    State::Tail
                },
                // Continue iterating without writing any characters until
                // we hit anothing non-zero value.
                (0, &State::Tail) => State::Tail,
                // When the state is Head or Tail write a u16 in hexadecimal
                // without the leading colon if the value is not 0.
                (_, &State::Head) => {
                    write!(f, "{:x}", word)?;
                    State::HeadBody
                },
                (_, &State::Tail) => {
                    write!(f, "{:x}", word)?;
                    State::TailBody
                },
                // Write the u16 with a leading colon when parsing a value
                // that isn't the first in a section
                (_, &State::HeadBody) | (_, &State::TailBody) => {
                    write!(f, ":{:x}", word)?;
                    state
                }
            }
        }
        Ok(())
    }
}

/// An IPv6 CIDR host: an address and a variable-length subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Cidr {
    address:    Address,
    prefix_len: u8,
}

/// An IPv6 CIDR block.
///
/// Relevant RFCs:
/// * [RFC 1519: Classless Inter-Domain Routing (CIDR)][RFC1519]
///
/// [RFC1519]: https://tools.ietf.org/html/rfc1519
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Subnet {
    address: Address,
    prefix: u8,
}

impl Cidr {
    /// The [solicited node prefix].
    ///
    /// [solicited node prefix]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const SOLICITED_NODE_PREFIX: Cidr =
        Cidr {
            address: Address([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00]),
            prefix_len: 104
        };

    /// Create an IPv6 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 128.
    pub fn new(address: Address, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 128);
        Cidr { address, prefix_len }
    }

    /// Return the address of this IPv6 CIDR block.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv6 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The subnet containing this address.
    pub fn subnet(self) -> Subnet {
        Subnet::from_cidr(self)
    }

    /// Query whether the subnetwork described by this IPv6 CIDR block contains
    /// the given address.
    #[deprecated = "Use contains on `subnet` instead."]
    pub fn contains_address(&self, addr: Address) -> bool {
        self.subnet().contains(addr)
    }

    /// Query whether the host is in a subnetwork contained in the subnetwork of `self`.
    ///
    /// This is used for finding out whether a given address is network or link-local or needs to
    /// be routed.
    #[deprecated = "Use `subnet` on both arguments instead."]
    pub fn contains_subnet(&self, subnet: Cidr) -> bool {
        self.subnet().contains_subnet(subnet.subnet())
    }

    /// Whether to accept a packet directed at some address.
    /// 
    /// See section 2.8 of [RFC4291].
    ///
    /// [4291]: https://tools.ietf.org/html/rfc4291#section-2.8
    pub fn accepts(&self, address: Address) -> bool {
        self.address.accepts(address)
    }
}

impl Subnet {
    /// The subnet that contains all addresses.
    pub const ANY: Self = Subnet { address: Address::UNSPECIFIED, prefix: 0 };

    /// Get the subnet block of a CIDR address.
    pub fn from_cidr(cidr: Cidr) -> Self {
        let address = cidr.address().mask(cidr.prefix_len());

        Subnet {
            address,
            prefix: cidr.prefix_len(),
        }
    }

    /// Return the network mask of this IPv4 CIDR block.
    pub fn netmask(&self) -> Address {
        Address([0xFF; 16]).mask(self.prefix)
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    /// Get the router anycast address of this subnet block.
    ///
    /// This can only return a valid anycast address if the subnet is one of the valid unicast
    /// blocks as anycast and unicast share the same addressing subspace.
    pub fn router_anycast(self) -> Option<Address> {
        // Already has all lower bits zeroed as required.
        Some(self.address)
            .filter(Address::is_unicast)
    }

    /// Query whether a host is contained in the block describe by `self`.
    ///
    /// It completely ignores the host identifiers. Consequently this will also successfully work
    /// for blocks that do not have an address identifying the network itself, that is for prefix
    /// lengths 31 and 32.
    ///
    /// This can be used for finding out whether a given address is network or link-local or needs
    /// to be routed.
    pub fn contains(&self, address: Address) -> bool {
        // Own address is already masked.
        self.address == address.mask(self.prefix)
    }

    /// Check if the other network is a subnet.
    pub fn contains_subnet(&self, other: Subnet) -> bool {
        self.prefix <= other.prefix && self.contains(other.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // https://tools.ietf.org/html/rfc4291#section-2.3
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// A read/write wrapper around an Internet Protocol version 6 packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: Payload> {
    buffer: T,
    repr: Repr,
}

byte_wrapper!(ipv6);

// Ranges and constants describing the IPv6 header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc2460#section-3 for details.
mod field {
    use crate::wire::field::Field;
    // 4-bit version number, 8-bit traffic class, and the
    // 20-bit flow label.
    pub const VER_TC_FLOW: Field = 0..4;
    // 16-bit value representing the length of the payload.
    // Note: Options are included in this length.
    pub const LENGTH:      Field = 4..6;
    // 8-bit value identifying the type of header following this
    // one. Note: The same numbers are used in IPv4.
    pub const NXT_HDR:     usize = 6;
    // 8-bit value decremented by each node that forwards this
    // packet. The packet is discarded when the value is 0.
    pub const HOP_LIMIT:   usize = 7;
    // IPv6 address of the source node.
    pub const SRC_ADDR:    Field = 8..24;
    // IPv6 address of the destination node.
    pub const DST_ADDR:    Field = 24..40;
}

impl ipv6 {
    /// Create a raw octet buffer with an IPv6 packet structure.
    #[inline]
    pub fn new_unchecked(buffer: &[u8]) -> &Self {
        Self::__from_macro_new_unchecked(buffer)
    }

    /// Create a raw octet buffer with an IPv6 packet structure.
    #[inline]
    pub fn new_unchecked_mut(buffer: &mut [u8]) -> &mut Self {
        Self::__from_macro_new_unchecked_mut(buffer)
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub fn new_checked(buffer: &[u8]) -> Result<&Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_payload_len].
    ///
    /// [set_payload_len]: #method.set_payload_len
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        let len = self.0.len();
        if len < field::DST_ADDR.end || len < self.total_len() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Return the header length.
    #[inline]
    pub fn header_len(&self) -> usize {
        // This is not a strictly necessary function, but it makes
        // code more readable.
        field::DST_ADDR.end
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.0[field::VER_TC_FLOW.start] >> 4
    }

    /// Return the traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((NetworkEndian::read_u16(&self.0[0..2]) & 0x0ff0) >> 4) as u8
    }

    /// Return the flow label field.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        NetworkEndian::read_u24(&self.0[1..4]) & 0x000fffff
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::LENGTH])
    }

    /// Return the payload length added to the known header length.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len() + self.payload_len() as usize
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.0[field::NXT_HDR])
    }

    /// Return the hop limit field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.0[field::HOP_LIMIT]
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.0[field::SRC_ADDR])
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        Address::from_bytes(&self.0[field::DST_ADDR])
    }

    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        // Make sure to retain the lower order bits which contain
        // the higher order bits of the traffic class
        self.0[0] = (self.0[0] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the traffic class field.
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        let data = &mut self.0;
        // Put the higher order 4-bits of value in the lower order
        // 4-bits of the first byte
        data[0] = (data[0] & 0xf0) | ((value & 0xf0) >> 4);
        // Put the lower order 4-bits of value in the higher order
        // 4-bits of the second byte
        data[1] = (data[1] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the flow label field.
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        // Retain the lower order 4-bits of the traffic class
        let raw = (((self.0[1] & 0xf0) as u32) << 16) | (value & 0x0fffff);
        NetworkEndian::write_u24(&mut self.0[1..4], raw);
    }

    /// Set the payload length field.
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::LENGTH], value);
    }

    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        self.0[field::NXT_HDR] = value.into();
    }

    /// Set the hop limit field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        self.0[field::HOP_LIMIT] = value;
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        self.0[field::SRC_ADDR].copy_from_slice(value.as_bytes());
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        self.0[field::DST_ADDR].copy_from_slice(value.as_bytes());
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload_slice(&self) -> &[u8] {
        let range = self.header_len()..self.total_len();
        &self.0[range]
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        let range = self.header_len()..self.total_len();
        &mut self.0[range]
    }
}

impl<T: Payload> Packet<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let repr = {
            let packet = ipv6::new_checked(buffer.payload())?;
            Repr::parse(packet)?
        };
        Ok(Packet {
            buffer,
            repr,
        })
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
        Packet {
            buffer,
            repr,
        }
    }

    /// Consume the packet, returning the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: PayloadMut> Packet<T> {
}

impl<T: Payload> ops::Deref for Packet<T> {
    type Target = ipv6;

    fn deref(&self) -> &ipv6 {
        ipv6::new_unchecked(self.buffer.payload())
    }
}

impl<T: Payload> Payload for Packet<T> {
    fn payload(&self) -> &payload {
        self.payload_slice().into()
    }
}

impl<T: PayloadMut> PayloadMut for Packet<T> {
    fn payload_mut(&mut self) -> &mut payload {
        ipv6::new_unchecked_mut(self.buffer.payload_mut())
            .payload_mut_slice()
            .into()
    }

    fn resize(&mut self, length: usize) -> core::result::Result<(), PayloadError> {
        let hdr_len = self.header_len();
        self.buffer.resize(length + hdr_len)
    }

    fn reframe(&mut self, mut reframe: Reframe)
        -> core::result::Result<(), PayloadError>
    {
        let hdr_len = self.header_len();
        reframe.within_header(hdr_len);
        self.buffer.reframe(reframe)
    }
}


impl<T: Payload> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv6 ({})", err)?;
                Ok(())
            }
        }
    }
}

impl<T: Payload> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.payload().into()
    }
}

/// A high-level representation of an Internet Protocol version 6 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// IPv6 address of the source node.
    pub src_addr:    Address,
    /// IPv6 address of the destination node.
    pub dst_addr:    Address,
    /// Protocol contained in the next header.
    pub next_header: Protocol,
    /// Length of the payload including the extension headers.
    pub payload_len: usize,
    /// The 8-bit hop limit field.
    pub hop_limit:   u8
}

impl Repr {
    /// Parse an Internet Protocol version 6 packet and return a high-level representation.
    pub fn parse(packet: &ipv6) -> Result<Repr> {
        // Ensure basic accessors will work
        packet.check_len()?;
        if packet.version() != 6 { return Err(Error::Malformed); }
        Ok(Repr {
            src_addr:    packet.src_addr(),
            dst_addr:    packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len: packet.payload_len() as usize,
            hop_limit:   packet.hop_limit()
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // This function is not strictly necessary, but it can make client code more readable.
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 6 packet.
    pub fn emit(&self, packet: &mut ipv6) {
        // Make no assumptions about the original state of the packet buffer.
        // Make sure to set every byte.
        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);
        packet.set_payload_len(self.payload_len as u16);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv6 src={} dst={} nxt_hdr={} hop_limit={}",
               self.src_addr, self.dst_addr, self.next_header, self.hop_limit)
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

// TODO: This is very similar to the implementation for IPv4. Make
// a way to have less copy and pasted code here.
impl PrettyPrint for ipv6 {
    fn pretty_print(buffer: &[u8], f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        // Verify the packet structure.
        let packet = match ipv6::new_checked(buffer) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(frame) => frame,
        };

        // Verify the packet content
        let repr = match Repr::parse(packet) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(ip_repr) => ip_repr,
        };

        write!(f, "{}{}", indent, repr)?;
        pretty_print_ip_payload(f, indent, repr, packet.payload_slice())
    }
}

#[cfg(test)]
mod test {
    use super::{Address, Error, Cidr};
    use super::{ipv6, Protocol, Repr};

    use crate::wire::pretty_print::{PrettyPrinter};
    use crate::wire::ipv4::Address as Ipv4Address;

    static LINK_LOCAL_ADDR: Address = Address([0xfe, 0x80, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x01]);
    #[test]
    fn test_basic_multicast() {
        assert!(!Address::LINK_LOCAL_ALL_ROUTERS.is_unspecified());
        assert!(Address::LINK_LOCAL_ALL_ROUTERS.is_multicast());
        assert!(!Address::LINK_LOCAL_ALL_ROUTERS.is_link_local());
        assert!(!Address::LINK_LOCAL_ALL_ROUTERS.is_loopback());
        assert!(!Address::LINK_LOCAL_ALL_NODES.is_unspecified());
        assert!(Address::LINK_LOCAL_ALL_NODES.is_multicast());
        assert!(!Address::LINK_LOCAL_ALL_NODES.is_link_local());
        assert!(!Address::LINK_LOCAL_ALL_NODES.is_loopback());
    }

    #[test]
    fn test_basic_link_local() {
        assert!(!LINK_LOCAL_ADDR.is_unspecified());
        assert!(!LINK_LOCAL_ADDR.is_multicast());
        assert!(LINK_LOCAL_ADDR.is_link_local());
        assert!(!LINK_LOCAL_ADDR.is_loopback());
    }

    #[test]
    fn test_basic_loopback() {
        assert!(!Address::LOOPBACK.is_unspecified());
        assert!(!Address::LOOPBACK.is_multicast());
        assert!(!Address::LOOPBACK.is_link_local());
        assert!(Address::LOOPBACK.is_loopback());
    }

    #[test]
    fn test_address_format() {
        assert_eq!("ff02::1",
                   format!("{}", Address::LINK_LOCAL_ALL_NODES));
        assert_eq!("fe80::1",
                   format!("{}", LINK_LOCAL_ADDR));
        assert_eq!("fe80::7f00:0:1",
                   format!("{}", Address::new(0xfe80, 0, 0, 0, 0, 0x7f00, 0x0000, 0x0001)));
        assert_eq!("::",
                   format!("{}", Address::UNSPECIFIED));
        assert_eq!("::1",
                   format!("{}", Address::LOOPBACK));

        #[cfg(feature = "proto-ipv4")]
        assert_eq!("::ffff:192.168.1.1",
                   format!("{}", Address::from(Ipv4Address::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_new() {
        assert_eq!(Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                   Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
                   Address::LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(Address::new(0, 0, 0, 0, 0, 0, 0, 1),
                   Address::LOOPBACK);
        assert_eq!(Address::new(0, 0, 0, 0, 0, 0, 0, 0),
                   Address::UNSPECIFIED);
        assert_eq!(Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                   LINK_LOCAL_ADDR);
    }

    #[test]
    fn test_from_parts() {
        assert_eq!(Address::from_parts(&[0xff02, 0, 0, 0, 0, 0, 0, 1]),
                   Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(Address::from_parts(&[0xff02, 0, 0, 0, 0, 0, 0, 2]),
                   Address::LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(Address::from_parts(&[0, 0, 0, 0, 0, 0, 0, 1]),
                   Address::LOOPBACK);
        assert_eq!(Address::from_parts(&[0, 0, 0, 0, 0, 0, 0, 0]),
                   Address::UNSPECIFIED);
        assert_eq!(Address::from_parts(&[0xfe80, 0, 0, 0, 0, 0, 0, 1]),
                   LINK_LOCAL_ADDR);
    }

    #[test]
    fn test_write_parts() {
        let mut bytes = [0u16; 8];
        {
            Address::LOOPBACK.write_parts(&mut bytes);
            assert_eq!(Address::LOOPBACK, Address::from_parts(&bytes));
        }
        {
            Address::LINK_LOCAL_ALL_ROUTERS.write_parts(&mut bytes);
            assert_eq!(Address::LINK_LOCAL_ALL_ROUTERS, Address::from_parts(&bytes));
        }
        {
            LINK_LOCAL_ADDR.write_parts(&mut bytes);
            assert_eq!(LINK_LOCAL_ADDR, Address::from_parts(&bytes));
        }
    }

    #[test]
    fn test_mask() {
        let addr = Address::new(0x0123, 0x4567, 0x89ab, 0, 0, 0, 0, 1);
        assert_eq!(addr.mask(11).0, [0x01, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(15).0, [0x01, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(26).0, [0x01, 0x23, 0x45, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(128).0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(addr.mask(127).0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_is_ipv4_mapped() {
        assert_eq!(false, Address::UNSPECIFIED.is_ipv4_mapped());
        assert_eq!(true, Address::from_mapped_ipv4(Ipv4Address::new(192, 168, 1, 1)).is_ipv4_mapped());
    }

    #[test]
    fn test_as_ipv4() {
        assert_eq!(None, Address::UNSPECIFIED.as_ipv4());

        let ipv4 = Ipv4Address::new(192, 168, 1, 1);
        assert_eq!(Some(ipv4), Address::from_mapped_ipv4(ipv4).as_ipv4());
    }

    #[test]
    fn test_from_ipv4_address() {
        assert_eq!(Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]),
            Address::from_mapped_ipv4(Ipv4Address::new(192, 168, 1, 1)));
        assert_eq!(Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 222, 1, 41, 90]),
            Address::from_mapped_ipv4(Ipv4Address::new(222, 1, 41, 90)));
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(LINK_LOCAL_ADDR, 64);

        let inside_subnet = [
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]
        ];

        let outside_subnet = [
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        ];

        let subnets = [
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             65),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
             128),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78],
             96)
        ];

        let not_subnets = [
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             63),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             64),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             65),
            ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
             128)
        ];

        for addr in inside_subnet.iter().cloned().map(Address) {
            assert!(cidr.subnet().contains(addr));
        }

        for addr in outside_subnet.iter().cloned().map(Address) {
            assert!(!cidr.subnet().contains(addr));
        }

        for subnet in subnets.iter().map(
            |&(a, p)| Cidr::new(Address(a), p).subnet()) {
            assert!(cidr.subnet().contains_subnet(subnet));
        }

        for subnet in not_subnets.iter().map(
            |&(a, p)| Cidr::new(Address(a), p).subnet()) {
            assert!(!cidr.subnet().contains_subnet(subnet));
        }

        let cidr_without_prefix = Cidr::new(LINK_LOCAL_ADDR, 0);
        assert!(cidr_without_prefix.subnet().contains(Address::LOOPBACK));
    }

    #[test]
    #[should_panic(expected = "destination and source slices have different lengths")]
    fn test_from_bytes_too_long() {
        let _ = Address::from_bytes(&[0u8; 15]);
    }

    #[test]
    #[should_panic(expected = "data.len() >= 8")]
    fn test_from_parts_too_long() {
        let _ = Address::from_parts(&[0u16; 7]);
    }

    static REPR_PACKET_BYTES: [u8; 52] = [0x60, 0x00, 0x00, 0x00,
                                          0x00, 0x0c, 0x11, 0x40,
                                          0xfe, 0x80, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01,
                                          0xff, 0x02, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01,
                                          0x00, 0x01, 0x00, 0x02,
                                          0x00, 0x0c, 0x02, 0x4e,
                                          0xff, 0xff, 0xff, 0xff];
    static REPR_PAYLOAD_BYTES: [u8; 12] = [0x00, 0x01, 0x00, 0x02,
                                           0x00, 0x0c, 0x02, 0x4e,
                                           0xff, 0xff, 0xff, 0xff];

    fn packet_repr() -> Repr {
        Repr {
            src_addr:    Address([0xfe, 0x80, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x01]),
            dst_addr:    Address::LINK_LOCAL_ALL_NODES,
            next_header: Protocol::Udp,
            payload_len: 12,
            hop_limit:   64
        }
    }

    #[test]
    fn test_packet_deconstruction() {
        let packet = ipv6::new_unchecked(&REPR_PACKET_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0);
        assert_eq!(packet.flow_label(), 0);
        assert_eq!(packet.total_len(), 0x34);
        assert_eq!(packet.payload_len() as usize, REPR_PAYLOAD_BYTES.len());
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.hop_limit(), 0x40);
        assert_eq!(packet.src_addr(), Address([0xfe, 0x80, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x01]));
        assert_eq!(packet.dst_addr(), Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.payload_slice(), &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let mut bytes = [0xff; 52];
        let packet = ipv6::new_unchecked_mut(&mut bytes[..]);
        // Version, Traffic Class, and Flow Label are not
        // byte aligned. make sure the setters and getters
        // do not interfere with each other.
        packet.set_version(6);
        assert_eq!(packet.version(), 6);
        packet.set_traffic_class(0x99);
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0x99);
        packet.set_flow_label(0x54321);
        assert_eq!(packet.traffic_class(), 0x99);
        assert_eq!(packet.flow_label(), 0x54321);
        packet.set_payload_len(0xc);
        packet.set_next_header(Protocol::Udp);
        packet.set_hop_limit(0xfe);
        packet.set_src_addr(Address::LINK_LOCAL_ALL_ROUTERS);
        packet.set_dst_addr(Address::LINK_LOCAL_ALL_NODES);
        packet.payload_mut_slice().copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        let mut expected_bytes = [
            0x69, 0x95, 0x43, 0x21, 0x00, 0x0c, 0x11, 0xfe,
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];
        let start = expected_bytes.len() - REPR_PAYLOAD_BYTES.len();
        expected_bytes[start..].copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(packet.as_bytes(), &expected_bytes[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(ipv6::new_unchecked(&bytes).payload_slice().len(),
                   REPR_PAYLOAD_BYTES.len());
        assert_eq!(ipv6::new_unchecked_mut(&mut bytes).payload_mut_slice().len(),
                   REPR_PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        ipv6::new_unchecked_mut(&mut bytes).set_payload_len(0x80);

        assert_eq!(ipv6::new_checked(&bytes).unwrap_err(),
                   Error::Truncated);
    }

    #[test]
    fn test_repr_parse_valid() {
        let packet = ipv6::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_repr_parse_bad_version() {
        let mut bytes = vec![0; 40];
        let packet = ipv6::new_unchecked_mut(&mut bytes[..]);
        packet.set_version(4);
        packet.set_payload_len(0);
        let packet = ipv6::new_unchecked(packet.as_bytes());
        assert_eq!(Repr::parse(packet), Err(Error::Malformed));
    }

    #[test]
    fn test_repr_parse_smaller_than_header() {
        let mut bytes = vec![0; 40];
        let packet = ipv6::new_unchecked_mut(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(39);
        let packet = ipv6::new_unchecked(packet.as_bytes());
        assert_eq!(Repr::parse(packet), Err(Error::Truncated));
    }

    #[test]
    fn test_repr_parse_smaller_than_payload() {
        let mut bytes = vec![0; 40];
        let packet = ipv6::new_unchecked_mut(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(1);
        let packet = ipv6::new_unchecked(packet.as_bytes());
        assert_eq!(Repr::parse(packet), Err(Error::Truncated));
    }

    #[test]
    fn test_basic_repr_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xff; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let packet = ipv6::new_unchecked_mut(&mut bytes);
        repr.emit(packet);
        packet.payload_mut_slice().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(packet.as_bytes(), &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_pretty_print() {
        assert_eq!(format!("{}", PrettyPrinter::<ipv6>::new("\n", &&REPR_PACKET_BYTES[..])),
                   "\nIPv6 src=fe80::1 dst=ff02::1 nxt_hdr=UDP hop_limit=64\n \\ UDP src=1 dst=2 len=4");
    }
}
