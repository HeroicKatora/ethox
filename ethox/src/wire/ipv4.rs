use core::{fmt, ops};
#[cfg(feature = "std")]
use core::str::FromStr;
use byteorder::{ByteOrder, NetworkEndian};

use super::{Reframe, Payload, PayloadError, PayloadMut, payload};
use super::{Error, Checksum, Result};
use super::ip::{checksum, pretty_print_ip_payload};
use super::field::Field;

pub(crate) use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv4. See [RFC 791 § 3.1].
///
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
// RFC 791 states the following:
//
// > Every internet module must be able to forward a datagram of 68
// > octets without further fragmentation... Every internet destination
// > must be able to receive a datagram of 576 octets either in one piece
// > or in fragments to be reassembled.
//
// As a result, we can assume that every host we send packets to can
// accept a packet of the following size.
pub const MIN_MTU: usize = 576;

/// A four-octet IPv4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 4]);

impl Address {
    /// An unspecified address.
    pub const UNSPECIFIED:           Address = Address([0x00; 4]);

    /// The broadcast address.
    pub const BROADCAST:             Address = Address([0xff; 4]);

    /// All multicast-capable nodes
    pub const MULTICAST_ALL_SYSTEMS: Address = Address([224, 0, 0, 1]);

    /// All multicast-capable routers
    pub const MULTICAST_ALL_ROUTERS: Address = Address([224, 0, 0, 2]);

    /// Construct an IPv4 address from parts.
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address([a0, a1, a2, a3])
    }

    /// Construct an IPv4 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not four octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an IPv4 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode the address into a `u32` in network endian byte order.
    pub fn to_network_integer(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Decode a network endian `u32` into an address.
    pub fn from_network_integer(num: u32) -> Self {
        Address(num.to_be_bytes())
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() ||
          self.is_multicast() ||
          self.is_unspecified())
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self.0[0..4] == [255; 4]
    }

    /// Query whether the address is a multicast address.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    /// Query whether the address falls into the "link-local" range.
    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    /// Query whether the address falls into the "loopback" range.
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Mask the address to some prefix length.
    ///
    /// Preserves only address bits that are relevant for the prefix length. This can be used to
    /// isolate the bits of the cidr subnet that the address belongs to.
    ///
    /// ```rust
    /// # use ethox::wire::Ipv4Address as Address;
    /// let base = Address([192, 168, 178, 32]);
    /// let masked = base.mask(24);
    /// assert!(masked == Address([192, 168, 178, 0]));
    /// ```
    ///
    /// # Panics
    /// This function panics if `prefix` is greater than 32.
    pub fn mask(&self, prefix: u8) -> Address {
        assert!(prefix <= 32);
        let masked_off = (!0u32)
            .checked_shr(prefix.into())
            .unwrap_or(0);
        let as_int = self.to_network_integer() & !masked_off;
        Address::from_network_integer(as_int)
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(x: ::std::net::Ipv4Addr) -> Address {
        Address(x.octets())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv4Addr {
    fn from(Address(x): Address) -> ::std::net::Ipv4Addr {
        x.into()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// An IPv4 CIDR host: an address and a variable-length subnet masking prefix length.
///
/// Relevant RFCs:
/// * [RFC 1519: Classless Inter-Domain Routing (CIDR)][RFC1519]
/// * [RFC 3021: Using 31-Bit Prefixes on IPv4 Point-to-Point Links][RFC3021]
///
/// [RFC1519]: https://tools.ietf.org/html/rfc1519
/// [RFC3021]: https://tools.ietf.org/html/rfc3021
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Cidr {
    address:    Address,
    prefix_len: u8,
}

/// An IPv4 CIDR block.
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
    /// The address identifying all networks.
    ///
    /// This must never be used as a source address (like other network addresses) but MAY be used
    /// to identify a host in a local network that has not yet been assigned an address while it is
    /// requesting one.
    ///
    /// Additionally, it may also be used as a mask in address selection when the ip address can be
    /// chosen arbitrarily.
    pub const UNSPECIFIED: Self = Cidr { address: Address::UNSPECIFIED, prefix_len: 0 };

    /// Create an IPv4 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 32.
    pub fn new(address: Address, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 32);
        Cidr { address, prefix_len }
    }

    /// Create an IPv4 CIDR block from the given address and network mask.
    pub fn from_netmask(addr: Address, netmask: Address) -> Option<Cidr> {
        let netmask = netmask.to_network_integer();
        if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
            Some(Cidr { address: addr, prefix_len: netmask.count_ones() as u8 })
        } else {
            None
        }
    }

    /// Return the address of this IPv4 CIDR block.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the network mask of this IPv4 CIDR.
    pub fn netmask(&self) -> Address {
        Address::from_network_integer(!0).mask(self.prefix_len)
    }

    /// Determines if the subnet contains a reserved network and broadcast address.
    ///
    /// This is the cast if the prefix is shorter than 31 bits according to
    /// [RFC3021](https://tools.ietf.org/html/rfc3021).
    pub fn has_network_and_broadcast(&self) -> bool {
        self.prefix_len < 31
    }

    /// Return the broadcast address of this IPv4 CIDR.
    pub fn broadcast(&self) -> Option<Cidr> {
        if !self.has_network_and_broadcast() {
            return None;
        }

        let netaddr = self.address.to_network_integer();
        let netmask = self.netmask().to_network_integer();

        Some(Cidr {
            address: Address::from_network_integer(netaddr | !netmask),
            .. *self
        })
    }

    /// Return the network address of this IPv4 CIDR.
    pub fn network(&self) -> Option<Cidr> {
        if !self.has_network_and_broadcast() {
            return None;
        }

        let netaddr = self.address.to_network_integer();
        let netmask = self.netmask().to_network_integer();

        Some(Cidr {
            address: Address::from_network_integer(netaddr & netmask),
            .. *self
        })
    }

    /// The subnet containing this address.
    ///
    /// Not to be confused with the `network` address, a reserved CIDR address identifying the
    /// whole subnet. This distinction is slightly more important for IPv6 where no such address
    /// exists.
    pub fn subnet(self) -> Subnet {
        Subnet::from_cidr(self)
    }

    /// Find out if the Cidr address identifies the host.
    ///
    /// If the prefix of the `Cidr` is 31 or 32 simply does a full match of the address. Otherwise,
    /// interprets the Cidr according to reserved host address semantics. That is:
    /// * A host address of all zeroes for any address in the subnet (including `0` and broadcast).
    /// * A host address of all ones for any address other than the all zeroes address.
    /// * Any other host address matches its host address exactly.
    ///
    /// To query if an address is contained in the subnet identified by this Cidr, use `subnet`.
    #[deprecated = "Imprecise"]
    pub fn matches(&self, address: Address) -> bool {
        if !self.has_network_and_broadcast() {
            return self.address == address
        }

        let address = address.to_network_integer();
        let netaddr = self.address.to_network_integer();
        let netmask = self.netmask().to_network_integer();

        // Network
        if netaddr & !netmask == 0 {
            return address & netmask == netaddr & netmask;
        }

        // Broadcast
        if !netaddr & !netmask == 0 {
            let same_net = address & netmask == netaddr & netmask;
            let is_net = address & !netmask == 0;
            return same_net && !is_net;
        }

        // Host address.
        netaddr == address
    }

    /// Whether to accept a packet directed at some address.
    ///
    /// See section 3.3. of [RFC1519].
	///
	/// [RFC1519]: https://tools.ietf.org/html/rfc1519
    pub fn accepts(&self, address: Address) -> bool {
		let broadcast = self.broadcast()
            .map(|cidr| cidr.address == address)
            .unwrap_or(false);
        let network = self.network()
            .map(|cidr| cidr.address == address)
            .unwrap_or(false);
		// We MAY accept packets to the network address. We don't because we would have to treat
        // them like broadcasts and thus probably mangle the address.
		(self.address == address || broadcast || address == Address::BROADCAST) && !network
    }

    /// Query whether the host is in a subnetwork contained in the subnetwork of `self`.
    ///
    /// In contrast to `contains` this only checks the relation of the subnets described by the
    /// both address blocks. It completely ignores the host identifiers. Consequently this will
    /// also successfully work for blocks that do not have an address identifying the network
    /// itself, that is for prefix lengths 31 and 32.
    ///
    /// This is used for finding out whether a given address is network or link-local or needs to
    /// be routed.
    #[deprecated = "Use `subnet` on both arguments instead."]
    pub fn contains_subnet(&self, subnet: Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && {
            let netmask = self.netmask().to_network_integer();
            let netaddr = self.address.to_network_integer();
            let othaddr = subnet.address.to_network_integer();
            netaddr & netmask == othaddr & netmask
        }
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
        Address::from_network_integer(!0).mask(self.prefix)
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix
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

/// Error emitted when parsing an IPv4 CIDR specifier fails.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseCidrError {
    kind: ParseCidrErrorKind,
}

/// The general kind of failure during parsing of an IPv4 CIDR.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseCidrErrorKind {
    /// The subnet prefix was missing entirely.
    NoSubnet,

    /// The IPv4 address part is invalid.
    AddrParseError,

    /// The subnet prefix is invalid.
    InvalidPrefix,
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

#[cfg(feature = "std")]
impl fmt::Display for ParseCidrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self.kind {
            ParseCidrErrorKind::NoSubnet => "missing subnet prefix separator",
            ParseCidrErrorKind::AddrParseError => "invalid address",
            ParseCidrErrorKind::InvalidPrefix => "invalid cidr prefix",
        })
    }
}

#[cfg(feature = "std")]
impl FromStr for Cidr {
    type Err = ParseCidrError;

    fn from_str(src :&str) -> core::result::Result<Self, ParseCidrError> {
        let subnet = src.find('/')
            .ok_or(ParseCidrError {
                kind: ParseCidrErrorKind::NoSubnet,
            })?;
        let address: std::net::Ipv4Addr = src[..subnet]
            .parse()
            .map_err(|_| ParseCidrError {
                kind: ParseCidrErrorKind::AddrParseError,
            })?;
        let prefix_len = src[subnet+1..]
            .parse()
            .map_err(|_| ParseCidrError {
                kind: ParseCidrErrorKind::InvalidPrefix,
            })
            .and_then(|prefix| if prefix <= 32 {
                Ok(prefix)
            } else {
                Err(ParseCidrError {
                    kind: ParseCidrErrorKind::InvalidPrefix,
                })
            })?;
        Ok(Cidr { address: address.into(), prefix_len })
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: Payload> {
    buffer: T,
    repr: Repr,
}

byte_wrapper! {
    /// A byte sequence representing an IPv4 packet.
    #[derive(Debug, PartialEq, Eq)]
    pub struct ipv4([u8]);
}

mod field {
    use crate::wire::field::Field;

    pub(crate) const VER_IHL:  usize = 0;
    pub(crate) const DSCP_ECN: usize = 1;
    pub(crate) const LENGTH:   Field = 2..4;
    pub(crate) const IDENT:    Field = 4..6;
    pub(crate) const FLG_OFF:  Field = 6..8;
    pub(crate) const TTL:      usize = 8;
    pub(crate) const PROTOCOL: usize = 9;
    pub(crate) const CHECKSUM: Field = 10..12;
    pub(crate) const SRC_ADDR: Field = 12..16;
    pub(crate) const DST_ADDR: Field = 16..20;
}

impl ipv4 {
    /// Imbue a raw octet buffer with IPv4 packet structure.
    pub fn new_unchecked(buffer: &[u8]) -> &ipv4 {
        Self::__from_macro_new_unchecked(buffer)
    }

    /// Imbue a mutable octet buffer with IPv4 packet structure.
    pub fn new_unchecked_mut(buffer: &mut [u8]) -> &mut ipv4 {
        Self::__from_macro_new_unchecked_mut(buffer)
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(data: &[u8]) -> Result<&ipv4> {
        let packet = Self::new_unchecked(data);
        packet.check_len()?;
        Ok(packet)
    }

    /// View the packet as a raw byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// View the packet as a mutable raw byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    /// Returns `Err(Error::Malformed)` if the header length is greater
    /// than total length.
    ///
    /// The result of this check is invalidated by calling [set_header_len]
    /// and [set_total_len].
    ///
    /// [set_header_len]: #method.set_header_len
    /// [set_total_len]: #method.set_total_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.0.len();
        if len < field::DST_ADDR.end {
            Err(Error::Truncated)
        } else if len < self.header_len() as usize {
            Err(Error::Truncated)
        } else if self.header_len() as u16 > self.total_len() {
            Err(Error::Malformed)
        } else if len < self.total_len() as usize {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.0[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.0[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        self.0[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        self.0[field::DSCP_ECN] & 0x03
    }

    /// Return the total length field.
    #[inline]
    pub fn total_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::LENGTH])
    }

    /// Return the fragment identification field.
    #[inline]
    pub fn ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    #[inline]
    pub fn dont_frag(&self) -> bool {
        NetworkEndian::read_u16(&self.0[field::FLG_OFF]) & 0x4000 != 0
    }

    /// Return the "more fragments" flag.
    #[inline]
    pub fn more_frags(&self) -> bool {
        NetworkEndian::read_u16(&self.0[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.0[field::TTL]
    }

    /// Return the protocol field.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.0[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::CHECKSUM])
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

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) { return true }

        checksum::data(&self.0[..self.header_len() as usize]) == !0
    }

    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        self.0[field::VER_IHL] = (self.0[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        self.0[field::VER_IHL] = (self.0[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        self.0[field::DSCP_ECN] = (self.0[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        self.0[field::DSCP_ECN] = (self.0[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::IDENT], value)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let raw = NetworkEndian::read_u16(&self.0[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut self.0[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        let raw = NetworkEndian::read_u16(&self.0[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut self.0[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let raw = NetworkEndian::read_u16(&self.0[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut self.0[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let raw = NetworkEndian::read_u16(&self.0[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut self.0[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        self.0[field::TTL] = value
    }

    /// Set the protocol field.
    #[inline]
    pub fn set_protocol(&mut self, value: Protocol) {
        self.0[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.0[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        self.0[field::SRC_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        self.0[field::DST_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            !checksum::data(&self.0[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }

    /// Compute the range of the payload without accessing it.
    ///
    /// Contrary to `payload_slice`, this only requires the packet to have a valid header but need
    /// not have a consistent length for the payload itself.
    pub fn payload_range(&self) -> Field {
        let header_end = usize::from(self.header_len());
        let total_len = usize::from(self.total_len());
        header_end..total_len
    }

    /// Return the payload as a byte slice.
    pub fn payload_slice(&self) -> &[u8] {
        let range = self.payload_range();
        &self.0[range]
    }

    /// Return the payload as a mutable byte slice.
    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        let range = self.payload_range();
        &mut self.0[range]
    }
}

impl AsRef<[u8]> for ipv4 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for ipv4 {
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
            let packet = ipv4::new_checked(buffer.payload())?;
            Repr::parse(packet, checksum)?
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

    /// Return the raw underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: Payload + PayloadMut> Packet<T> {
    /// Recalculate the checksum if necessary.
    ///
    /// Note that the checksum test can be elided even in a checked parse of the ipv4 frame. This
    /// provides in opportunity to recalculate it if necessary even though the header structure is
    /// not otherwise mutably accessible while in `Packet` representation.
    pub fn fill_checksum(&mut self, checksum: Checksum) {
        if checksum.manual() {
            ipv4::new_unchecked_mut(self.buffer.payload_mut())
                .fill_checksum()
        }
    }
}

impl<'a, T: Payload + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload_bytes(&self) -> &'a [u8] {
        let data = self.buffer.payload();
        ipv4::new_unchecked(data).payload_slice()
    }
}

impl<T: Payload> ops::Deref for Packet<T> {
    type Target = ipv4;

    fn deref(&self) -> &ipv4 {
        // We checked the length at construction.
        ipv4::new_unchecked(self.buffer.payload())
    }
}

impl<T: Payload> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.payload().into()
    }
}

impl<T: Payload> Payload for Packet<T> {
    fn payload(&self) -> &payload {
        self.payload_slice().into()
    }
}

impl<T: Payload + PayloadMut> PayloadMut for Packet<T> {
    fn payload_mut(&mut self) -> &mut payload {
        ipv4::new_unchecked_mut(self.buffer.payload_mut())
            .payload_mut_slice()
            .into()
    }

    fn resize(&mut self, length: usize) -> core::result::Result<(), PayloadError> {
        let hdr_len = self.payload_range().start;
        self.buffer.resize(length + hdr_len)
    }

    fn reframe(&mut self, mut reframe: Reframe)
        -> core::result::Result<(), PayloadError> 
    {
        let hdr_len = self.payload_range().start;
        reframe.within_header(hdr_len);
        self.buffer.reframe(reframe)
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The source of the packet.
    pub src_addr:    Address,
    /// The destination of the packet.
    pub dst_addr:    Address,
    /// The encapsulated protocol identifier.
    pub protocol:    Protocol,
    /// The length of the payload.
    pub payload_len: usize,
    /// The remaining hop limit of the packet.
    pub hop_limit:   u8,
}

impl Repr {
    /// Parse an Internet Protocol version 4 packet and return a high-level representation.
    pub fn parse(packet: &ipv4, checksum: Checksum) -> Result<Repr> {
        packet.check_len()?;
        // Version 4 is expected.
        if packet.version() != 4 { return Err(Error::Malformed) }
        // Valid checksum is expected.
        if checksum.manual() && !packet.verify_checksum() { return Err(Error::WrongChecksum) }
        // We do not support fragmentation.
        if packet.more_frags() || packet.frag_offset() != 0 { return Err(Error::Unsupported) }
        // Since the packet is not fragmented, it must include the entire payload.
        let payload_len = packet.total_len() as usize - packet.header_len() as usize;
        if packet.payload_slice().len() < payload_len  { return Err(Error::Truncated) }

        // All DSCP values are acceptable, since they are of no concern to receiving endpoint.
        // All ECN values are acceptable, since ECN requires opt-in from both endpoints.
        // All TTL values are acceptable, since we do not perform routing.
        Ok(Repr {
            src_addr:    packet.src_addr(),
            dst_addr:    packet.dst_addr(),
            protocol:    packet.protocol(),
            payload_len: payload_len,
            hop_limit:   packet.hop_limit()
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // We never emit any options.
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 4 packet.
    pub fn emit(&self, packet: &mut ipv4, checksum: Checksum) {
        packet.set_version(4);
        packet.set_header_len(field::DST_ADDR.end as u8);
        packet.set_dscp(0);
        packet.set_ecn(0);
        let total_len = packet.header_len() as u16 + self.payload_len as u16;
        packet.set_total_len(total_len);
        packet.set_ident(0);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(self.hop_limit);
        packet.set_protocol(self.protocol);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);

        if checksum.manual() {
            packet.fill_checksum();
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

impl<T: Payload> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self, Checksum::Manual) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv4 ({})", err)?;
                write!(f, " src={} dst={} proto={} hop_limit={}",
                       self.src_addr(), self.dst_addr(), self.protocol(), self.hop_limit())?;
                if self.version() != 4 {
                    write!(f, " ver={}", self.version())?;
                }
                if self.header_len() != 20 {
                    write!(f, " hlen={}", self.header_len())?;
                }
                if self.dscp() != 0 {
                    write!(f, " dscp={}", self.dscp())?;
                }
                if self.ecn() != 0 {
                    write!(f, " ecn={}", self.ecn())?;
                }
                write!(f, " tlen={}", self.total_len())?;
                if self.dont_frag() {
                    write!(f, " df")?;
                }
                if self.more_frags() {
                    write!(f, " mf")?;
                }
                if self.frag_offset() != 0 {
                    write!(f, " off={}", self.frag_offset())?;
                }
                if self.more_frags() || self.frag_offset() != 0 {
                    write!(f, " id={}", self.ident())?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv4 src={} dst={} proto={}",
               self.src_addr, self.dst_addr, self.protocol)
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl PrettyPrint for ipv4 {
    fn pretty_print(buffer: &[u8], f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        use crate::wire::ip::checksum::format_checksum;

        // Verify the packet structure.
        let packet = match ipv4::new_checked(buffer) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(frame) => frame,
        };

        // Verify the packet content
        let repr = match Repr::parse(packet, Checksum::Ignored) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(ip_repr) => ip_repr,
        };

        write!(f, "{}{}", indent, repr)?;
        format_checksum(f, packet.verify_checksum())?;

        pretty_print_ip_payload(f, indent, repr, packet.payload_slice())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 30] =
        [0x45, 0x00, 0x00, 0x1e,
         0x01, 0x02, 0x62, 0x03,
         0x1a, 0x01, 0xd5, 0x6e,
         0x11, 0x12, 0x13, 0x14,
         0x21, 0x22, 0x23, 0x24,
         0xaa, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 10] =
        [0xaa, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = ipv4::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.dscp(), 0);
        assert_eq!(packet.ecn(), 0);
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.ident(), 0x102);
        assert_eq!(packet.more_frags(), true);
        assert_eq!(packet.dont_frag(), true);
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.hop_limit(), 0x1a);
        assert_eq!(packet.protocol(), Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xd56e);
        assert_eq!(packet.src_addr(), Address([0x11, 0x12, 0x13, 0x14]));
        assert_eq!(packet.dst_addr(), Address([0x21, 0x22, 0x23, 0x24]));
        assert_eq!(packet.verify_checksum(), true);
        assert_eq!(packet.payload_slice(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 30];
        let packet = ipv4::new_unchecked_mut(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x102);
        packet.set_more_frags(true);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0x203 * 8);
        packet.set_hop_limit(0x1a);
        packet.set_protocol(Protocol::Icmp);
        packet.set_src_addr(Address([0x11, 0x12, 0x13, 0x14]));
        packet.set_dst_addr(Address([0x21, 0x22, 0x23, 0x24]));
        packet.fill_checksum();
        packet.payload_mut_slice().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(packet.as_bytes(), &PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(ipv4::new_unchecked(&bytes).payload_slice().len(),
                   PAYLOAD_BYTES.len());
        assert_eq!(ipv4::new_unchecked_mut(&mut bytes).payload_mut_slice().len(),
                   PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        ipv4::new_unchecked_mut(&mut bytes).set_total_len(128);

        assert_eq!(Packet::new_checked(&bytes, Checksum::Manual),
                   Err(Error::Truncated));
    }

    static REPR_PACKET_BYTES: [u8; 24] =
        [0x45, 0x00, 0x00, 0x18,
         0x00, 0x00, 0x40, 0x00,
         0x40, 0x01, 0xd2, 0x79,
         0x11, 0x12, 0x13, 0x14,
         0x21, 0x22, 0x23, 0x24,
         0xaa, 0x00, 0x00, 0xff];

    static REPR_PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    fn packet_repr() -> Repr {
        Repr {
            src_addr:    Address([0x11, 0x12, 0x13, 0x14]),
            dst_addr:    Address([0x21, 0x22, 0x23, 0x24]),
            protocol:    Protocol::Icmp,
            payload_len: 4,
            hop_limit:   64
        }
    }

    #[test]
    fn test_parse() {
        let packet = ipv4::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, Checksum::Manual).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_parse_bad_version() {
        let mut bytes = vec![0; 24];
        bytes.copy_from_slice(&REPR_PACKET_BYTES[..]);
        let packet = ipv4::new_unchecked_mut(&mut bytes);
        packet.set_version(6);
        packet.fill_checksum();
        assert_eq!(Repr::parse(packet, Checksum::Manual), Err(Error::Malformed));
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = vec![0; 40];
        bytes[0] = 0x09;
        assert_eq!(Packet::new_checked(&mut bytes, Checksum::Manual), Err(Error::Malformed));
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = ipv4::new_unchecked_mut(&mut bytes);
        repr.emit(&mut packet, Checksum::Manual);
        packet.payload_mut_slice().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(packet.as_bytes(), &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_unspecified() {
        assert!(Address::UNSPECIFIED.is_unspecified());
        assert!(!Address::UNSPECIFIED.is_broadcast());
        assert!(!Address::UNSPECIFIED.is_multicast());
        assert!(!Address::UNSPECIFIED.is_link_local());
        assert!(!Address::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_broadcast() {
        assert!(!Address::BROADCAST.is_unspecified());
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_multicast());
        assert!(!Address::BROADCAST.is_link_local());
        assert!(!Address::BROADCAST.is_loopback());
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(Address::new(192, 168, 1, 10), 24);

        let inside_subnet = [
            [192, 168,   1,   0], [192, 168,   1,   1],
            [192, 168,   1,   2], [192, 168,   1,  10],
            [192, 168,   1, 127], [192, 168,   1, 255],
        ];

        let outside_subnet = [
            [192, 168,   0,   0], [127,   0,   0,   1],
            [192, 168,   2,   0], [192, 168,   0, 255],
            [  0,   0,   0,   0], [255, 255, 255, 255],
        ];

        let subnets = [
            ([192, 168,   1,   0], 32),
            ([192, 168,   1, 255], 24),
            ([192, 168,   1,  10], 30),
        ];

        let not_subnets = [
            ([192, 168,   1,  10], 23),
            ([127,   0,   0,   1],  8),
            ([192, 168,   1,   0],  0),
            ([192, 168,   0, 255], 32),
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
    }

    #[test]
    fn test_cidr_from_netmask() {
        assert_eq!(Cidr::from_netmask(Address([0, 0, 0, 0]), Address([1, 0, 2, 0])),
                   None);
        assert_eq!(Cidr::from_netmask(Address([0, 0, 0, 0]), Address([0, 0, 0, 0])),
                   None);
        assert_eq!(Cidr::from_netmask(Address([0, 0, 0, 1]), Address([255, 255, 255, 0])),
                   Some(Cidr::new(Address([0, 0, 0, 1]), 24)));
        assert_eq!(Cidr::from_netmask(Address([192, 168, 0, 1]), Address([255, 255, 0, 0])),
                   Some(Cidr::new(Address([192, 168, 0, 1]), 16)));
        assert_eq!(Cidr::from_netmask(Address([172, 16, 0, 1]), Address([255, 240, 0, 0])),
                   Some(Cidr::new(Address([172, 16, 0, 1]), 12)));
        assert_eq!(Cidr::from_netmask(Address([255, 255, 255, 1]), Address([255, 255, 255, 0])),
                   Some(Cidr::new(Address([255, 255, 255, 1]), 24)));
        assert_eq!(Cidr::from_netmask(Address([255, 255, 255, 255]), Address([255, 255, 255, 255])),
                   Some(Cidr::new(Address([255, 255, 255, 255]), 32)));
    }

    #[test]
    fn test_cidr_netmask() {
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 0).netmask(),
                   Address([0, 0, 0, 0]));
        assert_eq!(Cidr::new(Address([0, 0, 0, 1]), 24).netmask(),
                   Address([255, 255, 255, 0]));
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 32).netmask(),
                   Address([255, 255, 255, 255]));
        assert_eq!(Cidr::new(Address([127, 0, 0, 0]), 8).netmask(),
                   Address([255, 0, 0, 0]));
        assert_eq!(Cidr::new(Address([192, 168, 0, 0]), 16).netmask(),
                   Address([255, 255, 0, 0]));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 16).netmask(),
                   Address([255, 255, 0, 0]));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 17).netmask(),
                   Address([255, 255, 128, 0]));
        assert_eq!(Cidr::new(Address([172, 16, 0, 0]), 12).netmask(),
                   Address([255, 240, 0, 0]));
        assert_eq!(Cidr::new(Address([255, 255, 255, 1]), 24).netmask(),
                   Address([255, 255, 255, 0]));
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 32).netmask(),
                   Address([255, 255, 255, 255]));
    }

    #[test]
    fn test_cidr_broadcast() {
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 0).broadcast().map(|x| x.address()),
                   Some(Address([255, 255, 255, 255])));
        assert_eq!(Cidr::new(Address([0, 0, 0, 1]), 24).broadcast().map(|x| x.address()),
                   Some(Address([0, 0, 0, 255])));
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 32).broadcast().map(|x| x.address()),
                   None);
        assert_eq!(Cidr::new(Address([127, 0, 0, 0]), 8).broadcast().map(|x| x.address()),
                   Some(Address([127, 255, 255, 255])));
        assert_eq!(Cidr::new(Address([192, 168, 0, 0]), 16).broadcast().map(|x| x.address()),
                   Some(Address([192, 168, 255, 255])));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 16).broadcast().map(|x| x.address()),
                   Some(Address([192, 168, 255, 255])));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 17).broadcast().map(|x| x.address()),
                   Some(Address([192, 168, 127, 255])));
        assert_eq!(Cidr::new(Address([172, 16, 0, 1]), 12).broadcast().map(|x| x.address()),
                   Some(Address([172, 31, 255, 255])));
        assert_eq!(Cidr::new(Address([255, 255, 255, 1]), 24).broadcast().map(|x| x.address()),
                   Some(Address([255, 255, 255, 255])));
        assert_eq!(Cidr::new(Address([255, 255, 255, 254]), 31).broadcast().map(|x| x.address()),
                   None);
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 32).broadcast().map(|x| x.address()),
                   None);

    }

    #[test]
    fn test_cidr_network() {
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 0).network(),
                   Some(Cidr::new(Address([0, 0, 0, 0]), 0)));
        assert_eq!(Cidr::new(Address([0, 0, 0, 1]), 24).network(),
                   Some(Cidr::new(Address([0, 0, 0, 0]), 24)));
        assert_eq!(Cidr::new(Address([0, 0, 0, 0]), 32).network(),
                   None);
        assert_eq!(Cidr::new(Address([127, 0, 0, 0]), 8).network(),
                   Some(Cidr::new(Address([127, 0, 0, 0]), 8)));
        assert_eq!(Cidr::new(Address([192, 168, 0, 0]), 16).network(),
                   Some(Cidr::new(Address([192, 168, 0, 0]), 16)));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 16).network(),
                   Some(Cidr::new(Address([192, 168, 0, 0]), 16)));
        assert_eq!(Cidr::new(Address([192, 168, 1, 1]), 17).network(),
                   Some(Cidr::new(Address([192, 168, 0, 0]), 17)));
        assert_eq!(Cidr::new(Address([172,  16, 0, 1]), 12).network(),
                   Some(Cidr::new(Address([172,  16, 0, 0]), 12)));
        assert_eq!(Cidr::new(Address([255, 255, 255, 1]), 24).network(),
                   Some(Cidr::new(Address([255, 255, 255, 0]), 24)));
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 31).network(),
                   None);
        assert_eq!(Cidr::new(Address([255, 255, 255, 255]), 32).network(),
                   None);
    }
}
