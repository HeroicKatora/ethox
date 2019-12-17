use core::fmt;
use core::convert::From;

use crate::wire::{Error, Checksum, Result};
use super::{Ipv4Address, Ipv4Cidr, Ipv4Repr, Ipv4Subnet, ipv4_packet};
use super::{Ipv6Address, Ipv6Cidr, Ipv6Repr, Ipv6Subnet, ipv6_packet};

/// Internet protocol version.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Version {
    Unspecified,
    Ipv4,
    Ipv6,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Version {
    /// Return the version of an IP packet stored in the provided buffer.
    ///
    /// This function never returns `Ok(IpVersion::Unspecified)`; instead,
    /// unknown versions result in `Err(Error::Unrecognized)`.
    pub fn of_packet(data: &[u8]) -> Result<Version> {
        match data[0] >> 4 {
            4 => Ok(Version::Ipv4),
            6 => Ok(Version::Ipv6),
            _ => Err(Error::Unrecognized)
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Version::Unspecified => write!(f, "IPv?"),
            &Version::Ipv4 => write!(f, "IPv4"),
            &Version::Ipv6 => write!(f, "IPv6"),
            &Version::__Nonexhaustive => unreachable!()
        }
    }
}

enum_with_unknown! {
    /// IP datagram encapsulated protocol.
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Protocol::HopByHop    => write!(f, "Hop-by-Hop"),
            Protocol::Icmp        => write!(f, "ICMP"),
            Protocol::Igmp        => write!(f, "IGMP"),
            Protocol::Tcp         => write!(f, "TCP"),
            Protocol::Udp         => write!(f, "UDP"),
            Protocol::Ipv6Route   => write!(f, "IPv6-Route"),
            Protocol::Ipv6Frag    => write!(f, "IPv6-Frag"),
            Protocol::Icmpv6      => write!(f, "ICMPv6"),
            Protocol::Ipv6NoNxt   => write!(f, "IPv6-NoNxt"),
            Protocol::Ipv6Opts    => write!(f, "IPv6-Opts"),
            Protocol::Unknown(id) => write!(f, "0x{:02x}", id)
        }
    }
}

/// An internetworking address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An unspecified address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Unspecified,

    /// An IPv4 address.
    Ipv4(Ipv4Address),

    /// An IPv6 address.
    Ipv6(Ipv6Address),

    #[doc(hidden)]
    __Nonexhaustive
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    pub const fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// Create an address wrapping an IPv6 address with the given octets.
    // TODO: `const` fn
    pub fn v6(
        a0: u16, a1: u16, a2: u16, a3: u16,
        a4: u16, a5: u16, a6: u16, a7: u16,
    ) -> Address {
        Address::Ipv6(Ipv6Address::new(a0, a1, a2, a3, a4, a5, a6, a7))
    }

    /// Return an address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Address::Unspecified     => &[],
            Address::Ipv4(addr)      => addr.as_bytes(),
            Address::Ipv6(addr)      => addr.as_bytes(),
            Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            Address::Unspecified     => false,
            Address::Ipv4(addr)      => addr.is_unicast(),
            Address::Ipv6(addr)      => addr.is_unicast(),
            Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the address is a valid multicast address.
    pub fn is_multicast(&self) -> bool {
        match self {
            Address::Unspecified     => false,
            Address::Ipv4(addr)      => addr.is_multicast(),
            Address::Ipv6(addr)      => addr.is_multicast(),
            Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            Address::Unspecified     => false,
            Address::Ipv4(addr)      => addr.is_broadcast(),
            Address::Ipv6(_)         => false,
            Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match self {
            Address::Unspecified     => true,
            Address::Ipv4(addr)      => addr.is_unspecified(),
            Address::Ipv6(addr)      => addr.is_unspecified(),
            Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Return an unspecified address that has the same IP version as `self`.
    pub fn to_unspecified(&self) -> Address {
        match self {
            Address::Unspecified     => Address::Unspecified,
            Address::Ipv4(_)         => Address::Ipv4(Ipv4Address::UNSPECIFIED),
            Address::Ipv6(_)         => Address::Ipv6(Ipv6Address::UNSPECIFIED),
            Address::__Nonexhaustive => unreachable!()
        }
    }

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    pub fn to_prefix_len(&self) -> Option<u8> {
        let mut ones = true;
        let mut prefix_len = 0;
        for byte in self.as_bytes() {
            let mut mask = 0x80;
            for _ in 0..8 {
                let one = *byte & mask != 0;
                if ones {
                    // Expect 1s until first 0
                    if one {
                        prefix_len += 1;
                    } else {
                        ones = false;
                    }
                } else {
                    if one {
                        // 1 where 0 was expected
                        return None
                    }
                }
                mask >>= 1;
            }
        }
        Some(prefix_len)
    }
}

#[cfg(feature = "std")]
impl From<::std::net::IpAddr> for Address {
    fn from(x: ::std::net::IpAddr) -> Address {
        match x {
            ::std::net::IpAddr::V4(ipv4) => Address::Ipv4(ipv4.into()),
            ::std::net::IpAddr::V6(ipv6) => Address::Ipv6(ipv6.into()),
        }
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(ipv4: ::std::net::Ipv4Addr) -> Address {
        Address::Ipv4(ipv4.into())
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv6Addr> for Address {
    fn from(ipv6: ::std::net::Ipv6Addr) -> Address {
        Address::Ipv6(ipv6.into())
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::Unspecified
    }
}

impl From<Ipv4Address> for Address {
    fn from(addr: Ipv4Address) -> Self {
        Address::Ipv4(addr)
    }
}

impl From<Ipv6Address> for Address {
    fn from(addr: Ipv6Address) -> Self {
        Address::Ipv6(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Address::Unspecified     => write!(f, "*"),
            Address::Ipv4(addr)      => write!(f, "{}", addr),
            Address::Ipv6(addr)      => write!(f, "{}", addr),
            Address::__Nonexhaustive => unreachable!()
        }
    }
}

/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Cidr {
    Ipv4(Ipv4Cidr),
    Ipv6(Ipv6Cidr),
    #[doc(hidden)]
    __Nonexhaustive,
}

/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Subnet {
    Ipv4(Ipv4Subnet),
    Ipv6(Ipv6Subnet),
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Cidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given address is unspecified, or
    /// the given prefix length is invalid for the given address.
    pub fn new(addr: Address, prefix_len: u8) -> Cidr {
        match addr {
            Address::Ipv4(addr) => Cidr::Ipv4(Ipv4Cidr::new(addr, prefix_len)),
            Address::Ipv6(addr) => Cidr::Ipv6(Ipv6Cidr::new(addr, prefix_len)),
            Address::Unspecified =>
                panic!("a CIDR block cannot be based on an unspecified address"),
            Address::__Nonexhaustive =>
                unreachable!()
        }
    }

    /// The subnet containing this address.
    pub fn subnet(self) -> Subnet {
        match self {
            Cidr::Ipv4(addr) => Subnet::Ipv4(addr.subnet()),
            Cidr::Ipv6(addr) => Subnet::Ipv6(addr.subnet()),
            Cidr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Return the IP address of this CIDR block.
    pub fn address(&self) -> Address {
        match self {
            Cidr::Ipv4(cidr)      => Address::Ipv4(cidr.address()),
            Cidr::Ipv6(cidr)      => Address::Ipv6(cidr.address()),
            Cidr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the prefix length of this CIDR block.
    pub fn prefix_len(&self) -> u8 {
        match self {
            Cidr::Ipv4(cidr)      => cidr.prefix_len(),
            Cidr::Ipv6(cidr)      => cidr.prefix_len(),
            Cidr::__Nonexhaustive => unreachable!()
        }
    }

    /// Query if the cidr accepts traffic to the specified address.
    pub fn accepts(&self, addr: Address) -> bool {
        match (self, addr) {
            (Cidr::Ipv4(ref cidr), Address::Ipv4(addr)) =>
                cidr.accepts(addr),
            (Cidr::Ipv6(ref cidr), Address::Ipv6(addr)) =>
                cidr.accepts(addr),
            (Cidr::Ipv4(_), Address::Ipv6(_)) | (Cidr::Ipv6(_), Address::Ipv4(_)) =>
                false,
            (_, Address::Unspecified) =>
                // a fully unspecified address covers both IPv4 and IPv6,
                // and no CIDR block can do that.
                false,
            (Cidr::__Nonexhaustive, _) |
            (_, Address::__Nonexhaustive) =>
                unreachable!()
        }
    }
}

impl Subnet {
    /// Get the length of the subnet prefix.
    ///
    /// A shorter prefix identifies a larger subnet.
    pub fn prefix_len(self) -> u8 {
        match self {
            Subnet::Ipv4(block) => block.prefix_len(),
            Subnet::Ipv6(block) => block.prefix_len(),
            Subnet::__Nonexhaustive => unreachable!(),
        }
    }

    /// Query whether the CIDR subnetwork contains the given address.
    pub fn contains(&self, addr: Address) -> bool {
        match (self, addr) {
            (Subnet::Ipv4(block), Address::Ipv4(addr)) =>
                block.contains(addr),
            (Subnet::Ipv6(block), Address::Ipv6(addr)) =>
                block.contains(addr),
            (Subnet::Ipv4(_), Address::Ipv6(_)) | (Subnet::Ipv6(_), Address::Ipv4(_)) =>
                false,
            (_, Address::Unspecified) =>
                // a fully unspecified address covers both IPv4 and IPv6,
                // and no CIDR block can do that.
                false,
            (Subnet::__Nonexhaustive, _) |
            (_, Address::__Nonexhaustive) =>
                unreachable!()
        }
    }

    /// Check if the CIDR subnetwork fully contains the other subnetwork.
    pub fn contains_subnet(&self, other: Subnet) -> bool {
        match (self, other) {
            (Subnet::Ipv4(block), Subnet::Ipv4(other)) =>
                block.contains_subnet(other),
            (Subnet::Ipv6(block), Subnet::Ipv6(other)) =>
                block.contains_subnet(other),
            (Subnet::Ipv4(_), Subnet::Ipv6(_)) | (Subnet::Ipv6(_), Subnet::Ipv4(_)) =>
                false,
            (Subnet::__Nonexhaustive, _) |
            (_, Subnet::__Nonexhaustive) =>
                unreachable!()
        }
    }
}

impl From<Ipv4Cidr> for Cidr {
    fn from(addr: Ipv4Cidr) -> Self {
        Cidr::Ipv4(addr)
    }
}

impl From<Ipv6Cidr> for Cidr {
    fn from(addr: Ipv6Cidr) -> Self {
        Cidr::Ipv6(addr)
    }
}

impl From<Ipv4Subnet> for Subnet {
    fn from(block: Ipv4Subnet) -> Self {
        Subnet::Ipv4(block)
    }
}

impl From<Ipv6Subnet> for Subnet {
    fn from(block: Ipv6Subnet) -> Self {
        Subnet::Ipv6(block)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cidr::Ipv4(cidr)      => write!(f, "{}", cidr),
            Cidr::Ipv6(cidr)      => write!(f, "{}", cidr),
            Cidr::__Nonexhaustive => unreachable!()
        }
    }
}

/// An internet endpoint address.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16
}

impl Endpoint {
    /// An endpoint with unspecified address and port.
    pub const UNSPECIFIED: Endpoint = Endpoint { addr: Address::Unspecified, port: 0 };

    /// Create an endpoint address from given address and port.
    pub fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr: addr, port: port }
    }

    /// Query whether the endpoint has a specified address and port.
    pub fn is_specified(&self) -> bool {
        !self.addr.is_unspecified() && self.port != 0
    }
}

#[cfg(feature = "std")]
impl From<::std::net::SocketAddr> for Endpoint {
    fn from(x: ::std::net::SocketAddr) -> Endpoint {
        Endpoint {
            addr: x.ip().into(),
            port: x.port(),
        }
    }
}

#[cfg(feature = "std")]
impl From<::std::net::SocketAddrV4> for Endpoint {
    fn from(x: ::std::net::SocketAddrV4) -> Endpoint {
        Endpoint {
            addr: x.ip().clone().into(),
            port: x.port(),
        }
    }
}

#[cfg(feature = "std")]
impl From<::std::net::SocketAddrV6> for Endpoint {
    fn from(x: ::std::net::SocketAddrV6) -> Endpoint {
        Endpoint {
            addr: x.ip().clone().into(),
            port: x.port(),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl From<u16> for Endpoint {
    fn from(port: u16) -> Endpoint {
        Endpoint { addr: Address::Unspecified, port: port }
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint { addr: addr.into(), port: port }
    }
}

/// An IP packet representation.
///
/// This enum abstracts the various versions of IP packets. It either contains a concrete
/// high-level representation for some IP protocol version, or an unspecified representation,
/// which permits the `IpAddress::Unspecified` addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repr {
    Unspecified {
        src_addr:    Address,
        dst_addr:    Address,
        protocol:    Protocol,
        payload_len: usize,
        hop_limit:   u8
    },
    Ipv4(Ipv4Repr),
    Ipv6(Ipv6Repr),
    #[doc(hidden)]
    __Nonexhaustive
}

impl From<Ipv4Repr> for Repr {
    fn from(repr: Ipv4Repr) -> Repr {
        Repr::Ipv4(repr)
    }
}

impl From<Ipv6Repr> for Repr {
    fn from(repr: Ipv6Repr) -> Repr {
        Repr::Ipv6(repr)
    }
}

impl Repr {
    /// Return the protocol version.
    pub fn version(&self) -> Version {
        match self {
            Repr::Unspecified { .. } => Version::Unspecified,
            Repr::Ipv4(_) => Version::Ipv4,
            Repr::Ipv6(_) => Version::Ipv6,
            Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the source address.
    pub fn src_addr(&self) -> Address {
        match self {
            Repr::Unspecified { src_addr, .. } => *src_addr,
            Repr::Ipv4(repr) => Address::Ipv4(repr.src_addr),
            Repr::Ipv6(repr) => Address::Ipv6(repr.src_addr),
            Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the destination address.
    pub fn dst_addr(&self) -> Address {
        match self {
            Repr::Unspecified { dst_addr, .. } => *dst_addr,
            Repr::Ipv4(repr) => Address::Ipv4(repr.dst_addr),
            Repr::Ipv6(repr) => Address::Ipv6(repr.dst_addr),
            Repr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Return the protocol.
    pub fn protocol(&self) -> Protocol {
        match self {
            Repr::Unspecified { protocol, .. } => *protocol,
            Repr::Ipv4(repr) => repr.protocol,
            Repr::Ipv6(repr) => repr.next_header,
            Repr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Return the payload length.
    pub fn payload_len(&self) -> usize {
        match self {
            Repr::Unspecified { payload_len, .. } => *payload_len,
            Repr::Ipv4(repr) => repr.payload_len,
            Repr::Ipv6(repr) => repr.payload_len,
            Repr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Set the payload length.
    pub fn set_payload_len(&mut self, length: usize) {
        match self {
            Repr::Unspecified { payload_len, .. } => *payload_len = length,
            Repr::Ipv4(Ipv4Repr { payload_len, .. }) => *payload_len = length,
            Repr::Ipv6(Ipv6Repr { payload_len, .. }) => *payload_len = length,
            Repr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Return the TTL value.
    pub fn hop_limit(&self) -> u8 {
        match self {
            Repr::Unspecified { hop_limit, .. }    => *hop_limit,
            Repr::Ipv4(Ipv4Repr { hop_limit, .. }) => *hop_limit,
            Repr::Ipv6(Ipv6Repr { hop_limit, ..})  => *hop_limit,
            Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Convert an unspecified representation into a concrete one, or return
    /// `Err(Error::Unaddressable)` if not possible.
    ///
    /// # Panics
    /// This function panics if source and destination addresses belong to different families,
    /// or the destination address is unspecified, since this indicates a logic error.
    pub fn lower(&self, fallback_src_addrs: &[Cidr]) -> Option<Repr> {
        macro_rules! resolve_unspecified {
            ($reprty:path, $ipty:path, $iprepr:expr, $fallbacks:expr) => {
                if $iprepr.src_addr.is_unspecified() {
                    for cidr in $fallbacks {
                        match cidr.address() {
                            $ipty(addr) => {
                                $iprepr.src_addr = addr;
                                return Some($reprty($iprepr));
                            },
                            _ => ()
                        }
                    }
                    None
                } else {
                    Some($reprty($iprepr))
                }
            }
        }

        match self {
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Unspecified,
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } |
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Ipv4(_),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } if src_addr.is_unspecified() => {
                let mut src_addr = if let Address::Ipv4(src_ipv4_addr) = src_addr {
                    Some(src_ipv4_addr)
                } else {
                    None
                };
                for cidr in fallback_src_addrs {
                    if let Address::Ipv4(addr) = cidr.address() {
                        src_addr = Some(addr);
                        break;
                    }
                }
                Some(Repr::Ipv4(Ipv4Repr {
                    src_addr: src_addr?,
                    dst_addr, protocol, payload_len, hop_limit
                }))
            }

            &Repr::Unspecified {
                src_addr: src_addr @ Address::Unspecified,
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } |
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Ipv6(_),
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } if src_addr.is_unspecified() => {
                let mut src_addr = if let Address::Ipv6(src_ipv6_addr) = src_addr {
                    Some(src_ipv6_addr)
                } else {
                    None
                };
                for cidr in fallback_src_addrs {
                    if let Address::Ipv6(addr) = cidr.address() {
                        src_addr = Some(addr);
                        break;
                    }
                }
                Some(Repr::Ipv6(Ipv6Repr {
                    src_addr: src_addr?,
                    next_header: protocol,
                    dst_addr, payload_len, hop_limit
                }))
            }

            &Repr::Unspecified {
                src_addr: Address::Ipv4(src_addr),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } => {
                Some(Repr::Ipv4(Ipv4Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    protocol:    protocol,
                    payload_len: payload_len, hop_limit
                }))
            }

            &Repr::Unspecified {
                src_addr: Address::Ipv6(src_addr),
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } => {
                Some(Repr::Ipv6(Ipv6Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    next_header: protocol,
                    payload_len: payload_len,
                    hop_limit:   hop_limit
                }))
            }

            &Repr::Ipv4(mut repr) =>
                resolve_unspecified!(Repr::Ipv4, Address::Ipv4, repr, fallback_src_addrs),

            &Repr::Ipv6(mut repr) =>
                resolve_unspecified!(Repr::Ipv6, Address::Ipv6, repr, fallback_src_addrs),

            &Repr::Unspecified { .. } =>
                panic!("source and destination IP address families do not match"),

            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            Repr::Unspecified { .. } =>
                panic!("unspecified IP representation"),
            Repr::Ipv4(repr) => repr.buffer_len(),
            Repr::Ipv6(repr) => repr.buffer_len(),
            Repr::__Nonexhaustive => unreachable!(),
        }
    }

    /// Emit this high-level representation into a buffer.
    ///
    /// The checksum setting is passed to the specific representation for IPv4.
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, mut buffer: T, checksum: Checksum) {
        match self {
            Repr::Unspecified { .. } => panic!("unspecified IP representation"),
            Repr::Ipv4(repr) => {
                repr.emit(ipv4_packet::new_unchecked_mut(buffer.as_mut()), checksum)
            },
            Repr::Ipv6(repr) => {
                repr.emit(ipv6_packet::new_unchecked_mut(buffer.as_mut()))
            },
            Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the total length of a packet that will be emitted from this
    /// high-level representation.
    ///
    /// This is the same as `repr.buffer_len() + repr.payload_len()`.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn total_len(&self) -> usize {
        self.buffer_len() + self.payload_len()
    }
}

pub(crate) mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub(crate) fn data(mut data: &[u8]) -> u16 {
        let mut accum = 0;

        // For each 32-byte chunk...
        const CHUNK_SIZE: usize = 32;
        while data.len() >= CHUNK_SIZE {
            let mut d = &data[..CHUNK_SIZE];
            // ... take by 2 bytes and sum them.
            while d.len() >= 2 {
                accum += NetworkEndian::read_u16(d) as u32;
                d = &d[2..];
            }

            data = &data[CHUNK_SIZE..];
        }

        // Sum the rest that does not fit the last 32-byte chunk,
        // taking by 2 bytes.
        while data.len() >= 2 {
            accum += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }

        // Add the last remaining odd byte, if any.
        if let Some(&value) = data.first() {
            accum += (value as u32) << 8;
        }

        propagate_carries(accum)
    }

    /// Combine several RFC 1071 compliant checksums.
    pub(crate) fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    /// Compute an IP pseudo header checksum.
    pub(crate) fn pseudo_header(src_addr: &Address, dst_addr: &Address,
                         protocol: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
            (Address::Ipv4(src_addr), Address::Ipv4(dst_addr)) => {
                let mut proto_len = [0u8; 4];
                proto_len[1] = protocol.into();
                NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            },

            (Address::Ipv6(src_addr), Address::Ipv6(dst_addr)) => {
                let mut proto_len = [0u8; 8];
                proto_len[7] = protocol.into();
                NetworkEndian::write_u32(&mut proto_len[0..4], length);
                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            }

            _ => panic!("Unexpected pseudo header addresses: {}, {}",
                        src_addr, dst_addr)
        }
    }

    // We use this in pretty printer implementations.
    pub(crate) fn format_checksum(f: &mut fmt::Formatter, correct: bool) -> fmt::Result {
        if !correct {
            write!(f, " (checksum incorrect)")
        } else {
            Ok(())
        }
    }
}

use super::pretty_print::PrettyIndent;

pub(crate) fn pretty_print_ip_payload<T: Into<Repr>>(f: &mut fmt::Formatter, indent: PrettyIndent,
                                              ip_repr: T, payload: &[u8]) -> fmt::Result {
    use crate::wire::{TcpChecksum, TcpPacket, udp};
    use crate::wire::ip::checksum::format_checksum;

    let repr = ip_repr.into();
    match repr.protocol() {
        /*
        Protocol::Icmp => {
            indent.increase(f)?;
            Icmpv4Packet::<&[u8]>::pretty_print(&payload.as_ref(), f, indent)
        }
        */
        Protocol::Udp => {
            let indent = indent.increase(f)?;
            let printer = udp::CheckedPrinter::new(udp::Checksum::Manual {
                src_addr: repr.src_addr(),
                dst_addr: repr.dst_addr(),
            });

            printer.pretty_print(payload.as_ref(), f, indent)
        }
        Protocol::Tcp => {
            let indent = indent.increase(f)?;
            match TcpPacket::<&[u8]>::new_checked(payload.as_ref(), TcpChecksum::Ignored) {
                Err(err) => write!(f, "{}({})", indent, err),
                Ok(tcp_packet) => {
                    write!(f, "{}{}", indent, tcp_packet)?;
                    let valid = tcp_packet.verify_checksum(
                        repr.src_addr(), repr.dst_addr());
                    format_checksum(f, valid)
                }
            }
        }
        _ => Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(unused)]

    pub(crate) const MOCK_IP_ADDR_1: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 1]));
    pub(crate) const MOCK_IP_ADDR_2: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 2]));
    pub(crate) const MOCK_IP_ADDR_3: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 3]));
    pub(crate) const MOCK_IP_ADDR_4: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 4]));
    pub(crate) const MOCK_UNSPECIFIED: IpAddress = IpAddress::Ipv6(Ipv6Address::UNSPECIFIED);

    use super::*;
    use crate::wire::{IpAddress, IpProtocol,IpCidr};
    use crate::wire::{Ipv4Address, Ipv4Repr};

    macro_rules! generate_common_tests {
        ($name:ident, $repr:ident, $ip_repr:path, $ip_addr:path,
         $addr_from:path, $nxthdr:ident, $bytes_a:expr, $bytes_b:expr,
         $unspecified:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn test_ip_repr_lower() {
                    let ip_addr_a = $addr_from(&$bytes_a);
                    let ip_addr_b = $addr_from(&$bytes_b);
                    let proto = IpProtocol::Icmp;
                    let payload_len = 10;

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  $ip_addr(ip_addr_a),
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 0x2a,
                            payload_len,
                        }.lower(&[]),
                        Some($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 0x2a,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  IpAddress::Unspecified,
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[]),
                        None
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  IpAddress::Unspecified,
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[IpCidr::new($ip_addr(ip_addr_a), 24)]),
                        Some($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  $ip_addr($unspecified),
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[IpCidr::new($ip_addr(ip_addr_a), 24)]),
                        Some($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        Repr::Unspecified{
                            src_addr:  $ip_addr($unspecified),
                            dst_addr:  $ip_addr(ip_addr_b),
                            protocol:  proto,
                            hop_limit: 64,
                            payload_len
                        }.lower(&[]),
                        Some($ip_repr($repr{
                            src_addr:  $unspecified,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        $ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 255,
                            payload_len
                        }).lower(&[]),
                        Some($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 255,
                            payload_len
                        }))
                    );

                    assert_eq!(
                        $ip_repr($repr{
                            src_addr:  $unspecified,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 255,
                            payload_len
                        }).lower(&[]),
                        None
                    );

                    assert_eq!(
                        $ip_repr($repr{
                            src_addr:  $unspecified,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }).lower(&[IpCidr::new($ip_addr(ip_addr_a), 24)]),
                        Some($ip_repr($repr{
                            src_addr:  ip_addr_a,
                            dst_addr:  ip_addr_b,
                            $nxthdr:   proto,
                            hop_limit: 64,
                            payload_len
                        }))
                    );
                }
            }
        };
        (ipv4 $addr_bytes_a:expr, $addr_bytes_b:expr) => {
            generate_common_tests!(ipv4, Ipv4Repr, Repr::Ipv4, IpAddress::Ipv4,
                                   Ipv4Address::from_bytes, protocol, $addr_bytes_a,
                                   $addr_bytes_b, Ipv4Address::UNSPECIFIED);
        };
        (ipv6 $addr_bytes_a:expr, $addr_bytes_b:expr) => {
            generate_common_tests!(ipv6, Ipv6Repr, Repr::Ipv6, IpAddress::Ipv6,
                                   Ipv6Address::from_bytes, next_header, $addr_bytes_a,
                                   $addr_bytes_b, Ipv6Address::UNSPECIFIED);
        }
    }

    generate_common_tests!(ipv4
                           [1, 2, 3, 4],
                           [5, 6, 7, 8]);

    generate_common_tests!(ipv6
                           [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                           [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    #[test]
    #[should_panic(expected = "source and destination IP address families do not match")]
    fn test_lower_between_families() {
        Repr::Unspecified {
            src_addr:  Address::Ipv6(Ipv6Address::UNSPECIFIED),
            dst_addr:  Address::Ipv4(Ipv4Address::UNSPECIFIED),
            protocol:  IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: 0
        }.lower(&[]);
    }

    #[test]
    fn endpoint_unspecified() {
        assert!(!Endpoint::UNSPECIFIED.is_specified());
    }

    #[test]
    fn to_prefix_len_ipv4() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(
                Some(prefix_len),
                mask.into().to_prefix_len()
            );
        }

        test_eq(0, Ipv4Address::new(0, 0, 0, 0));
        test_eq(1, Ipv4Address::new(128, 0, 0, 0));
        test_eq(2, Ipv4Address::new(192, 0, 0, 0));
        test_eq(3, Ipv4Address::new(224, 0, 0, 0));
        test_eq(4, Ipv4Address::new(240, 0, 0, 0));
        test_eq(5, Ipv4Address::new(248, 0, 0, 0));
        test_eq(6, Ipv4Address::new(252, 0, 0, 0));
        test_eq(7, Ipv4Address::new(254, 0, 0, 0));
        test_eq(8, Ipv4Address::new(255, 0, 0, 0));
        test_eq(9, Ipv4Address::new(255, 128, 0, 0));
        test_eq(10, Ipv4Address::new(255, 192, 0, 0));
        test_eq(11, Ipv4Address::new(255, 224, 0, 0));
        test_eq(12, Ipv4Address::new(255, 240, 0, 0));
        test_eq(13, Ipv4Address::new(255, 248, 0, 0));
        test_eq(14, Ipv4Address::new(255, 252, 0, 0));
        test_eq(15, Ipv4Address::new(255, 254, 0, 0));
        test_eq(16, Ipv4Address::new(255, 255, 0, 0));
        test_eq(17, Ipv4Address::new(255, 255, 128, 0));
        test_eq(18, Ipv4Address::new(255, 255, 192, 0));
        test_eq(19, Ipv4Address::new(255, 255, 224, 0));
        test_eq(20, Ipv4Address::new(255, 255, 240, 0));
        test_eq(21, Ipv4Address::new(255, 255, 248, 0));
        test_eq(22, Ipv4Address::new(255, 255, 252, 0));
        test_eq(23, Ipv4Address::new(255, 255, 254, 0));
        test_eq(24, Ipv4Address::new(255, 255, 255, 0));
        test_eq(25, Ipv4Address::new(255, 255, 255, 128));
        test_eq(26, Ipv4Address::new(255, 255, 255, 192));
        test_eq(27, Ipv4Address::new(255, 255, 255, 224));
        test_eq(28, Ipv4Address::new(255, 255, 255, 240));
        test_eq(29, Ipv4Address::new(255, 255, 255, 248));
        test_eq(30, Ipv4Address::new(255, 255, 255, 252));
        test_eq(31, Ipv4Address::new(255, 255, 255, 254));
        test_eq(32, Ipv4Address::new(255, 255, 255, 255));
    }

    #[test]
    fn to_prefix_len_ipv4_error() {
        assert_eq!(None, IpAddress::from(Ipv4Address::new(255,255,255,1)).to_prefix_len());
    }

    #[test]
    fn to_prefix_len_ipv6() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(
                Some(prefix_len),
                mask.into().to_prefix_len()
            );
        }

        test_eq(0, Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0));
        test_eq(128, Ipv6Address::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff));
    }

    #[test]
    fn to_prefix_len_ipv6_error() {
        assert_eq!(None, IpAddress::from(Ipv6Address::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 1)).to_prefix_len());
    }
}
