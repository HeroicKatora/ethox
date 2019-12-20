// FIXME: make most of these methods `const` as soon as possible.
use crate::wire::{Checksum, IpRepr, UdpChecksum, TcpChecksum};

/// A general description of a device.
///
/// The interaction with these happens purely via methods. This leaves the implementation open to
/// additions in the future, primarily concerning support for other protocols with support from
/// significant network cards.
#[derive(Clone, Debug)]
pub struct Personality {
    capabilities: Capabilities,
}

/// Operations supported natively by the card.
///
/// Such as offloading of checksum algorithms, ... The usage for a `Device` is simply to
/// instantiate a baseline with no support for any upper layer and then adjust those for which
/// support can be provided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    ipv4: Protocol,
    icmpv4: Protocol,
    udp: Udp,
    tcp: Tcp,
}

/// The extent of support for a specific protocol.
///
/// This is mostly about checksums in a particular protocol. If at all support, it concerns both
/// directions of packet flow for that protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocol {
    send: Checksum,
    receive: Checksum,
}

/// A specialized instance of `Protocol`.
///
/// This is a different instance since the checksumming behaviour of network cards is much more
/// convoluted here. Until requirements for real cards are evaluated this will stay a wrapper with
/// mostly no additional methods.
///
/// It is possible to create one `From` a `Protocol` instance as `Udp` is a specialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Udp {
    inner: Protocol,
}

/// A specialized instance of `Protocol` for Tcp.
///
/// This is a different instance since the checksumming behaviour of network cards is much more
/// convoluted here. Until requirements for real cards are evaluated this will stay a wrapper with
/// mostly no additional methods.
///
/// It is possible to create one `From` a `Protocol` instance as `Udp` is a specialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tcp {
    inner: Protocol,
}

impl Personality {
    /// A personality with no extras.
    ///
    /// Indicates no support for any upper layer protocols nor does it advertise specific builtin
    /// addressing, it does not even provide serial numbers, or manufacturer details. Populate this
    /// with your own details as you see fit.
    pub fn baseline() -> Self {
        Personality {
            capabilities: Capabilities::no_support(),
        }
    }

    /// Check the capabilities of the interface.
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Mutably get the capabilities which allows for modifications.
    pub fn capabilities_mut(&mut self) -> &mut Capabilities {
        &mut self.capabilities
    }
}

impl Capabilities {
    /// Instantiates capabilities that are completely oblivious to the upper protocol layers.
    ///
    /// This also provides for a useful baseline for adding very specific protocol support.
    pub fn no_support() -> Self {
        Capabilities {
            ipv4: Protocol::no_support(),
            icmpv4: Protocol::no_support(),
            udp: Udp::no_support(),
            tcp: Tcp::no_support(),
        }
    }

    /// Check ICMPv4 support descriptor.
    pub fn icmpv4(&self) -> &Protocol {
        &self.icmpv4
    }

    /// Check IPv4 support descriptor.
    pub fn ipv4(&self) -> &Protocol {
        &self.ipv4
    }

    /// Mutably get IPv4 support descriptor.
    pub fn ipv4_mut(&mut self) -> &mut Protocol {
        &mut self.ipv4
    }

    /// Check UDP support descriptor.
    pub fn udp(&self) -> &Udp {
        &self.udp
    }

    /// Mutably get UDP support descriptor.
    pub fn udp_mut(&mut self) -> &mut Udp {
        &mut self.udp
    }

    /// Check TCP support descriptor.
    pub fn tcp(&self) -> &Tcp {
        &self.tcp
    }

    /// Mutably get TCP support descriptor.
    pub fn tcp_mut(&mut self) -> &mut Tcp {
        &mut self.tcp
    }
}

impl Protocol {
    /// Create a protocol support descriptor without any supported feature.
    ///
    /// This means that the stack needs to perform all checksums manually.
    pub fn no_support() -> Self {
        Protocol {
            send: Checksum::Manual,
            receive: Checksum::Manual,
        }
    }

    /// Expect the underlying nic to do all work automatically.
    ///
    /// This is very unlikely to actually happen (partial checksums or offset are likely required)
    /// but in specialize links it may be pre-determined knowledge that both sides ignore checksums
    /// entirely.
    pub fn offloaded() -> Self {
        Protocol {
            send: Checksum::Ignored,
            receive: Checksum::Ignored,
        }
    }

    /// Get the receive checksum descriptor.
    pub fn rx_checksum(&self) -> Checksum {
        self.receive
    }

    /// Mutably get the receive checksum descriptor.
    pub fn rx_checksum_mut(&mut self) -> &mut Checksum {
        &mut self.receive
    }

    /// Get the transmit checksum descriptor.
    pub fn tx_checksum(&self) -> Checksum {
        self.send
    }

    /// Mutably get the transmit checksum descriptor.
    pub fn tx_checksum_mut(&mut self) -> &mut Checksum {
        &mut self.send
    }
}

impl Udp {
    /// Create a UDP descriptor with no supported features.
    pub fn no_support() -> Self {
        Udp {
            inner: Protocol::no_support(),
        }
    }

    /// Create the `UdpChecksum` instance necessary for sending a header.
    ///
    /// The enum `UdpChecksum` controls when and how the checksum is filled in by the `wire`
    /// portion of the library. This creates an instance which corresponds to the requirements of
    /// the nic.
    pub fn tx_checksum(&self, ip: IpRepr) -> UdpChecksum {
        match self.inner.tx_checksum() {
            Checksum::Manual => UdpChecksum::Lazy {
                src_addr: ip.src_addr(),
                dst_addr: ip.dst_addr(),
            },
            Checksum::Ignored => UdpChecksum::Ignored,
        }
    }

    /// Create the `UdpChecksum` instance necessary for receiving a header.
    ///
    /// The enum `UdpChecksum` controls when and how the checksum is filled in by the `wire`
    /// portion of the library. This creates an instance which corresponds to the requirements of
    /// the nic.
    pub fn rx_checksum(&self, ip: IpRepr) -> UdpChecksum {
        match self.inner.rx_checksum() {
            Checksum::Manual => UdpChecksum::Lazy {
                src_addr: ip.src_addr(),
                dst_addr: ip.dst_addr(),
            },
            Checksum::Ignored => UdpChecksum::Ignored,
        }
    }
}

impl Tcp {
    /// Create a TCP descriptor with no supported features.
    pub fn no_support() -> Self {
        Tcp {
            inner: Protocol::no_support(),
        }
    }

    /// Create the `UdpChecksum` instance necessary for sending a header.
    ///
    /// The enum `UdpChecksum` controls when and how the checksum is filled in by the `wire`
    /// portion of the library. This creates an instance which corresponds to the requirements of
    /// the nic.
    pub fn tx_checksum(&self, ip: IpRepr) -> TcpChecksum {
        match self.inner.tx_checksum() {
            Checksum::Manual => TcpChecksum::Manual {
                src_addr: ip.src_addr(),
                dst_addr: ip.dst_addr(),
            },
            Checksum::Ignored => TcpChecksum::Ignored,
        }
    }

    /// Create the `UdpChecksum` instance necessary for receiving a header.
    ///
    /// The enum `UdpChecksum` controls when and how the checksum is filled in by the `wire`
    /// portion of the library. This creates an instance which corresponds to the requirements of
    /// the nic.
    pub fn rx_checksum(&self, ip: IpRepr) -> TcpChecksum {
        match self.inner.rx_checksum() {
            Checksum::Manual => TcpChecksum::Manual {
                src_addr: ip.src_addr(),
                dst_addr: ip.dst_addr(),
            },
            Checksum::Ignored => TcpChecksum::Ignored,
        }
    }
}

/// `Protocol` may be a simplified version in the future.
impl From<Protocol> for Udp {
    fn from(inner: Protocol) -> Self {
        Udp {
            inner,
        }
    }
}

/// `Protocol` may be a simplified version in the future.
impl From<Protocol> for Tcp {
    fn from(inner: Protocol) -> Self {
        Tcp {
            inner,
        }
    }
}
