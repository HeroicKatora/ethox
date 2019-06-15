// FIXME: make most of these methods `const` as soon as possible.
use crate::wire::{Checksum, IpRepr, UdpChecksum};

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

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

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
        }
    }

    pub fn icmpv4(&self) -> &Protocol {
        &self.icmpv4
    }

    pub fn ipv4(&self) -> &Protocol {
        &self.ipv4
    }

    pub fn ipv4_mut(&mut self) -> &mut Protocol {
        &mut self.ipv4
    }

    pub fn udp(&self) -> &Udp {
        &self.udp
    }

    pub fn udp_mut(&mut self) -> &mut Udp {
        &mut self.udp
    }
}

impl Protocol {
    pub fn no_support() -> Self {
        Protocol {
            send: Checksum::Manual,
            receive: Checksum::Manual,
        }
    }

    pub fn rx_checksum(&self) -> Checksum {
        self.receive
    }

    pub fn rx_checksum_mut(&mut self) -> &mut Checksum {
        &mut self.receive
    }

    pub fn tx_checksum(&self) -> Checksum {
        self.send
    }

    pub fn tx_checksum_mut(&mut self) -> &mut Checksum {
        &mut self.send
    }
}

impl Udp {
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

/// `Protocol` is a simplified version.
impl From<Protocol> for Udp {
    fn from(inner: Protocol) -> Self {
        Udp {
            inner,
        }
    }
}
