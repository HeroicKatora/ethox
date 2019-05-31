// FIXME: make most of these methods `const` as soon as possible.
use crate::wire::Checksum;

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
    udp: Protocol,
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
            udp: Protocol::no_support(),
        }
    }

    pub fn ipv4(&self) -> &Protocol {
        &self.ipv4
    }

    pub fn ipv4_mut(&mut self) -> &mut Protocol {
        &mut self.ipv4
    }

    pub fn udp(&self) -> &Protocol {
        &self.udp
    }

    pub fn udp_mut(&mut self) -> &mut Protocol {
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
