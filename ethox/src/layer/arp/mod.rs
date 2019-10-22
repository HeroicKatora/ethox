//! Receiving and sending ARP messages.
//!
//! Restricted to simple use of answering and sending arp based on the required addresses of the
//! ip/ipv4 layer. You might not need to use this directly as it is embedded into the IP layer for
//! its use in IPv4 addressing.
//!
//! Its code could be more generic and might in the future be reused for other protocols.
mod endpoint;
mod neighbor;
mod packet;
#[cfg(test)]
mod tests;

pub use endpoint::{Endpoint, Receiver, Sender};

pub use neighbor::{
    Neighbor,
    Answer as NeighborAnswer,
    Mapping as NeighborMapping,
    Cache as NeighborCache,
    Table as NeighborTable,
};

pub use packet::{Controller, In as InPacket, Init, Out as OutPacket, Raw as RawPacket};
