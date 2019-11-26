//! The udp layer.
//!
//! The central layer does not contain routing logic to ports but merely extracts that information.
//! A separate routing layer for upper layer services utilizes port information. This makes it
//! possible to respond dynamically at any port without settting up logic prior to a packet
//! arriving (e.g. dynamic port knocking) but also simplifies implementation by enforcing clear cut
//! separation of concerns.
use crate::wire::Payload;

mod endpoint;
mod packet;
#[cfg(test)]
mod tests;

pub use endpoint::{
    Endpoint,
    Receiver,
    Sender,
};

pub use packet::{
    Handle,
    Init,
    Packet,
    RawPacket,
};

/// A UDP receiver.
///
/// Processes incoming UDP packets of all addresses and ports. Should contain some internal
/// mechanism to distribute these.
pub trait Recv<P: Payload> {
    /// Inspect one incoming packet buffer.
    ///
    /// Contains a parsed representation of a UDP packet on top of some IP and Ethernet layers.
    /// Also a control handle to the UDP endpoint to answer directly.
    fn receive(&mut self, frame: Packet<P>);
}

/// A TCP sender.
///
/// Utilize raw packet buffers and a UDP endpoint to fill valid packets.
pub trait Send<P: Payload> {
    /// Fill in one available packet buffer.
    fn send(&mut self, raw: RawPacket<P>);
}
