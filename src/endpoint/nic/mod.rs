//! Encapsulates a network interface card.
//!
//! Also permits software emulation or implementation of one as well, of course.
mod personality;
mod software;

use super::{Result, Payload};

pub use self::personality::{
    Capabilities,
    Personality,
    Protocol};

pub use self::software::{
    Loopback};

/// A reference to memory holding packet data and a handle.
///
/// The `Payload` is as an interfance into internal library types for packet parsing while the
/// `Handle` is an interface to the device to provide operations for packet handling.
pub trait Packet<'a> {
    /// The inner interface into deciding the packet's processing.
    type Handle: Handle + 'a;

    /// Handle to the contained payload.
    type Payload: Payload + 'a;

    /// It must be possible to access handle and payload simultaneously.
    ///
    /// Note that while the reference to the payload must be mutable, the payload itself must not
    /// be a reference to mutable data.
    fn separate(&'a mut self) -> (&'a mut Self::Handle, &'a mut Self::Payload);
}

pub trait Handle {
    /// Queue this packet to be sent.
    ///
    /// This operation may fail for cards that can only send packets that have been previously
    /// allocated for that specific purpose and can, for lack of logic for this, not implement
    /// ad-hoc allocation for this purpose. Another reason for failure is simply a lack of
    /// resources to queue the packet.
    fn queue(self) -> Result<()>;
}

pub trait Device<'a> {
    type Packet: Packet<'a> + 'a;

    /// A description of the device.
    ///
    /// Could be dynamically configured but the optimizer and the user is likely happier if the
    /// implementation does not take advantage of this fact.
    fn personality(&self) -> Personality;

    /// Receive some packets with the specified receptor.
    ///
    /// Should return the number of processed packets for convenience.
    fn rx<R: Receive<'a, Self::Packet>>(&mut self, max: usize, receptor: R) -> Result<usize>;

    /// Prepare then send some packets with the specified receptor.
    ///
    /// Should return the number of processed packets for convenience.
    fn tx<R: Send<'a, Self::Packet>>(&mut self, max: usize, sender: R) -> Result<usize>;
}

pub trait Receive<'a, P: Packet<'a>> {
    /// Receive a single packet.
    ///
    /// Some `Packet` types will allow you not only to access but also modify their contents (i.e.
    /// they also implement `AsMut<[u8]>`
    fn receive(&mut self, packet: &mut P);

    /// Vectored receive.
    ///
    /// The default implementation will simply receive all packets in sequence.
    fn receivev(&mut self, packets: &mut [P])
        where P: Sized,
    {
        for packet in packets.iter_mut() {
            self.receive(packet);
        }
    }
}

pub trait Send<'a, P: Packet<'a>> {
    fn send(&mut self, packet: &mut P);

    fn sendv(&mut self, packets: &mut [P])
        where P: Sized,
    {
        for packet in packets.iter_mut() {
            self.send(packet)
        }
    }
}
