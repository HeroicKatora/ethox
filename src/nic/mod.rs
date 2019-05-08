//! Encapsulates a network interface card.
//!
//! Also permits software emulation or implementation of one as well, of course.
pub mod common;
pub mod loopback;
pub mod external;
mod personality;

use crate::wire::Payload;
use crate::endpoint::{Error, Result};

pub use self::personality::{
    Capabilities,
    Personality,
    Protocol};

/// A reference to memory holding packet data and a handle.
///
/// The `Payload` is as an interfance into internal library types for packet parsing while the
/// `Handle` is an interface to the device to provide operations for packet handling.
pub trait Packet<'a> {
    /// The inner interface into deciding the packet's processing.
    type Handle: Handle + 'a;

    /// Handle to the contained payload.
    type Payload: Payload + ?Sized + 'a;

    /// It must be possible to access handle and payload simultaneously.
    ///
    /// Note that while the reference to the payload must be mutable, the payload itself must not
    /// be a reference to mutable data.
    fn separate(self) -> (Self::Handle, &'a mut Self::Payload);
}

pub trait Handle {
    /// Queue this packet to be sent.
    ///
    /// This operation may fail for cards that can only send packets that have been previously
    /// allocated for that specific purpose and can, for lack of logic for this, not implement
    /// ad-hoc allocation for this purpose. Another reason for failure is simply a lack of
    /// resources to queue the packet.
    fn queue(&mut self) -> Result<()>;
}

pub trait Device<'a> {
    /// A description of the device.
    ///
    /// Could be dynamically configured but the optimizer and the user is likely happier if the
    /// implementation does not take advantage of this fact.
    fn personality(&self) -> Personality;
}

pub trait Recv<'a, P: Packet<'a>> {
    /// Receive a single packet.
    ///
    /// Some `Packet` types will allow you not only to access but also modify their contents (i.e.
    /// they also implement `AsMut<[u8]>`
    fn receive(&mut self, packet: P);

    /// Vectored receive.
    ///
    /// The default implementation will simply receive all packets in sequence.
    fn receivev(&mut self, packets: impl IntoIterator<Item=P>)
        where P: Sized,
    {
        for packet in packets.into_iter() {
            self.receive(packet);
        }
    }
}

pub trait Send<'a, P: Packet<'a>> {
    fn send(&mut self, packet: P);

    fn sendv(&mut self, packets: impl IntoIterator<Item=P>)
        where P: Sized,
    {
        for packet in packets.into_iter() {
            self.send(packet)
        }
    }
}

/// Some base types and methods for other tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::PayloadMut;

    /// Sender and receiver verifying packet lengths.
    #[derive(Copy, Clone)]
    pub struct LengthIo;

    impl LengthIo {
        fn signature<P: Payload + ?Sized>(&mut self, payload: &P) -> [u8; 8] {
            payload.payload()
                .as_slice()
                .len()
                .to_le_bytes()
        }
    }

    impl<'a, P: Packet<'a>> Recv<'a, P> for LengthIo {
        fn receive(&mut self, packet: P) {
            let (_, payload) = packet.separate();
            let bytes = self.signature(payload);
            for (p, b) in payload.payload().as_slice().iter().zip(bytes.iter().cycle()) {
                assert!(p == b)
            }
        }
    }

    impl<'a, P: Packet<'a>> Send<'a, P> for LengthIo 
        where P::Payload: PayloadMut
    {
        fn send(&mut self, packet: P) {
            let (mut handle, payload) = packet.separate();
            let bytes = self.signature(payload);
            for (p, b) in payload.payload_mut().as_mut_slice().iter_mut().zip(bytes.iter().cycle()) {
                *p = *b;
            }
            assert_eq!(handle.queue(), Ok(()));
        }
    }
}
