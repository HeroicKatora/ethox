//! Encapsulates a network interface card.
//!
//! Also permits software emulation or implementation of one as well, of course.
pub mod common;
pub mod loopback;
pub mod external;
mod personality;

use crate::wire::Payload;
use crate::layer::Result;

pub use self::personality::{
    Capabilities,
    Personality,
    Protocol};

/// A reference to memory holding packet data and a handle.
///
/// The `Payload` is as an interfance into internal library types for packet parsing while the
/// `Handle` is an interface to the device to provide operations for packet handling.
pub struct Packet<'a, H, P>
where
    H: Handle + ?Sized + 'a,
    P: Payload + ?Sized + 'a,
{
    pub handle: &'a mut H,
    pub payload: &'a mut P,
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
    type Handle: Handle + ?Sized + 'a;
    type Payload: Payload + ?Sized + 'a;

    /// A description of the device.
    ///
    /// Could be dynamically configured but the optimizer and the user is likely happier if the
    /// implementation does not take advantage of this fact.
    fn personality(&self) -> Personality;

    fn tx(&mut self, max: usize, sender: impl Send<Self::Handle, Self::Payload>)
        -> Result<usize>;

    fn rx(&mut self, max: usize, receptor: impl Recv<Self::Handle, Self::Payload>)
        -> Result<usize>;
}

pub trait Recv<H: Handle + ?Sized, P: Payload + ?Sized> {
    /// Receive a single packet.
    ///
    /// Some `Packet` types will allow you not only to access but also modify their contents (i.e.
    /// they also implement `AsMut<[u8]>`
    fn receive(&mut self, packet: Packet<H, P>);

    /// Vectored receive.
    ///
    /// The default implementation will simply receive all packets in sequence.
    fn receivev<'a>(&mut self, packets: impl IntoIterator<Item=Packet<'a, H, P>>)
        where P: 'a, H: 'a
    {
        for packet in packets.into_iter() {
            self.receive(packet);
        }
    }
}

pub trait Send<H: Handle + ?Sized, P: Payload + ?Sized> {
    fn send(&mut self, packet: Packet<H, P>);

    fn sendv<'a>(&mut self, packets: impl IntoIterator<Item=Packet<'a, H, P>>)
        where P: 'a, H: 'a
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

    impl<H, P> Recv<H, P> for LengthIo
        where H: Handle + ?Sized, P: Payload + ?Sized,
    {
        fn receive(&mut self, packet: Packet<H, P>) {
            let bytes = self.signature(&packet.payload);
            for (p, b) in packet.payload.payload().as_slice().iter().zip(bytes.iter().cycle()) {
                assert!(p == b)
            }
        }
    }

    impl<H, P> Send<H, P> for LengthIo 
        where H: Handle + ?Sized, P: Payload + PayloadMut + ?Sized,
    {
        fn send(&mut self, packet: Packet<H, P>) {
            let bytes = self.signature(&packet.payload);
            for (p, b) in packet.payload.payload_mut().as_mut_slice().iter_mut().zip(bytes.iter().cycle()) {
                *p = *b;
            }
            assert_eq!(packet.handle.queue(), Ok(()));
        }
    }
}
