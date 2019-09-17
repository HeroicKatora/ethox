//! Encapsulates a network interface card.
//!
//! Also permits software emulation or implementation of one as well, of course.
pub mod common;
pub mod loopback;
pub mod external;
mod personality;
#[cfg(feature = "sys")]
mod sys;

use crate::wire::Payload;
use crate::layer::{Result, FnHandler};
#[cfg(feature = "std")]
use crate::wire::{ethernet_frame, pretty_print::{Formatter, PrettyPrinter}};
use crate::time::Instant;

pub use self::personality::{
    Capabilities,
    Personality,
    Protocol};

#[cfg(feature = "sys")]
pub use self::sys::exports::*;

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

    /// Information on the packet intended for lower layers.
    ///
    /// Note that technically the information may change after a call to `queue` or in the future
    /// after changing the target interface of an outgoing packet. That is intentional.
    fn info(&self) -> &dyn Info;
    // TODO: multiple interfaces (=zerocopy forwarding).
}

pub trait Info {
    /// The reference timestamp for this packet.
    fn timestamp(&self) -> Instant;

    /// Capabilities used for the packet.
    ///
    /// Indicates pre-checked checksums for incoming packets and hardware support for checksums of
    /// outgoing packets across the layers of the network stack.
    fn capabilities(&self) -> Capabilities;
}

pub trait Device {
    type Handle: Handle + ?Sized;
    type Payload: Payload + ?Sized;

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

impl<F, H: Handle + ?Sized, P: Payload + ?Sized> Recv<H, P> for FnHandler<F>
    where F: FnMut(Packet<H, P>)
{
    fn receive(&mut self, packet: Packet<H, P>) {
        (self.0)(packet)
    }
}

impl<F, H: Handle + ?Sized, P: Payload + ?Sized> Send<H, P> for FnHandler<F>
    where F: FnMut(Packet<H, P>)
{
    fn send(&mut self, packet: Packet<H, P>) {
        (self.0)(packet)
    }
}

impl<F, H: Handle + ?Sized, P: Payload + ?Sized> Recv<H, P> for &'_ mut F
    where F: Recv<H, P>
{
    fn receive(&mut self, packet: Packet<H, P>) {
        (**self).receive(packet)
    }

    fn receivev<'a>(&mut self, packets: impl IntoIterator<Item=Packet<'a, H, P>>)
        where P: 'a, H: 'a
    {
        (**self).receivev(packets)
    }
}

impl<F, H: Handle + ?Sized, P: Payload + ?Sized> Send<H, P> for &'_ mut F
    where F: Send<H, P>
{
    fn send(&mut self, packet: Packet<H, P>) {
        (**self).send(packet)
    }

    fn sendv<'a>(&mut self, packets: impl IntoIterator<Item=Packet<'a, H, P>>)
        where P: 'a, H: 'a
    {
        (**self).sendv(packets)
    }
}

/// Available only on `std` because it prints to standard out.
#[cfg(feature = "std")]
impl<H: Handle + ?Sized, P: Payload + ?Sized> Recv<H, P> for Formatter<ethernet_frame> {
    fn receive(&mut self, frame: Packet<H, P>) {
        let printer = PrettyPrinter::<ethernet_frame>
            ::new("", frame.payload.payload().as_slice());
        eprintln!("{}", printer);
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
