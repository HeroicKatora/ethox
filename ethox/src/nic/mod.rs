//! Encapsulates a network interface card.
//!
//! Also permits software emulation or implementation of one as well, of course.
pub mod common;
pub mod loopback;
pub mod external;
mod personality;

#[cfg(feature = "sys")]
#[path="sys/mod.rs"]
mod sys_internal;

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
pub use self::sys_internal::exports as sys;

pub use crate::layer::loss::{Lossy, PrngLoss};

/// A reference to memory holding packet data and a handle.
///
/// The `Payload` is as an interface into internal library types for packet parsing while the
/// `Handle` is an interface to the device to provide operations for packet handling.
pub struct Packet<'a, H, P>
where
    H: Handle + ?Sized + 'a,
    P: Payload + ?Sized + 'a,
{
    /// A control handle to the network interface and current buffer.
    pub handle: &'a mut H,
    /// One buffer containing an Ethernet frame.
    pub payload: &'a mut P,
}

/// A controller for the network operations of the payload buffer.
///
/// Provides the meta data of the payload. This trait is split from the main payload since it must
/// be possible to use its method even while the payload itself is borrowed (e.g. within a parsed
/// packet representation).
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

/// The metadata associated with a packet buffer.
///
/// This is the central source of information for the ethox implementation that can be customized
/// by the network interface. The data can differ per buffer, although certain constraints should
/// hold such as the timestamp should also be monotonically increasing. Violating them is not a
/// memory safety concern but could hinder forward progress or harm performance, trough discarded
/// caches or otherwise.
pub trait Info {
    /// The reference time stamp for this packet.
    fn timestamp(&self) -> Instant;

    /// Capabilities used for the packet.
    ///
    /// Indicates pre-checked checksums for incoming packets and hardware support for checksums of
    /// outgoing packets across the layers of the network stack.
    fn capabilities(&self) -> Capabilities;
}

/// A layer 2 device.
pub trait Device {
    /// The control handle type also providing packet meta information.
    type Handle: Handle + ?Sized;
    /// The payload buffer type of this device.
    ///
    /// It can be an owning buffer such as `Vec<u8>` or a non-owning buffer or even only emulate a
    /// buffer containing an Ethernet packet. Note that the buffer trait should stay a type
    /// parameter so that upper layers can make use of additional methods and not be constrained to
    /// the `Payload` trait. (Although smart use of `Any` might in some cases suffice in a real,
    /// specific network stack that is not this library).
    type Payload: Payload + ?Sized;

    /// A description of the device.
    ///
    /// Could be dynamically configured but the optimizer and the user is likely happier if the
    /// implementation does not take advantage of this fact.
    fn personality(&self) -> Personality;

    /// Transmit some packets utilizing the `sender`.
    ///
    /// Up to `max` packet buffers are chosen by the device. They are provided to the sender callback
    /// which may initialize their contents and decide to queue them. Afterwards, the device is
    /// responsible for cleaning up unused buffers and physically sending queued buffers.
    fn tx(&mut self, max: usize, sender: impl Send<Self::Handle, Self::Payload>)
        -> Result<usize>;

    /// Receive packet utilizing the `receptor`.
    ///
    /// Dequeue up to `max` received packets and provide them to the receiver callback.
    fn rx(&mut self, max: usize, receiver: impl Recv<Self::Handle, Self::Payload>)
        -> Result<usize>;
}

/// A raw network packet receiver.
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

/// A raw network packet sender.
pub trait Send<H: Handle + ?Sized, P: Payload + ?Sized> {
    /// Fill a single packet for sending.
    fn send(&mut self, packet: Packet<H, P>);

    /// Vectored sending.
    ///
    /// The default implementation will simply send all packets in sequence.
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
    pub(crate) struct LengthIo;

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
