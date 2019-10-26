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

pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: Packet<P>);
}

pub trait Send<P: Payload> {
    fn send(&mut self, raw: RawPacket<P>);
}

impl<P, C> Recv<P> for &'_ mut C
    where P: Payload, C: Recv<P>,
{
    fn receive(&mut self, frame: Packet<P>) {
        (**self).receive(frame)
    }
}

impl<P, C> Send<P> for &'_ mut C
    where P: Payload, C: Send<P>,
{
    fn send(&mut self, frame: RawPacket<P>) {
        (**self).send(frame)
    }
}
