//! Receiving and sending ARP messages
use crate::wire::Payload;

mod endpoint;
mod packet;
#[cfg(test)]
mod tests;

pub use endpoint::{Endpoint, Receiver, Sender};

pub use packet::{Handle, In as InPacket, Init, Out as OutPacket, Raw as RawPacket};

pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: InPacket<P>);
}

pub trait Send<P: Payload> {
    fn send(&mut self, raw: RawPacket<P>);
}
