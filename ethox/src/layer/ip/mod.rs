//! The ip layer.
//!
//! While there is a possible distinction between ip4 and ip6 traffic, the layer implementation
//! tries to offer several abstractions that make this distinction less noticable. At least it
//! might some day.
use crate::wire::Payload;

mod endpoint;
mod packet;
mod route;
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
    IpPacket,
    V4Packet,
    V6Packet,
    In as InPacket,
    Out as OutPacket,
    Raw as RawPacket,
    Source,
};

pub use route::{
    Route,
    Routes,
};

pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: InPacket<P>);
}

pub trait Send<P: Payload> {
    fn send(&mut self, raw: RawPacket<P>);
}

pub(crate) use endpoint::Routing;
