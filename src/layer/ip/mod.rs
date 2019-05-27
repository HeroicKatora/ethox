//! The ip layer.
//!
//! While there is a possible distinction between ip4 and ip6 traffic, the layer implementation
//! tries to offer several abstractions that make this distinction less noticable. At least it
//! might some day.
// mod route;
use crate::wire::Payload;

mod packet;
mod route;

pub use packet::{
    Packet,
    RawPacket,
};

pub use route::{
    Route,
    Routes,
};

pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: Packet<P>);
}

pub trait Send<P: Payload> {
    fn send(&mut self, raw: RawPacket<P>);
}
