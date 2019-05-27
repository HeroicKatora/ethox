//! The ethernet layer.
use crate::wire::{ethernet_frame, Payload};
use crate::wire::pretty_print::{PrettyPrinter, Formatter};

mod endpoint;
mod neighbor;
mod packet;

pub use endpoint::{
    Endpoint,
    Receiver,
    Sender,
};

pub use neighbor::{
    Neighbor,
    Answer as NeighborAnswer,
    Cache as NeighborCache,
    Table as NeighborTable,
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

/// Available only on `std` because it prints to standard out.
#[cfg(feature = "std")]
impl<P: Payload> Recv<P> for Formatter<ethernet_frame> {
    fn receive(&mut self, frame: Packet<P>) {
        let printer = PrettyPrinter::<ethernet_frame>::print(&frame.frame);
        eprintln!("{}", printer);
    }
}
