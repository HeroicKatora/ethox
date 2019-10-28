//! The ethernet layer.
use crate::wire::{Payload};
#[cfg(feature = "std")]
use crate::wire::{Formatter, PrettyPrinter, ethernet_frame};

mod endpoint;
mod packet;

pub use endpoint::{
    Endpoint,
    Receiver,
    Sender,
};

// Re-export arp as a utility.
pub use crate::layer::arp::{
    Neighbor,
    NeighborAnswer,
    NeighborMapping,
    NeighborCache,
    NeighborTable,
};

pub use packet::{
    Handle,
    Init,
    In as InPacket,
    Out as OutPacket,
    Raw as RawPacket,
};

pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: InPacket<P>);
}

pub trait Send<P: Payload> {
    fn send(&mut self, raw: RawPacket<P>);
}

/// Available only on `std` because it prints to standard out.
#[cfg(feature = "std")]
impl<P: Payload> Recv<P> for Formatter<ethernet_frame> {
    fn receive(&mut self, frame: InPacket<P>) {
        let printer = PrettyPrinter::<ethernet_frame>::print(&frame.frame);
        eprintln!("{}", printer);
    }
}
