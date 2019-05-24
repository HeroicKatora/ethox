//! The ethernet layer.
use crate::wire::Payload;

mod endpoint;
mod neighbor;
mod packet;

pub use endpoint::{
    Endpoint,
    FnHandler,
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
