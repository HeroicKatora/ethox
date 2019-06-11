//! The udp layer.
//!
//! The central layer does not contain routing logic to ports but merely extracts that information.
//! A separate routing layer for upper layer services utilizes port information. This makes it
//! possible to respond dynamically at any port without settting up logic prior to a packet
//! arriving (e.g. dynamic port knocking) but also simplifies implementation by enforcing clear cut
//! separation of concerns.

mod endpoint;
mod packet;

pub use packet::{
    Handle,
    Init,
    Packet,
    RawPacket,
};
