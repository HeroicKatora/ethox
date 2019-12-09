//! The IP layer.
//!
//! Abstract a way to control the routing layer for data protocol on top. This also accepts some
//! ancillary other protocols beside IPv4 and IPv6 to support address configuration management.
//! Currently, this means ARP for IPv4.
//!
//! There is a possible distinction between IPv4 and IPv6 traffic by matching the enum [`IpPacket`]
//! into its variants. There is *no* implied mapping between protocols and no rewriting of packets
//! within the buffer, however the layer implementation tries to offer several abstractions that
//! make this distinction transparent. It hence uses a common, comparable representation for ip
//! addresses ([`IpAddress`]) and a unified [`Init`] structure. This generally enables the layer to
//! transparently dispatch into the desired underlying layer.
//!
//! It does **not yet** provide (transparent) fragment reassembly.
//!
//! ## Structure
//!
//! The IP endpoint stores both routing information and a link-local neighborhood cache. This
//! enables it to match received packet destinations against the configured addresses of the
//! network device and to find next hops for transmitted packets.
//!
//! ## Receiving packets
//!
//! The IP endpoint acts as an ethernet receiver. Note that it not only processes IP packets but
//! also ARP traffic and other relevant protocols for neighbor discovery. (In IPv6 this would also
//! refer to some protocols wrapped into IPv6 but these have not yet been implemented).
//!
//! For all other packets the destination addresses are checked against the configured addresses of
//! the receiving endpoint. They are subsequently forwarded to the upper layer handler.
//!
//! ## Transmitting packets
//!
//! The basics of transmission work just like described in the general layer structure. A raw
//! packet buffer is initialized with the help of the endpoint and an [`Init`] descriptor of both
//! the header data and payload. The source address is selected automatically or provided by the
//! user, in which case it is *not* checked against the configured addresses. The layer will
//! translate the desired destination address to a corresponding next hop. Control over extension
//! headers *is not* supported (but you could rewrite the packet buffer after initialization
//! yourself).
//!
//! Note that the configured next hop might be missing a resolved link-layer address. In this case,
//! the init call will return an error but the request for this resolution is stored in an internal
//! table. The IP layer will send a probe as soon as possible, which is subject to both a packet
//! buffer begin available and an internal rate limit. Only buffers that are not used for the
//! purpose of neighbor discovery are available to the upper layers.
//!
//! [`Init`]: struct.Init.html
//! [`IpAddress`]: ../../wire/enum.IpAddress.html
//! [`IpPacket`]: enum.IpPacket.html
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

/// A IP receiver.
///
/// Processes incoming TCP traffic and automatic answers and is encouraged to generate additional
/// packets when the buffer is not needed for protocol internal messages.
pub trait Recv<P: Payload> {
    /// Inspect one incoming packet buffer.
    ///
    /// The packet might be IPv4 or IPv6 traffic.
    fn receive(&mut self, frame: InPacket<P>);
}


/// An IP sender.
///
/// Utilize raw packet buffers to generate IP encapsulated packets with control over options,
/// flags, and other extensions.
pub trait Send<P: Payload> {
    /// Fill in one available packet buffer.
    ///
    /// Utilize one of the methods to query routes or let `Init` do all the work of filling the
    /// packets from the configured existing ones. Directly modifying the endpoint could instead be
    /// done outside the `Send` trait but a few methods are available as well.
    fn send(&mut self, raw: RawPacket<P>);
}

pub(crate) use endpoint::Routing;

impl<P: Payload, E> Recv<P> for &'_ mut E
    where E: Recv<P>
{
    fn receive(&mut self, frame: InPacket<P>) {
        (**self).receive(frame)
    }
}

impl<P: Payload, E> Send<P> for &'_ mut E
    where E: Send<P>
{
    fn send(&mut self, frame: RawPacket<P>) {
        (**self).send(frame)
    }
}
