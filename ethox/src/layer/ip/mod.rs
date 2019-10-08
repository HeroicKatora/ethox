//! The ip layer.
//!
//! Abstract a way to control the routing layer for data protocol on top. This also accepts some
//! ancillary other protocols beside IPv4 and IPv6 to support address configuration management.
//! Currently, this means ARP for IPv4.
//!
//! There is a possible distinction between ip4 and ip6 traffic by matching the enum [`IpPacket`]
//! into its variants, however the layer implementation tries to offer several abstractions that
//! make this distinction transparent. It hence uses a common, comparable representation for ip
//! addresses ([`IpAddress`]) and a unified [`Init`] structure. This generally enables the layer to
//! transparently dispatch into the desired underlying layer.
//!
//! It does **not yet** provide transparent fragment reassembly.
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

pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: InPacket<P>);
}

pub trait Send<P: Payload> {
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
