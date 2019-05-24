use crate::layer::{Error, Result};
use crate::wire::{EthernetAddress, IpAddress, IpRepr, Ipv4Packet, Ipv6Packet, Payload, PayloadMut};
use crate::nic;

use crate::layer::eth;

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: IpPacket<'a, P>,
}

pub struct RawPacket<'a, P: Payload> {
    init: Init,
    payload: &'a mut P,
}

pub struct Handle<'a> {
    eth: eth::Handle<'a>,
    endpoint: &'a mut (Endpoint + 'a),
}

pub enum IpPacket<'a, P: Payload> {
    V4(Ipv4Packet<&'a mut P>),
    // TODO: not yet converted.
    // V6(Ipv6Packet<&'a mut P>),
}

/// Initializer for a packet.
pub struct Init {
    pub from: IpAddress,
    pub to: Option<IpAddress>,
    pub payload: usize,
}

/// The interface to the endpoint.
pub(crate) trait Endpoint{
    fn init(&mut self) -> Init;
    fn resolve(&mut self, _: IpAddress) -> Result<EthernetAddress>;
}

