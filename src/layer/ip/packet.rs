use crate::layer::{Error, Result, eth};
use crate::wire::{Checksum, EthernetAddress, EthernetFrame, EthernetProtocol, Payload, PayloadMut};
use crate::wire::{IpAddress, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet};

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: IpPacket<'a, P>,
}

pub struct RawPacket<'a, P: Payload> {
    handle: Handle<'a>,
    init: Option<Init>,
    payload: &'a mut P,
}

pub struct Handle<'a> {
    eth: eth::Handle<'a>,
    endpoint: &'a mut (Endpoint + 'a),
}

pub enum IpPacket<'a, P: Payload> {
    V4(Ipv4Packet<EthernetFrame<&'a mut P>>),
    V6(Ipv6Packet<EthernetFrame<&'a mut P>>),
}

/// Initializer for a packet.
pub struct Init {
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
    pub protocol: IpProtocol,
    pub payload: usize,
}

/// The interface to the endpoint.
pub(crate) trait Endpoint{
}

impl<'a> Handle<'a> {
    pub(crate) fn new(
        handle: eth::Handle<'a>,
        endpoint: &'a mut (Endpoint + 'a),
    ) -> Self {
        Handle {
            eth: handle,
            endpoint,
        }
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn coerce_lifetime<'b>(self) -> Handle<'b> where 'a: 'b {
        Handle {
            eth: self.eth.coerce_lifetime(),
            endpoint: self.endpoint,
        }
    }
}

impl<'a, P: Payload> Packet<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        packet: IpPacket<'a, P>)
    -> Self {
        Packet {
            handle,
            packet,
        }
    }

    pub fn reinit(self) -> RawPacket<'a, P>
        where P: PayloadMut,
    {
        RawPacket::new(self.handle, self.packet.into_raw())
    }
}

impl<'a, P: Payload + PayloadMut> RawPacket<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        RawPacket {
            handle,
            init: None,
            payload,
        }
    }

    pub fn prepare(self) -> Result<Packet<'a, P>> {
        let mut lower = eth::RawPacket::new(
            self.handle.eth,
            self.payload);
        let mut init = self.init.ok_or(Error::Illegal)?;

        let src_addr = lower.src_addr();
        lower.init = Some(eth::Init {
            src_addr,
            dst_addr: EthernetAddress::BROADCAST, //overwritten later
            ethertype: EthernetProtocol::Ipv4, // FIXME: hard coded proto.
            payload: init.payload + 20, // FIXME: hard coded length.
        });
        // Overwrite the dst_addr.
        lower.resolve(init.dst_addr)?;

        let mut prepared = lower.prepare()?;
        let repr = init.initialize(&mut prepared.frame)?;

        // Reconstruct the handle.
        let handle = Handle::new(prepared.handle, self.handle.endpoint);

        Ok(Packet {
            handle,
            packet: IpPacket::new_unchecked(prepared.frame, repr),
        })
    }
}

impl Init {
    fn initialize<P: PayloadMut>(&mut self, payload: &mut P) -> Result<IpRepr> {
        let repr = IpRepr::Unspecified {
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            hop_limit: u8::max_value(),
            protocol: self.protocol,
            payload_len: self.payload,
        };
        let repr = repr.lower(&[])
            .ok_or(Error::Illegal)?;
        // FIXME: recheck the buffer size.
        repr.emit(payload.payload_mut().as_mut_slice(), Checksum::Manual);
        Ok(repr)
    }
}

impl<'a, P: Payload> IpPacket<'a, P> {
    pub fn new_unchecked(inner: EthernetFrame<&'a mut P>, repr: IpRepr) -> Self {
        match repr {
            IpRepr::Ipv4(repr) => IpPacket::V4(Ipv4Packet::new_unchecked(inner, repr)),
            _ => unimplemented!(),
        }
    }

    pub fn repr(&self) -> IpRepr {
        match self {
            IpPacket::V4(packet) => packet.repr().into(),
            IpPacket::V6(packet) => unimplemented!("Need to rework ipv6 repr first"),
        }
    }

    fn into_raw(self) -> &'a mut P {
        match self {
            IpPacket::V4(packet) => packet.into_inner().into_inner(),
            IpPacket::V6(packet) => packet.into_inner().into_inner(),
        }
    }
}
