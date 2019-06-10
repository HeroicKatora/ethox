use crate::layer::{Error, Result, eth};
use crate::nic::Info;
use crate::time::Instant;
use crate::wire::{Checksum, EthernetAddress, EthernetFrame, EthernetProtocol};
use crate::wire::{Reframe, Payload, PayloadMut, PayloadResult, payload};
use crate::wire::{IpAddress, IpCidr, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet};

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: IpPacket<'a, P>,
}

pub struct RawPacket<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
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
    pub src_mask: IpCidr,
    pub dst_addr: IpAddress,
    pub protocol: IpProtocol,
    pub payload: usize,
}

/// Source and destination chosen for a particular routing.
pub(crate) struct Route {
    pub next_hop: IpAddress,
    pub src_addr: IpAddress,
}

struct EthRoute {
    next_mac: EthernetAddress,
    src_addr: IpAddress,
}

/// The interface to the endpoint.
pub(crate) trait Endpoint{
    fn route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route>;
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

    /// Get the hardware info for that packet.
    pub fn info(&self) -> &Info {
        self.eth.info()
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn borrow_mut(&mut self) -> Handle {
        Handle {
            eth: self.eth.borrow_mut(),
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

    /// Called last after having initialized the payload.
    pub fn send(mut self) -> Result<()>
        where P: PayloadMut,
    {
        let capabilities = self.handle.info().capabilities();
        match &mut self.packet {
            IpPacket::V4(ipv4) => {
                // Recalculate the checksum if necessary.
                ipv4.fill_checksum(capabilities.ipv4().tx_checksum());
            },
            _ => (),
        }
        let lower = eth::Packet::new(
            self.handle.eth,
            self.packet.into_inner());
        lower.send()
    }
}

impl<'a, P: Payload + PayloadMut> RawPacket<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        RawPacket {
            handle,
            payload,
        }
    }

    fn route_to(&mut self, dst_addr: IpAddress) -> Result<EthRoute> {
        let now = self.handle.eth.info().timestamp();
        let Route { next_hop, src_addr } = self.handle.endpoint
            .route(dst_addr, now)
            .ok_or(Error::Unreachable)?;
        let next_mac = self.handle.eth.resolve(next_hop)?;

        Ok(EthRoute {
            next_mac,
            src_addr,
        })
    }

    /// Initialize to a valid ip packet.
    pub fn prepare(mut self, init: Init) -> Result<Packet<'a, P>> {
        let route = self.route_to(init.dst_addr)?;

        let mut lower = eth::RawPacket::new(
            self.handle.eth,
            self.payload);

        let src_addr = lower.src_addr();
        let lower_init = eth::Init {
            src_addr,
            dst_addr: route.next_mac,
            ethertype: match init.dst_addr {
                IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
                _ => return Err(Error::Illegal),
            },
            payload: init.payload + 20, // FIXME: hard coded length.
        };

        let mut prepared = lower.prepare(lower_init)?;
        let repr = init.initialize(route.src_addr, &mut prepared.frame)?;

        // Reconstruct the handle.
        let handle = Handle::new(prepared.handle, self.handle.endpoint);

        Ok(Packet {
            handle,
            packet: IpPacket::new_unchecked(prepared.frame, repr),
        })
    }
}

impl Init {
    fn initialize<P: PayloadMut>(&self, src_addr: IpAddress, payload: &mut P) -> Result<IpRepr> {
        let repr = IpRepr::Unspecified {
            src_addr,
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
            IpPacket::V6(_packet) => unimplemented!("Need to rework ipv6 repr first"),
        }
    }

    pub fn into_inner(self) -> EthernetFrame<&'a mut P> {
        match self {
            IpPacket::V4(packet) => packet.into_inner(),
            IpPacket::V6(packet) => packet.into_inner(),
        }
    }

    pub fn into_raw(self) -> &'a mut P {
        self.into_inner().into_inner()
    }
}

impl<'a, P: Payload> Payload for IpPacket<'a, P> {
    fn payload(&self) -> &payload {
        match self {
            IpPacket::V4(packet) => packet.payload(),
            IpPacket::V6(_packet) => unimplemented!("TODO"),
        }
    }
} 

impl<'a, P: PayloadMut> PayloadMut for IpPacket<'a, P> {
    fn payload_mut(&mut self) -> &mut payload {
        match self {
            IpPacket::V4(packet) => packet.payload_mut(),
            IpPacket::V6(_packet) => unimplemented!("TODO"),
        }
    }

    fn resize(&mut self, length: usize) -> PayloadResult<()> {
        match self {
            IpPacket::V4(packet) => packet.resize(length),
            IpPacket::V6(_packet) => unimplemented!("TODO"),
        }
    }

    fn reframe(&mut self, frame: Reframe) -> PayloadResult<()> {
        match self {
            IpPacket::V4(packet) => packet.reframe(frame),
            IpPacket::V6(_packet) => unimplemented!("TODO"),
        }
    }
} 
