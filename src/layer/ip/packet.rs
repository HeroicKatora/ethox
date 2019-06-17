use crate::layer::{Error, Result, eth};
use crate::nic::Info;
use crate::time::Instant;
use crate::wire::{Checksum, EthernetAddress, EthernetFrame, EthernetProtocol};
use crate::wire::{Reframe, Payload, PayloadMut, PayloadResult, payload};
use crate::wire::{IpAddress, IpCidr, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet};

/// An incoming packet.
///
/// The contents were inspected and could be handled up to the ip layer.
pub struct In<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: IpPacket<'a, P>,
}

/// An outgoing packet as prepared by the ip layer.
///
/// While the layers below have been initialized, the payload of the packet has not. Fill it by
/// grabbing the mutable slice for example.
pub struct Out<'a, P: Payload> {
    handle: Handle<'a>,
    packet: IpPacket<'a, P>,
}

/// A buffer into which a packet can be placed.
pub struct Raw<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
}

pub struct Handle<'a> {
    eth: eth::Handle<'a>,
    endpoint: &'a mut (Endpoint + 'a),
}

pub type V4Packet<'a, P> = Ipv4Packet<EthernetFrame<&'a mut P>>;
pub type V6Packet<'a, P> = Ipv6Packet<EthernetFrame<&'a mut P>>;

pub enum IpPacket<'a, P: Payload> {
    V4(V4Packet<'a, P>),
    V6(V6Packet<'a, P>),
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

#[derive(Clone, Copy)]
struct EthRoute {
    next_mac: EthernetAddress,
    src_addr: IpAddress,
    dst_addr: IpAddress,
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

    fn route_to(&mut self, dst_addr: IpAddress) -> Result<EthRoute> {
        let now = self.eth.info().timestamp();
        let Route { next_hop, src_addr } = self.endpoint
            .route(dst_addr, now)
            .ok_or(Error::Unreachable)?;
        let next_mac = self.eth.resolve(next_hop)?;

        Ok(EthRoute {
            next_mac,
            src_addr,
            dst_addr,
        })
    }

    fn init_eth(&mut self, route: EthRoute, payload: usize) -> Result<eth::Init> {
        let eth_init = eth::Init {
            src_addr: self.eth.src_addr(),
            dst_addr: route.next_mac,
            ethertype: match route.dst_addr {
                IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
                _ => return Err(Error::Illegal),
            },
            payload: payload + 20, // FIXME: hard coded length.
        };
        Ok(eth_init)
    }
}

impl<'a, P: Payload> In<'a, P> {
    /// Deconstruct the packet into the reusable buffer.
    pub fn deinit(self) -> Raw<'a, P>
        where P: PayloadMut,
    {
        Raw::new(self.handle, self.packet.into_raw())
    }
}

impl<'a, P: PayloadMut> In<'a, P> {
    pub fn reinit(mut self, init: Init) -> Result<Out<'a, P>> {
        let route = self.handle.route_to(init.dst_addr)?;
        let lower_init = self.handle.init_eth(route, init.payload)?;

        let new_repr = init.ip_repr(route.dst_addr);
        let raw_repr = self.packet.repr();

        let eth_packet = eth::InPacket {
            handle: self.handle.eth,
            frame: self.packet.into_inner(),
        };

        let packet = eth_packet.reinit(lower_init)?;
        let eth::InPacket { handle, mut frame } = packet.into_incoming();
        let repr = init.initialize(route.src_addr, &mut frame)?;

        // Reconstruct the handle.
        let handle = Handle::new(handle, self.handle.endpoint);

        Ok(Out {
            handle,
            packet: IpPacket::new_unchecked(frame, repr),
        })
    }
}

impl<'a, P: Payload> Out<'a, P> {
    /// Pretend the packet has been initialized by the ip layer.
    ///
    /// This is fine to call if a previous call to `into_incoming` was used to destructure the
    /// initialized packet and its contents have not changed. Some changes are fine as well and
    /// nothing will cause unsafety but panics or dropped packets are to be expected.
    pub fn new_unchecked(
        handle: Handle<'a>,
        packet: IpPacket<'a, P>) -> Self
    {
        Out { handle, packet, }
    }

    /// Unwrap the contained control handle and initialized ethernet frame.
    pub fn into_incoming(self) -> In<'a, P> {
        let Out { handle, packet } = self;
        In { handle, packet }
    }
}

impl<'a, P: PayloadMut> Out<'a, P> {
    /// Called last after having initialized the payload.
    ///
    /// This will also take care of filling the checksums as required.
    pub fn send(mut self) -> Result<()> {
        let capabilities = self.handle.info().capabilities();
        match &mut self.packet {
            IpPacket::V4(ipv4) => {
                // Recalculate the checksum if necessary.
                ipv4.fill_checksum(capabilities.ipv4().tx_checksum());
            },
            _ => (),
        }
        let lower = eth::OutPacket::new_unchecked(
            self.handle.eth,
            self.packet.into_inner());
        lower.send()
    }

    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        self.packet.payload_mut().as_mut_slice()
    }
}

impl<'a, P: Payload + PayloadMut> Raw<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        Raw {
            handle,
            payload,
        }
    }

    /// Initialize to a valid ip packet.
    pub fn prepare(mut self, init: Init) -> Result<Out<'a, P>> {
        let route = self.handle.route_to(init.dst_addr)?;
        let lower_init = self.handle.init_eth(route, init.payload)?;

        let lower = eth::RawPacket::new(
            self.handle.eth,
            self.payload);

        let packet = lower.prepare(lower_init)?;
        let eth::InPacket { handle, mut frame } = packet.into_incoming();
        let repr = init.initialize(route.src_addr, &mut frame)?;

        // Reconstruct the handle.
        let handle = Handle::new(handle, self.handle.endpoint);

        Ok(Out {
            handle,
            packet: IpPacket::new_unchecked(frame, repr),
        })
    }
}

impl Init {
    fn initialize(&self, src_addr: IpAddress, payload: &mut impl PayloadMut) -> Result<IpRepr> {
        let repr = self.ip_repr(src_addr)?;
        // Emit the packet but ignore the checksum for now. it is filled in later when calling
        // `OutPacket::send`.
        repr.emit(payload.payload_mut().as_mut_slice(), Checksum::Ignored);
        Ok(repr)
    }

    /// Resolve the ip representation without initializing the packet.
    fn ip_repr(&self, src_addr: IpAddress) -> Result<IpRepr> {
        let repr = IpRepr::Unspecified {
            src_addr,
            dst_addr: self.dst_addr,
            hop_limit: u8::max_value(),
            protocol: self.protocol,
            payload_len: self.payload,
        };
        repr.lower(&[]).ok_or(Error::Illegal)
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
