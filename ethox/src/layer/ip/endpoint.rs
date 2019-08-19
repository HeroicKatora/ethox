use crate::layer::{arp, eth, FnHandler};
use crate::layer::{Error, Result};
use crate::managed::Slice;
use crate::wire::{EthernetAddress, EthernetProtocol, Payload, PayloadMut};
use crate::wire::{IpAddress, IpCidr, IpSubnet, Ipv4Packet, Ipv6Packet};
use crate::time::Instant;

use super::{Recv, Send};
use super::packet::{self, IpPacket, Handle, Route};
use super::route::Routes;

pub struct Endpoint<'a> {
    /// Routing information.
    routing: Routing<'a>,

    /// Internal ipv4/ipv6 arp state.
    arp: arp::Endpoint<'a>,
}

/// Routing information of an ip endpoint.
///
/// Separated in struct such that the arp and other neighborhood protocols can borrow this portion
/// to generate and receive packets but also store their own data in the ip endpoint.
///
/// `'data` is the lifetime of the memory referenced for storing the routing data (address
/// assignments, routing table).
pub(crate) struct Routing<'data> {
    /// Our own address.
    addr: Slice<'data, IpCidr>,

    /// Routing information.
    routes: Routes<'data>,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configurerd here, and not in the endpoint state.
pub struct Receiver<'a, 'data, H> {
    endpoint: IpEndpoint<'a, 'data>,

    /// The upper protocol receiver.
    handler: H,
}

pub struct Sender<'a, 'data, H> {
    endpoint: IpEndpoint<'a, 'data>,

    /// The upper protocol sender.
    handler: H,
}

pub struct IpEndpoint<'a, 'data> {
    pub inner: &'a mut Endpoint<'data>,
}

impl<'a> Endpoint<'a> {
    /// Construct a new endpoint handling messages to the specified addresses.
    ///
    /// # Panics
    /// This method will panic if one of the addresses assigned to the interface is not a unicast
    /// address.
    pub fn new<A, C, N>(addr: A, routes: C, neighbors: N) -> Self
    where
        A: Into<Slice<'a, IpCidr>>,
        C: Into<Routes<'a>>,
        N: Into<arp::NeighborCache<'a>>,
    {
        let addresses = addr.into();
        for addr in addresses.iter() {
            assert!(addr.address().is_unicast());
        }
        Endpoint {
            routing: Routing {
                addr: addresses,
                routes: routes.into(),
            },
            arp: arp::Endpoint::new(neighbors.into()),
        }
    }

    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.ip(), handler, }
    }

    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    pub fn send<H>(&mut self, handler: H) -> Sender<'_, 'a, H> {
        Sender { endpoint: self.ip(), handler, }
    }

    pub fn send_with<H>(&mut self, handler: H) -> Sender<'_, 'a, FnHandler<H>> {
        self.send(FnHandler(handler))
    }

    fn ip(&mut self) -> IpEndpoint<'_, 'a> {
        IpEndpoint {
            inner: self,
        }
    }

    pub fn accepts(&self, dst_addr: IpAddress) -> bool {
        self.routing.accepts(dst_addr)
    }

    pub(crate) fn routing(&mut self) -> &mut Routing<'a> {
        &mut self.routing
    }
}

impl Routing<'_> {
    pub fn accepts(&self, dst_addr: IpAddress) -> bool {
        self.addr.iter().any(|own_addr| own_addr.accepts(dst_addr))
    }

    /// Find the route to use.
    ///
    /// Typically is a three stage process:
    /// * If it is a local address, then only route loopback.
    /// * If dst is in the network of an assigned ip then route directly.
    /// * Lookup in routing table for all other addresses.
    ///
    /// For lack of direct loopback mechanism (TODO) we only implement the second two stages.
    pub fn route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        if let Some(route) = self.find_local_route(dst_addr, time) {
            return Some(route)
        }

        self.find_outer_route(dst_addr, time)
    }

    pub fn find_local_route(&self, dst_addr: IpAddress, _: Instant) -> Option<Route> {
        let matching_src = self.addr
            .iter()
            .filter(|addr| addr.subnet().contains(dst_addr))
            .nth(0)?;

        Some(Route {
            src_addr: matching_src.address(),
            next_hop: dst_addr,
        })
    }

    pub fn find_outer_route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        let next_hop = self.routes.lookup(dst_addr, time)?;

        // Which source to use?
        let src_addr = self.addr
            .iter()
            .filter(|addr| addr.subnet().contains(next_hop))
            .nth(0)?;

        Some(Route {
            next_hop,
            src_addr: src_addr.address(),
        })
    }
}

impl<'data> IpEndpoint<'_, 'data> {
    pub fn neighbors(&self) -> &arp::NeighborCache<'data> {
        self.inner.arp.neighbors()
    }

    pub fn neighbors_mut(&mut self) -> &mut arp::NeighborCache<'data> {
        self.inner.arp.neighbors_mut()
    }
}

impl packet::Endpoint for IpEndpoint<'_, '_> {
    fn local_ip(&self, subnet: IpSubnet) -> Option<IpAddress> {
        self.inner.routing.addr
            .iter()
            .cloned()
            .map(|cidr| cidr.address())
            .filter(|&addr| subnet.contains(addr))
            .nth(0)
    }

    fn route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        self.inner.routing.route(dst_addr, time)
    }

    fn resolve(&mut self, addr: IpAddress, time: Instant, look: bool) -> Result<EthernetAddress> {
        match self.neighbors().lookup_pure(addr, time) {
            Some(addr) => return Ok(addr),
            None if !look => return Err(Error::Unreachable),
            None => (),
        }

        match self.neighbors_mut().fill_looking(addr, Some(time)) {
            Ok(()) => Err(Error::Unreachable),
            Err(_) => Err(Error::Exhausted),
        }
    }
}

impl<P, T> eth::Recv<P> for Receiver<'_, '_, T>
where
    P: Payload,
    T: Recv<P>,
{
    fn receive(&mut self, eth::InPacket { mut handle, frame }: eth::InPacket<P>) {
        let capabilities = handle.info().capabilities();
        let packet = match frame.repr().ethertype {
            EthernetProtocol::Ipv4 => {
                match Ipv4Packet::new_checked(frame, capabilities.ipv4().rx_checksum()) {
                    Ok(packet) => IpPacket::V4(packet),
                    Err(_) => return,
                }
            },
            EthernetProtocol::Ipv6 => {
                match Ipv6Packet::new_checked(frame) {
                    Ok(packet) => IpPacket::V6(packet),
                    Err(_) => return,
                }
            },
            _ => return,
        };

        if !self.endpoint.inner.accepts(packet.repr().dst_addr()) {
            return
        }

        let handle = Handle::new(handle.borrow_mut(), &mut self.endpoint);
        let packet = packet::In { handle, packet };
        self.handler.receive(packet)
    }
}

impl<P, T> eth::Send<P> for Sender<'_, '_, T>
where
    P: Payload + PayloadMut,
    T: Send<P>,
{
    fn send<'a>(&mut self, packet: eth::RawPacket<'a, P>) {
        let eth::RawPacket { handle: mut eth_handle, payload } = packet;
        let handle = Handle::new(eth_handle.borrow_mut(), &mut self.endpoint);
        let packet = packet::Raw { handle, payload };

        self.handler.send(packet)
    }
}

impl<P: Payload, F> Recv<P> for FnHandler<F>
    where F: FnMut(packet::In<P>)
{
    fn receive(&mut self, frame: packet::In<P>) {
        self.0(frame)
    }
}

impl<P: Payload, F> Send<P> for FnHandler<F>
    where F: FnMut(packet::Raw<P>)
{
    fn send(&mut self, frame: packet::Raw<P>) {
        self.0(frame)
    }
}
