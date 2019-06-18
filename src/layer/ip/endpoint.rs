use crate::layer::{eth, FnHandler};
use crate::managed::Slice;
use crate::wire::{EthernetProtocol, Payload, PayloadMut};
use crate::wire::{IpAddress, IpCidr, Ipv4Cidr, Ipv6Cidr, Ipv4Packet};
use crate::time::Instant;

use super::{Recv, Send};
use super::packet::{self, IpPacket, Handle, Route};
use super::route::Routes;

pub struct Endpoint<'a> {
    /// Our own address.
    addr: Slice<'a, IpCidr>,

    /// Routing information.
    routes: Routes<'a>,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configurerd here, and not in the endpoint state.
pub struct Receiver<'a, 'e, H> {
    endpoint: IpEndpoint<'a, 'e>,

    /// The upper protocol receiver.
    handler: H,
}

pub struct Sender<'a, 'e, H> {
    endpoint: IpEndpoint<'a, 'e>,

    /// The upper protocol sender.
    handler: H,
}

struct IpEndpoint<'a, 'e> {
    // TODO: could be immutable as well, just disallowing updates. Evaluate whether this is useful
    // or needed somewhere.
    inner: &'a mut Endpoint<'e>,
}

impl<'a> Endpoint<'a> {
    pub fn new<A, C>(addr: A, routes: C) -> Self 
        where A: Into<Slice<'a, IpCidr>>, C: Into<Routes<'a>>,
    {
        Endpoint {
            addr: addr.into(),
            routes: routes.into(),
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

    fn accepts(&self, dst_addr: IpAddress) -> bool {
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
    fn route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        if let Some(route) = self.find_local_route(dst_addr, time) {
            return Some(route)
        }

        self.find_outer_route(dst_addr, time)
    }

    fn find_local_route(&self, dst_addr: IpAddress, _: Instant) -> Option<Route> {
        let dst_cidr = match dst_addr {
            IpAddress::Ipv4(addr) => Ipv4Cidr::new(addr, 32).into(),
            IpAddress::Ipv6(addr) => Ipv6Cidr::new(addr, 128).into(),
            addr => panic!("Invalid address to find route to: {}", addr),
        };

        let matching_src = self.addr
            .iter()
            .filter(|addr| addr.contains_subnet(dst_cidr))
            .nth(0)?;

        Some(Route {
            src_addr: matching_src.address(),
            next_hop: dst_addr,
        })
    }

    fn find_outer_route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        let next_hop = self.routes.lookup(dst_addr, time)?;

        // Which source to use?
        let src_addr = self.addr
            .iter()
            .filter(|addr| addr.contains(dst_addr))
            .nth(0)?;

        Some(Route {
            next_hop,
            src_addr: src_addr.address(),
        })
    }
}

impl packet::Endpoint for IpEndpoint<'_, '_> {
    fn route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        self.inner.route(dst_addr, time)
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
            /*EthernetProtocol::Ipv6 => {
                let packet = Ipv6Packet::new_checked(packet, Checksum::Manual);
            },*/
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
