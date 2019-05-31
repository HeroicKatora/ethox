use crate::layer::{eth, FnHandler};
use crate::managed::Slice;
use crate::wire::{Checksum, EthernetProtocol, IpAddress, IpCidr, Ipv4Packet, Ipv6Packet, Payload, PayloadMut};
use crate::time::Instant;

use super::{Recv, Send};
use super::packet::{self, IpPacket, Handle, Packet, RawPacket, Route};
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
        self.addr.iter().any(|own_addr| own_addr.address() == dst_addr)
    }

    /// Find the route to use.
    fn route(&self, dst_addr: IpAddress, time: Instant) -> Option<Route> {
        let next_hop = self.routes.lookup(&dst_addr, time)?;

        // Which source to use?
        let src_addr = self.addr
            .iter()
            .filter(|addr| addr.contains_addr(&dst_addr))
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
    fn receive(&mut self, packet: eth::Packet<P>) {
        let capabilities = packet.handle.info().capabilities();
        let eth::Packet { mut handle, frame } = packet;
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
        let packet = Packet::new(handle, packet);
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
        let packet = RawPacket::new(handle, payload);

        self.handler.send(packet)
    }
}
