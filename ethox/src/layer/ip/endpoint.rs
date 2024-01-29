use crate::layer::{self, FnHandler};
use crate::layer::{Error, Result};
use crate::managed::Slice;
use crate::wire::{ip, ethernet, Payload, PayloadMut};
use crate::time::Instant;

use super::{Recv, Send};
use super::packet::{self, Controller, IpPacket, Route};
use super::route::Routes;

/// Handles IP connection states.
///
/// See the [module level documentation][mod] for more information about the context in which this
/// structure is used.
///
/// [mod]: index.html
///
/// As noted there, this contains routing information and neighbor cache(s).
pub struct Endpoint<'a> {
    /// Routing information.
    routing: Routing<'a>,

    /// Internal ipv4/ipv6 arp state.
    arp: layer::arp::Endpoint<'a>,
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
    addr: Slice<'data, ip::Cidr>,

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

/// An endpoint borrowed for sending.
///
/// Note that automatic address configuration traffic (arp, ...) is sent before the upper layer is
/// invoked. That is, some packet buffers provided by the ethernet layer below might not reach to
/// handler.
pub struct Sender<'a, 'data, H> {
    endpoint: IpEndpoint<'a, 'data>,

    /// The upper protocol sender.
    handler: H,
}

/// An endpoint borrowed only for doing layer internal communication.
///
/// This is an equivalent of a receiver and sender without an upper layer handler but might be
/// slightly more optimized since we statically know that this is the case.
pub struct Layer<'a, 'data> {
    endpoint: IpEndpoint<'a, 'data>,
}

pub(crate) struct IpEndpoint<'a, 'data> {
    pub(crate) inner: &'a mut Endpoint<'data>,
}

impl<'a> Endpoint<'a> {
    /// Construct a new endpoint handling messages to the specified addresses.
    ///
    /// The neighbors buffer for ARP can be built from an empty slice if it is not needed. This
    /// will however stall send operations indeterminately.
    ///
    /// # Panics
    /// This method will panic if one of the addresses assigned to the interface is not a unicast
    /// address.
    pub fn new<A, C, N>(addr: A, routes: C, neighbors: N) -> Self
    where
        A: Into<Slice<'a, ip::Cidr>>,
        C: Into<Routes<'a>>,
        N: Into<layer::arp::Endpoint<'a>>,
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
            arp: neighbors.into(),
        }
    }

    /// Receive packet using this mutably borrowed endpoint.
    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.ip(), handler, }
    }

    /// Receive packet using this mutably borrowed endpoint and a function.
    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    /// Send packets using this mutably borrowed endpoint.
    pub fn send<H>(&mut self, handler: H) -> Sender<'_, 'a, H> {
        Sender { endpoint: self.ip(), handler, }
    }

    /// Send packets using this mutably borrowed endpoint and a function.
    pub fn send_with<H>(&mut self, handler: H) -> Sender<'_, 'a, FnHandler<H>> {
        self.send(FnHandler(handler))
    }

    /// Do layer internal maintenance operation such as arp.
    pub fn layer_internal(&mut self) -> Layer<'_, 'a> {
        Layer { endpoint: self.ip() }
    }

    fn ip(&mut self) -> IpEndpoint<'_, 'a> {
        IpEndpoint {
            inner: self,
        }
    }

    /// Query if the configured addresses contain this destination.
    pub fn accepts(&self, dst_addr: ip::Address) -> bool {
        self.routing.accepts(dst_addr)
    }

    pub(crate) fn routing(&mut self) -> &mut Routing<'a> {
        &mut self.routing
    }
}

impl Routing<'_> {
    pub(crate) fn accepts(&self, dst_addr: ip::Address) -> bool {
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
    pub(crate) fn route(&self, dst_addr: ip::Address, time: Instant) -> Option<Route> {
        if let Some(route) = self.find_local_route(dst_addr, time) {
            return Some(route)
        }

        self.find_outer_route(dst_addr, time)
    }

    pub(crate) fn find_local_route(&self, dst_addr: ip::Address, _: Instant) -> Option<Route> {
        let matching_src = self.addr
            .iter()
            .filter(|addr| addr.subnet().contains(dst_addr))
            .nth(0)?;

        Some(Route {
            src_addr: matching_src.address(),
            next_hop: dst_addr,
        })
    }

    pub(crate) fn find_outer_route(&self, dst_addr: ip::Address, time: Instant) -> Option<Route> {
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
    pub(crate) fn neighbors(&self) -> &layer::arp::NeighborCache<'data> {
        self.inner.arp.neighbors()
    }

    pub(crate) fn neighbors_mut(&mut self) -> &mut layer::arp::NeighborCache<'data> {
        self.inner.arp.neighbors_mut()
    }

    fn into_arp_receiver(&mut self) -> layer::arp::Receiver<'_, 'data> {
        let Endpoint { routing, arp } = self.inner;
        arp.answer_for(routing)
    }

    fn into_arp_sender(&mut self) -> layer::arp::Sender<'_, 'data> {
        let Endpoint { routing, arp } = self.inner;
        arp.query_for(routing)
    }
}

impl packet::Endpoint for IpEndpoint<'_, '_> {
    fn local_ip(&self, subnet: ip::Subnet) -> Option<ip::Address> {
        self.inner.routing.addr
            .iter()
            .cloned()
            .map(|cidr| cidr.address())
            .filter(|&addr| subnet.contains(addr))
            .nth(0)
    }

    fn route(&self, dst_addr: ip::Address, time: Instant) -> Option<Route> {
        self.inner.routing.route(dst_addr, time)
    }

    fn resolve(&mut self, addr: ip::Address, time: Instant, look: bool) -> Result<ethernet::Address> {
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

impl<P, T> layer::eth::Recv<P> for Receiver<'_, '_, T>
where
    P: PayloadMut,
    T: Recv<P>,
{
    fn receive(&mut self, layer::eth::InPacket { mut control, frame }: layer::eth::InPacket<P>) {
        let capabilities = control.info().capabilities();
        let packet = match frame.repr().ethertype {
            ethernet::EtherType::Ipv4 => {
                match ip::v4::Packet::new_checked(frame, capabilities.ipv4().rx_checksum()) {
                    Ok(packet) => IpPacket::V4(packet),
                    Err(_) => return,
                }
            },
            ethernet::EtherType::Ipv6 => {
                match ip::v6::Packet::new_checked(frame) {
                    Ok(packet) => IpPacket::V6(packet),
                    Err(_) => return,
                }
            },
            ethernet::EtherType::Arp => {
                return self.endpoint.into_arp_receiver().receive(
                    layer::eth::InPacket { control, frame, });
            }
            _ => return,
        };

        if !self.endpoint.inner.accepts(packet.repr().dst_addr()) {
            return
        }

        self.handler.receive(packet::In {
            control: Controller {
                eth: control.borrow_mut(),
                endpoint: &mut self.endpoint,
            },
            packet,
        })
    }
}

impl<P, T> layer::eth::Send<P> for Sender<'_, '_, T>
where
    P: Payload + PayloadMut,
    T: Send<P>,
{
    fn send(&mut self, packet: layer::eth::RawPacket<P>) {
        // FIXME: will *always* intercept, even if we can't actually send any arp.
        if self.endpoint.neighbors().missing().count() > 0 {
            return self.endpoint.into_arp_sender().send(packet);
        }

        let layer::eth::RawPacket { control: mut eth_handle, payload } = packet;

        self.handler.send(packet::Raw {
            control: Controller {
                eth: eth_handle.borrow_mut(),
                endpoint: &mut self.endpoint
            },
            payload,
        });
    }
}

impl<P> layer::eth::Recv<P> for Layer<'_, '_>
    where P: PayloadMut,
{
    fn receive(&mut self, packet: layer::eth::InPacket<P>) {
        Receiver {
            endpoint: IpEndpoint {
                inner: self.endpoint.inner,
            },
            handler: FnHandler(recv_nothing),
        }.receive(packet)
    }
}

impl<P> layer::eth::Send<P> for Layer<'_, '_>
    where P: PayloadMut,
{
    fn send(&mut self, packet: layer::eth::RawPacket<P>) {
        Sender {
            endpoint: IpEndpoint {
                inner: self.endpoint.inner,
            },
            handler: FnHandler(send_nothing),
        }.send(packet)
    }
}

fn recv_nothing<P: PayloadMut>(_: packet::In<P>) { }
fn send_nothing<P: PayloadMut>(_: packet::Raw<P>) { }

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
