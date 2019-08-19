//! As noted in RFC 826, arp assumes that at least the mapping and identities of the own host are
//! fully known to the resolver. Furthermore, we are expected to only keep a very small cache of
//! immediate communication hosts. To make the requests themselves we thus need to be informed
//! about missing addresses.

use crate::layer::{eth, Result};
use crate::wire::{ArpPacket, ArpRepr, ArpOperation, EthernetAddress, EthernetProtocol, Payload, PayloadMut, IpAddress};
use crate::time::Instant;
use crate::layer::ip;

use super::packet::{Handle, In, Init, Raw};
use super::neighbor::Cache;

/// The persistent data of an arp layer.
///
/// A protocol layer (currently only IP) must be used in together with this structure to provide
/// the answer and query functionality.
///
/// The endpoint of arp is embedded into the ethernet layer where it can be used by all other upper
/// layers for handling their protocol specific arp tasks.
pub struct Endpoint<'data> {
    neighbors: Cache<'data>,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configured here, and not in the endpoint state.
pub struct Receiver<'a, 'data> {
    endpoint: EndpointRef<'a, 'data>,
}

/// An arp endpoint for sending.
pub struct Sender<'a, 'data> {
    endpoint: EndpointRef<'a, 'data>,
}

struct EndpointRef<'a, 'data> {
    inner: &'a mut Endpoint<'data>,
    ip: &'a mut ip::Routing<'data>,
}

impl<'data> Endpoint<'data> {
    pub fn new<C>(neighbors: C) -> Self
        where C: Into<Cache<'data>>,
    {
        Endpoint {
            neighbors: neighbors.into(),
        }
    }

    /// A receiver that answers arp requests in stead of an ip endpoint.
    ///
    /// Utilizes the address and routing configuration of the endpoint but handles arp traffic
    /// instead of the built-in arp handler of the ip endpoint.
    pub fn answer<'a>(&'a mut self, ip: &'a mut ip::Endpoint<'data>) -> Receiver<'a, 'data> {
        self.answer_for(ip.routing())
    }

    pub(crate) fn answer_for<'a>(&'a mut self, ip: &'a mut ip::Routing<'data>) -> Receiver<'a, 'data> {
        Receiver {
            endpoint: self.get_mut(ip),
        }
    }

    /// A sender that sends outstanding arp queries.
    ///
    /// Utilizes the address and routing configuration of the endpoint but handles arp traffic
    /// instead of the built-in arp handler of the ip endpoint.
    pub fn query<'a>(&'a mut self, ip: &'a mut ip::Endpoint<'data>) -> Sender<'a, 'data> {
        self.query_for(ip.routing())
    }


    pub(crate) fn query_for<'a>(&'a mut self, ip: &'a mut ip::Routing<'data>) -> Sender<'a, 'data> {
        Sender {
            endpoint: self.get_mut(ip),
        }
    }

    /// Get this by mutable reference for a receiver or sender.
    fn get_mut<'a>(&'a mut self, ip: &'a mut ip::Routing<'data>) -> EndpointRef<'a, 'data> {
        EndpointRef { inner: self, ip, }
    }

    pub(crate) fn neighbors(&self) -> &Cache<'data> {
        &self.neighbors
    }

    pub(crate) fn neighbors_mut(&mut self) -> &mut Cache<'data> {
        &mut self.neighbors
    }
}

impl EndpointRef<'_, '_> {
    /// Try to answer or otherwise handle the packet without propagating it upwards.
    ///
    /// See [RFC826] for details.
    ///
    /// [RFC826]: https://tools.ietf.org/html/rfc826
    fn handle_internally<P: PayloadMut>(&mut self, packet: In<P>) -> Result<()> {
        let (operation, source_hardware_addr, source_protocol_addr, target_protocol_addr) =
            match packet.packet.repr() {
                ArpRepr::EthernetIpv4 {
                    operation,
                    source_hardware_addr,
                    source_protocol_addr,
                    target_hardware_addr: _,
                    target_protocol_addr
                } => {
                    (operation, source_hardware_addr, source_protocol_addr, target_protocol_addr)
                },
                _ => return Ok(()),
            };

        // Update the address if it already exists in our tables (may be currently looking it up).
        self.update(
            source_hardware_addr,
            IpAddress::Ipv4(source_protocol_addr),
            packet.handle.info().timestamp());

        // TODO: handle incoming gratuitous ARP ?

        // verify that target protocol address is not a multicast address and we accept it.
        if target_protocol_addr.is_unicast() && self.ip.accepts(IpAddress::Ipv4(target_protocol_addr)) {
            // unsolicited updates fully ignored not enabled.

            // send a reply if necessary.
            if let ArpOperation::Request = operation {
                packet.answer()?.send()?;
            }
        }

        Ok(())
    }

    /// Send oustanding arp requests.
    fn send_oustanding<P: PayloadMut>(&mut self, raw: Raw<P>) -> Result<()> {
        let ts = raw.handle.info().timestamp();

        // Search through the missing arp entries:
        let unresolved = self.inner.neighbors
            .missing()
            // only those alive and not recently been requested already
            .filter(|missing| missing.is_alive(ts) && missing.looking_for())
            // … and that are entries for ipv4
            .filter_map(|missing| match missing.protocol_addr() {
                IpAddress::Ipv4(addr) => Some(addr),
                _ => None,
            })
            // … and for which we can find a link-local outbound route.
            .filter_map(|addr| {
                self.ip.find_local_route(IpAddress::Ipv4(addr), ts)
                    .map(|route| (addr, route))
            })
            .next();

        let (addr, route) = match unresolved {
            None => return Ok(()),
            Some(required) => required,
        };

        debug_assert_eq!(route.next_hop, IpAddress::Ipv4(addr));

        let ip_src_address = match route.src_addr {
            IpAddress::Ipv4(addr) => addr,
            _ => unreachable!("Ipv4 destination routed with non-ipv4 source"),
        };

        let mut raw = raw;

        let src = raw.handle.inner.src_addr();
        let prepared = raw.prepare(Init::EthernetIpv4Request {
            source_hardware_addr: src,
            target_hardware_addr: EthernetAddress::BROADCAST,
            source_protocol_addr: ip_src_address,
            target_protocol_addr: addr,
        })?;

        // Reset the timer for that entry. Should always succeed.
        let reset = self.inner.neighbors.requesting(IpAddress::Ipv4(addr), ts);
        debug_assert!(reset.is_ok());

        prepared.send()?;

        Ok(())
    }

    fn update(&mut self, hw_addr: EthernetAddress, prot_addr: IpAddress, time: Instant) -> bool {
        if let Some(_) = self.inner.neighbors.lookup(prot_addr, time) {
            assert!(self.inner.neighbors.fill(prot_addr, hw_addr, Some(time)).is_ok());
            true
        } else {
            false
        }
    }
}

impl<P> eth::Recv<P> for Receiver<'_, '_>
    where P: PayloadMut,
{
    fn receive(&mut self, eth::InPacket { handle, frame }: eth::InPacket<P>) {
        let packet = match frame.repr().ethertype {
            EthernetProtocol::Arp => match ArpPacket::new_checked(frame) {
                Ok(packet) => packet,
                Err(_) => return,
            },
            _ => return,
        };

        let handle = Handle::new(handle);
        let packet = In::new(handle, packet);

        if let Err(_) = self.endpoint.handle_internally(packet) {
            // TODO: log error
        }
    }
}

impl<P> eth::Send<P> for Sender<'_, '_>
    where P: Payload + PayloadMut,
{
    fn send(&mut self, packet: eth::RawPacket<P>) {
        let eth::RawPacket {
            handle: mut eth_handle,
            payload,
        } = packet;

        let handle = Handle::new(eth_handle.borrow_mut());
        let packet = Raw::new(handle, payload);

        if let Err(_) = self.endpoint.send_oustanding(packet) {
            // TODO: log error
        }
    }
}
