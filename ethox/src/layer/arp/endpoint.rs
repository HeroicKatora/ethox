//! As noted in RFC 826, arp assumes that at least the mapping and identities of the own host are
//! fully known to the resolver. Furthermore, we are expected to only keep a very small cache of
//! immediate communication hosts. To make the requests themselves we thus need to be informed
//! about missing addresses.

use crate::layer::{eth, Error, Result};
use crate::wire::{arp, ethernet, ip as wire_ip, Payload, PayloadMut};
use crate::time::Instant;
use crate::layer::ip;

use super::buffer::Buffer;
use super::packet::{Controller, In, Init, Raw};
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
    respond: Buffer<'data>,
    drop_counter: u64,
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
    /// Create a new endpoint with some memory for a cache.
    ///
    /// The cache might be pre-filled, for example with some static entries that are set to never
    /// expire.
    pub fn new<C>(neighbors: C) -> Self
        where C: Into<Cache<'data>>,
    {
        Endpoint {
            neighbors: neighbors.into(),
            respond: Buffer::default(),
            drop_counter: 0,
        }
    }

    /// Set a storage to temporary buffer outstanding ARP responses.
    pub fn with_request_buffer(self, buffer: Buffer<'data>) -> Self {
        Endpoint {
            respond: buffer,
            ..self
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

    pub(crate) fn has_send_need(&self) -> bool {
        self.neighbors().missing().count() > 0 || !self.respond.is_empty()
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
    fn handle_internally<P: PayloadMut>(&mut self, mut packet: In<P>) -> Result<()> {
        let (operation, source_hardware_addr, source_protocol_addr, target_protocol_addr) =
            match packet.packet.repr() {
                arp::Repr::EthernetIpv4 {
                    operation,
                    source_hardware_addr,
                    source_protocol_addr,
                    target_hardware_addr: _,
                    target_protocol_addr
                } => {
                    (operation, source_hardware_addr, source_protocol_addr, target_protocol_addr)
                },
            };

        // Update the address if it already exists in our tables (may be currently looking it up).
        self.update(
            source_hardware_addr,
            wire_ip::Address::Ipv4(source_protocol_addr),
            packet.control.info().timestamp());

        // TODO: handle incoming gratuitous ARP ?

        // verify that target protocol address is not a multicast address and we accept it.
        if target_protocol_addr.is_unicast() && self.ip.accepts(wire_ip::Address::Ipv4(target_protocol_addr)) {
            // unsolicited updates fully ignored not enabled.

            // send a reply if necessary.
            if let arp::Operation::Request = operation {
                let src = packet.control.inner.src_addr();
                let err = packet.answer()?.send();

                // Does not allow in-line responses. We instead queue this packet.
                if let Err(Error::Illegal) = err {
                    self.buffer_v4(
                        source_hardware_addr,
                        source_protocol_addr,
                        // Always use our own src as the target hardware address.
                        src,
                        target_protocol_addr,
                    );
                }

                err?
            }
        }

        Ok(())
    }

    /// Send oustanding arp requests.
    fn send_oustanding<P: PayloadMut>(&mut self, raw: Raw<P>) -> Result<()> {
        let ts = raw.control.info().timestamp();

        if let Some(inner) = self.buffered_answer(ts) {
            let prepared = raw.prepare(Init::Raw { inner })?;
            prepared.send()?;
            return Ok(());
        }

        // Search through the missing arp entries:
        let unresolved = self.inner.neighbors
            .missing()
            // only those alive and not recently been requested already
            .filter(|missing| missing.is_alive(ts) && missing.looking_for())
            // … and that are entries for ipv4
            .filter_map(|missing| match missing.protocol_addr() {
                wire_ip::Address::Ipv4(addr) => Some(addr),
                _ => None,
            })
            // … and for which we can find a link-local outbound route.
            .find_map(|addr| {
                self.ip.find_local_route(wire_ip::Address::Ipv4(addr), ts)
                    .map(|route| (addr, route))
            });

        let (addr, route) = match unresolved {
            None => return Ok(()),
            Some(required) => required,
        };

        debug_assert_eq!(route.next_hop, wire_ip::Address::Ipv4(addr));

        let ip_src_address = match route.src_addr {
            wire_ip::Address::Ipv4(addr) => addr,
            _ => unreachable!("Ipv4 destination routed with non-ipv4 source"),
        };

        let mut raw = raw;

        let src = raw.control.inner.src_addr();
        let prepared = raw.prepare(Init::EthernetIpv4Request {
            source_hardware_addr: src,
            target_hardware_addr: ethernet::Address::BROADCAST,
            source_protocol_addr: ip_src_address,
            target_protocol_addr: addr,
        })?;

        // Reset the timer for that entry. Should always succeed.
        let reset = self.inner.neighbors.requesting(wire_ip::Address::Ipv4(addr), ts);
        debug_assert!(reset.is_ok());

        prepared.send()?;

        Ok(())
    }

    fn buffer_v4(
        &mut self,
        source_hardware_addr: ethernet::Address,
        source_protocol_addr: wire_ip::v4::Address,
        target_hardware_addr: ethernet::Address,
        target_protocol_addr: wire_ip::v4::Address,
    ) {
        if !self.inner.respond.offer(arp::Repr::EthernetIpv4 {
            operation: arp::Operation::Reply,
            source_hardware_addr: target_hardware_addr,
            source_protocol_addr: target_protocol_addr,
            target_hardware_addr: source_hardware_addr,
            target_protocol_addr: source_protocol_addr,
        }) {
            self.inner.drop_counter += 1;
        }
    }

    /// If there are outstanding queries about _us_, then answer them at a defined rate.
    fn buffered_answer(&mut self, ts: Instant) -> Option<arp::Repr> {
        self.inner.respond.pop()
    }

    fn update(&mut self, hw_addr: ethernet::Address, prot_addr: wire_ip::Address, time: Instant) -> bool {
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
    fn receive(&mut self, eth::InPacket { control, frame }: eth::InPacket<P>) {
        let packet = match frame.repr().ethertype {
            ethernet::EtherType::Arp => match arp::Packet::new_checked(frame) {
                Ok(packet) => packet,
                Err(_) => return,
            },
            _ => return,
        };

        let control = Controller::new(control);
        let packet = In::new(control, packet);

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
            control: mut eth_handle,
            payload,
        } = packet;

        let control = Controller::new(eth_handle.borrow_mut());
        let packet = Raw::new(control, payload);

        if let Err(_) = self.endpoint.send_oustanding(packet) {
            // TODO: log error
        }
    }
}
