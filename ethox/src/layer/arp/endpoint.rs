//! As noted in RFC 826, arp assumes that at least the mapping and identities of the own host are
//! fully known to the resolver. Furthermore, we are expected to only keep a very small cache of
//! immediate communication hosts. To make the requests themselves we thus need to be informed
//! about missing addresses.

use crate::layer::{eth, Result};
use crate::wire::{ArpPacket, ArpRepr, ArpOperation, EthernetProtocol, Payload, PayloadMut, IpAddress};
use crate::layer::ip::{self, IpEndpoint};

use super::packet::{Handle, In, Raw};

/// An arp traffic handler.
#[derive(Default)]
pub struct Endpoint {
    // Some configuration could be done here ...
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configured here, and not in the endpoint state.
pub struct Receiver<'a, 'e> {
    endpoint: EndpointRef<'a>,

    ip: IpEndpoint<'a, 'e>,
}

/// An arp endpoint for sending.
pub struct Sender<'a, 'e> {
    endpoint: EndpointRef<'a>,

    ip: IpEndpoint<'a, 'e>,
}

struct EndpointRef<'a> {
    inner: &'a Endpoint,
}

impl Endpoint {
    pub fn new() -> Self {
        Self::default()
    }

    /// A receiver that only answers (and handles) arp requests.
    pub fn answer<'a, 'e>(&'a mut self, ip: &'a mut ip::Endpoint<'e>) -> Receiver<'a, 'e> {
        Receiver {
            endpoint: self.get_mut(),
            ip: ip.ip(),
        }
    }

    /// A sender that sends outstanding arp queries.
    pub fn query<'a, 'e>(&'a mut self, ip: &'a mut ip::Endpoint<'e>) -> Sender<'a, 'e> {
        Sender {
            endpoint: self.get_mut(),
            ip: ip.ip(),
        }
    }

    /// Get this by mutable reference for a receiver or sender.
    fn get_mut(&mut self) -> EndpointRef {
        EndpointRef { inner: self }
    }
}

impl EndpointRef<'_> {
    /// Try to answer or otherwise handle the packet without propagating it upwards.
    ///
    /// See [RFC826] for details.
    ///
    /// [RFC826]: https://tools.ietf.org/html/rfc826
    fn handle_internally<P: PayloadMut>(&mut self, packet: In<P>, ip: &IpEndpoint) -> Result<()> {
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
        packet.handle.inner.endpoint.update(
            source_hardware_addr,
            IpAddress::Ipv4(source_protocol_addr),
            packet.handle.info().timestamp());

        // verify that target protocol address is not a multicast address and we accept it.
        if !target_protocol_addr.is_multicast() && ip.inner.accepts(IpAddress::Ipv4(target_protocol_addr)) {
            // unsolicited updates fully ignored not enabled.

            // send a reply if necessary.
            if let ArpOperation::Request = operation {
                packet.answer()?.send()?;
            }
        }

        Ok(())
    }

    /// Send oustanding arp requests.
    fn send_oustanding<P: PayloadMut>(&mut self, _: Raw<P>, _: &IpEndpoint) -> Result<()> {
        unimplemented!()
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

        if let Err(_) = self.endpoint.handle_internally(packet, &self.ip) {
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

        if let Err(_) = self.endpoint.send_oustanding(packet, &self.ip) {
            // TODO: log error
        }
    }
}
