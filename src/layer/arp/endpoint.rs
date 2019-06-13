//! As noted in RFC 826, arp assumes that at least the mapping and identities of the own host are
//! fully known to the resolver. Furthermore, we are expected to only keep a very small cache of
//! immediate communication hosts. To make the requests themselves we thus need to be informed
//! about missing addresses.

use crate::layer::{eth, FnHandler, Result};
use crate::wire::{ArpPacket, ArpRepr, ArpOperation, EthernetProtocol, Payload, PayloadMut, IpAddress};
use crate::layer::ip::{self, IpEndpoint};

use super::packet::{Handle, In, Raw};
use super::{Recv, Send};

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
pub struct Sender<'a, 'e, H> {
    endpoint: EndpointRef<'a>,

    ip: IpEndpoint<'a, 'e>,

    /// The upper protocol sender.
    handler: H,
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

    pub fn send<'a, 'e, H>(&'a mut self, ip: &'a mut ip::Endpoint<'e>, handler: H) -> Sender<'a, 'e, H> {
        Sender {
            endpoint: self.get_mut(),
            ip: ip.ip(),
            handler,
        }
    }

    pub fn send_with<'a, 'e, H>(&'a mut self, ip: &'a mut ip::Endpoint<'e>, handler: H) -> Sender<'a, 'e, FnHandler<H>> {
        self.send(ip, FnHandler(handler))
    }

    /// Get this by mutable reference for a receiver or sender.
    fn get_mut(&mut self) -> EndpointRef {
        EndpointRef { inner: self }
    }
}

impl EndpointRef<'_> {
    /// Try to answer or otherwise handle the packet without propagating it upwards.
    fn handle_internally<P: PayloadMut>(&mut self, packet: In<P>, ip: &IpEndpoint) -> Result<()> {
        let (operation, source_hardware_addr, source_protocol_addr, target_hardware_addr, target_protocol_addr) =
            match packet.packet.repr() {
                ArpRepr::EthernetIpv4 {
                    operation,
                    source_hardware_addr,
                    source_protocol_addr,
                    target_hardware_addr,
                    target_protocol_addr
                } => {
                    (operation, source_hardware_addr, source_protocol_addr, target_hardware_addr, target_protocol_addr)
                },
                _ => unreachable!(),
            };

        packet.handle.inner.endpoint.update(source_hardware_addr, IpAddress::Ipv4(source_protocol_addr))?;

        // verify that target protocol address is not a multicast address
        if ip.inner.accepts(IpAddress::Ipv4(target_protocol_addr)) && !IpAddress::Ipv4(target_protocol_addr).is_multicast() {
            if let ArpOperation::Request = operation {
                packet.answer()?.send()?;
            }
        }

        Ok(())
    }
}

impl<P> eth::Recv<P> for Receiver<'_, '_>
    where
        P: PayloadMut,
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

        self.endpoint.handle_internally(packet, &self.ip);
    }
}

impl<P, T> eth::Send<P> for Sender<'_, '_, T>
    where
        P: Payload + PayloadMut,
        T: Send<P>,
{
    fn send(&mut self, packet: eth::RawPacket<P>) {
        let eth::RawPacket {
            handle: mut eth_handle,
            payload,
        } = packet;
        let handle = Handle::new(eth_handle.borrow_mut());
        let packet = Raw::new(handle, payload);

        self.handler.send(packet)
    }
}

impl<P: Payload, F> Recv<P> for FnHandler<F>
    where
        F: FnMut(In<P>),
{
    fn receive(&mut self, frame: In<P>) {
        self.0(frame)
    }
}

impl<P: Payload, F> Send<P> for FnHandler<F>
    where
        F: FnMut(Raw<P>),
{
    fn send(&mut self, frame: Raw<P>) {
        self.0(frame)
    }
}
