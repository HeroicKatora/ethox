use crate::layer::{ip, FnHandler};
use crate::managed::Slice;
use crate::wire::{IpProtocol, Payload, PayloadMut, UdpPacket};

use super::{Recv, Send};
use super::packet::{Controller, Packet, RawPacket};

/// The udp endpoint state.
///
/// Compared to TCP this is very minimal as it contains no connection states, only a list of ports
/// to appear open and simple switches to control the processing of other packets not reaching
/// those ports.
pub struct Endpoint<'a> {
    /// List of accepted ports for lookup.
    ports: Slice<'a, u16>,

    /// Whether to filter incoming packets based on port.
    filter_ports: bool,
}

/// An endpoint borrowed for receiving.
pub struct Receiver<'a, 'e, H> {
    endpoint: UdpEndpoint<'a, 'e>,

    /// The upper protocol receiver.
    handler: H,
}

/// An endpoint borrowed for sending.
pub struct Sender<'a, 'e, H> {
    // FIXME: I don't know, maybe we should need it for selecting a source port?
    _endpoint: UdpEndpoint<'a, 'e>,

    /// The upper protocol sender.
    handler: H,
}

struct UdpEndpoint<'a, 'e> {
    inner: &'a Endpoint<'e>,
}


impl<'a> Endpoint<'a> {
    /// Create a new udp endpoint with a list of open ports.
    pub fn new<A>(ports: A) -> Self 
        where A: Into<Slice<'a, u16>>,
    {
        Endpoint {
            ports: ports.into(),
            filter_ports: true,
        }
    }

    /// Create an endpoint that only decodes udp packets.
    ///
    /// The endpoint contains an empty list of ports but does not filter incoming packets based on
    /// this list. This allows full customization of the filter by the upper layer which is useful
    /// if no short list of potential ports is known a-priori.
    pub fn new_unfiltered() -> Self {
        Endpoint {
            ports: Slice::empty(),
            filter_ports: false,
        }
    }

    /// Receive packet using this mutably borrowed endpoint.
    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.get_mut(), handler, }
    }

    /// Receive packet using this mutably borrowed endpoint and a function.
    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    /// Send packets using this mutably borrowed endpoint.
    pub fn send<H>(&mut self, handler: H) -> Sender<'_, 'a, H> {
        Sender { _endpoint: self.get_mut(), handler, }
    }

    /// Send packets using this mutably borrowed endpoint and a function.
    pub fn send_with<H>(&mut self, handler: H) -> Sender<'_, 'a, FnHandler<H>> {
        self.send(FnHandler(handler))
    }

    /// Set whether to filter incoming packets based on their destination port.
    ///
    /// When enabled checks the destination port of all incoming packets against the list of open
    /// ports of the endpoint and drops packets to all other ports. When disabled all packets will
    /// be received regardless.
    pub fn filter_ports(&mut self, filter_ports: bool) {
        self.filter_ports = filter_ports;
    }

    fn accepts(&self, port: u16) -> bool {
        !self.filter_ports || self.ports.as_slice().contains(&port)
    }

    fn get_mut(&mut self) -> UdpEndpoint<'_, 'a> {
        UdpEndpoint {
            inner: self,
        }
    }
}

impl<P, H> ip::Recv<P> for Receiver<'_, '_, H>
where
    P: Payload,
    H: Recv<P>,
{
    fn receive(&mut self, ip::InPacket { control, packet }: ip::InPacket<P>) {
        let capabilities = control.info().capabilities();
        let checksum = capabilities.udp().rx_checksum(packet.repr());

        let packet = match packet.repr().protocol() {
            IpProtocol::Udp => {
                match UdpPacket::new_checked(packet, checksum) {
                    Ok(packet) => packet,
                    Err(_) => return,
                }
            },
            _ => return,
        };

        if !self.endpoint.inner.accepts(packet.repr().dst_port) {
            // FIXME: we might send ICMP unreachable but may want to have a silent configuration
            // that does not.
            return
        }

        let control = Controller::new(control);
        let packet = Packet::new(control, packet);
        self.handler.receive(packet);
    }
}

impl<P, H> ip::Send<P> for Sender<'_, '_, H>
where
    P: Payload + PayloadMut,
    H: Send<P>,
{
    fn send<'a>(&mut self, packet: ip::RawPacket<'a, P>) {
        let ip::RawPacket { control, payload } = packet;
        let control = Controller::new(control);
        let packet = RawPacket::new(control, payload);

        self.handler.send(packet)
    }
}

impl<P: Payload, F> Recv<P> for FnHandler<F>
    where F: FnMut(Packet<P>)
{
    fn receive(&mut self, frame: Packet<P>) {
        self.0(frame)
    }
}

impl<P: Payload, F> Send<P> for FnHandler<F>
    where F: FnMut(RawPacket<P>)
{
    fn send(&mut self, frame: RawPacket<P>) {
        self.0(frame)
    }
}
