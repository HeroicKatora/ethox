use crate::layer::{ip, FnHandler};
use crate::managed::Slice;
use crate::wire::{IpProtocol, Payload, PayloadMut, UdpPacket};

use super::{Recv, Send};
use super::packet::{Handle, Packet, RawPacket};

pub struct Endpoint<'a> {
    /// List of accepted ports for lookup.
    ports: Slice<'a, u16>,
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
    pub fn new<A>(ports: A) -> Self 
        where A: Into<Slice<'a, u16>>,
    {
        Endpoint {
            ports: ports.into(),
        }
    }

    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.get_mut(), handler, }
    }

    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    pub fn send<H>(&mut self, handler: H) -> Sender<'_, 'a, H> {
        Sender { _endpoint: self.get_mut(), handler, }
    }

    pub fn send_with<H>(&mut self, handler: H) -> Sender<'_, 'a, FnHandler<H>> {
        self.send(FnHandler(handler))
    }

    fn accepts(&self, port: u16) -> bool {
        self.ports.as_slice().contains(&port)
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
    fn receive(&mut self, packet: ip::Packet<P>) {
        let capabilities = packet.handle.info().capabilities();
        let ip::Packet { handle, packet } = packet;
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
            return
        }

        let handle = Handle::new(handle);
        let packet = Packet::new(handle, packet);
        self.handler.receive(packet);
    }
}

impl<P, H> ip::Send<P> for Sender<'_, '_, H>
where
    P: Payload + PayloadMut,
    H: Send<P>,
{
    fn send<'a>(&mut self, packet: ip::RawPacket<'a, P>) {
        let ip::RawPacket { handle, payload } = packet;
        let handle = Handle::new(handle);
        let packet = RawPacket::new(handle, payload);

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
