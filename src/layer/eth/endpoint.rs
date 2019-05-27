use crate::layer::{Result, Error, FnHandler};
use crate::time::Instant;
use crate::wire::{EthernetAddress, EthernetFrame, IpAddress,  Payload, PayloadMut};
use crate::nic;

use super::{Recv, Send};
use super::packet::{self, Init, Handle, Packet, RawPacket};
use super::neighbor::{Cache};

pub struct Endpoint<'a> {
    /// Our own address.
    ///
    /// We ignored any packets with mismatching destination.
    addr: EthernetAddress,

    /// Internal neighbor cache.
    ///
    /// Upper layer protocols, usually ARP, are also allowed to update the table of associated
    /// entires.
    neighbors: Cache<'a>,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configurerd here, and not in the endpoint state.
pub struct Receiver<'a, 'e, H> {
    endpoint: EthEndpoint<'a, 'e>,

    /// The upper protocol receiver.
    handler: H,
}

pub struct Sender<'a, 'e, H> {
    endpoint: EthEndpoint<'a, 'e>,

    /// The upper protocol sender.
    handler: H,
}

struct EthEndpoint<'a, 'e> {
    // TODO: could be immutable as well, just disallowing updates. Evaluate whether this is useful
    // or needed somewhere.
    inner: &'a mut Endpoint<'e>,

    /// The current timestamp for this operation.
    time: Instant,
}

impl<'a> Endpoint<'a> {
    pub fn new<C>(addr: EthernetAddress, neighbors: C) -> Self 
        where C: Into<Cache<'a>>,
    {
        Endpoint {
            addr,
            neighbors: neighbors.into(),
        }
    }

    pub fn recv<H>(&mut self, handler: H, time: Instant) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.eth(time), handler, }
    }

    pub fn recv_with<H>(&mut self, handler: H, time: Instant) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler), time)
    }

    pub fn send<H>(&mut self, handler: H, time: Instant) -> Sender<'_, 'a, H> {
        Sender { endpoint: self.eth(time), handler, }
    }

    pub fn send_with<H>(&mut self, handler: H, time: Instant) -> Sender<'_, 'a, FnHandler<H>> {
        self.send(FnHandler(handler), time)
    }

    fn eth(&mut self, time: Instant) -> EthEndpoint<'_, 'a> {
        EthEndpoint {
            inner: self,
            time,
        }
    }

    fn accepts(&self, dst_addr: EthernetAddress) -> bool {
        // TODO: broadcast and multicast
        self.addr == dst_addr
    }
}

impl packet::Endpoint for EthEndpoint<'_, '_> {
    fn init(&mut self) -> Init {
        self.inner.addr.into()
    }

    fn resolve(&mut self, addr: IpAddress) -> Result<EthernetAddress> {
        // TODO: should we automatically try to send an ARP request?  And if so, should lookup be
        // used instead.
        self.inner.neighbors.lookup_pure(&addr, self.time)
            .ok_or(Error::Unreachable)
    }
}

impl<H, P, T> nic::Recv<H, P> for Receiver<'_, '_, T>
where
    H: nic::Handle,
    P: Payload,
    T: Recv<P>,
{
    fn receive(&mut self, packet: nic::Packet<H, P>) {
        let frame = match EthernetFrame::new_checked(packet.payload) {
            Ok(frame) => frame,
            Err(_) => return,
        };

        let repr = frame.repr();
        if !self.endpoint.inner.accepts(repr.dst_addr) {
            return
        }

        let handle = Handle::new(packet.handle, &mut self.endpoint);
        let packet = Packet::new(handle, frame);
        self.handler.receive(packet)
    }
}

impl<H, P, T> nic::Send<H, P> for Sender<'_, '_, T>
where
    H: nic::Handle,
    P: Payload + PayloadMut,
    T: Send<P>,
{
    fn send(&mut self, packet: nic::Packet<H, P>) {
        let handle = Handle::new(packet.handle, &mut self.endpoint);
        let packet = RawPacket::new(handle, packet.payload);
        self.handler.send(packet);
    }
}

impl<'a, P: Payload, F> Recv<P> for FnHandler<F>
    where F: FnMut(Packet<P>)
{
    fn receive(&mut self, frame: Packet<P>) {
        self.0(frame)
    }
}

impl<'a, P: Payload, F> Send<P> for FnHandler<F>
    where F: FnMut(RawPacket<P>)
{
    fn send(&mut self, frame: RawPacket<P>) {
        self.0(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::Slice;
    use crate::nic::{external::External, Device};
    use crate::layer::eth::NeighborCache;
    use crate::wire::{EthernetAddress, EthernetProtocol};

    const MAC_ADDR_1: EthernetAddress = EthernetAddress([0, 1, 2, 3, 4, 5]);

    static PAYLOAD_BYTES: [u8; 50] =
        [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    fn simple_send<P: Payload + PayloadMut>(mut frame: RawPacket<P>) {
        frame.init.set_dst_addr(MAC_ADDR_1);
        frame.init.set_ethertype(EthernetProtocol::Unknown(0xBEEF));
        frame.init.set_payload_len(PAYLOAD_BYTES.len());
        let mut prepared = frame.prepare()
            .expect("Preparing frame mustn't fail in controlled environment");
        prepared
            .frame()
            .payload_mut_slice()
            .copy_from_slice(&PAYLOAD_BYTES[..]);
    }

    fn simple_recv<P: Payload>(mut frame: Packet<P>) {
        assert_eq!(frame.frame().payload().as_slice(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn simple() {
        let mut endpoint = Endpoint::new(MAC_ADDR_1, NeighborCache::new(&mut [][..]));
        let mut nic = External::new_send(Slice::One(vec![0; 1024]));

        let time = Instant::from_millis(0);
        let sent = nic.tx(
            1,
            endpoint
                .send_with(simple_send, time));
        assert_eq!(sent, Ok(1));

        let time = Instant::from_millis(1);
        nic.set_one_past_receive(1);
        let recv = nic.rx(
            1,
            endpoint
                .recv_with(simple_recv, time));
        assert_eq!(recv, Ok(1));
    }
}