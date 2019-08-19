use crate::layer::{arp, Result, Error, FnHandler};
use crate::time::Instant;
use crate::wire::{EthernetAddress, EthernetFrame, IpAddress,  Payload, PayloadMut};
use crate::nic;

use super::{Recv, Send};
use super::packet::{self, Handle};
use super::NeighborCache;

pub struct Endpoint<'a> {
    /// Our own address.
    ///
    /// We ignored any packets with mismatching destination.
    addr: EthernetAddress,

    /// Internal arp state.
    arp: arp::Endpoint<'a>,
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
}

impl<'a> Endpoint<'a> {
    pub fn new<C>(addr: EthernetAddress, neighbors: C) -> Self 
        where C: Into<NeighborCache<'a>>,
    {
        Endpoint {
            addr,
            arp: arp::Endpoint::new(neighbors.into()),
        }
    }

    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.eth(), handler, }
    }

    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    pub fn send<H>(&mut self, handler: H) -> Sender<'_, 'a, H> {
        Sender { endpoint: self.eth(), handler, }
    }

    pub fn send_with<H>(&mut self, handler: H) -> Sender<'_, 'a, FnHandler<H>> {
        self.send(FnHandler(handler))
    }

    fn eth(&mut self) -> EthEndpoint<'_, 'a> {
        EthEndpoint {
            inner: self,
        }
    }

    fn accepts(&self, dst_addr: EthernetAddress) -> bool {
        // TODO: broadcast and multicast
        self.addr == dst_addr
    }
}

impl<'data> EthEndpoint<'_, 'data> {
    pub fn neighbors(&self) -> &NeighborCache<'data> {
        self.inner.arp.neighbors()
    }

    pub fn neighbors_mut(&mut self) -> &mut NeighborCache<'data> {
        self.inner.arp.neighbors_mut()
    }
}

impl packet::Endpoint for EthEndpoint<'_, '_> {
    fn src_addr(&mut self) -> EthernetAddress {
        self.inner.addr
    }

    fn resolve(&mut self, addr: IpAddress, time: Instant, look: bool) -> Result<EthernetAddress> {
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

    fn update(&mut self, hw_addr: EthernetAddress, prot_addr: IpAddress, time: Instant) -> bool {
        if let Some(_) = self.neighbors().lookup_pure(prot_addr, Instant::from_millis(0)) {
            assert!(self.neighbors_mut().fill(prot_addr, hw_addr, Some(time)).is_ok());
            true
        } else {
            false
        }
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
        let packet = packet::In { handle, frame };
        self.handler.receive(packet)
    }
}

impl<H, P, T> nic::Send<H, P> for Sender<'_, '_, T>
where
    H: nic::Handle,
    P: Payload + PayloadMut,
    T: Send<P>,
{
    fn send(&mut self, nic::Packet { handle, payload }: nic::Packet<H, P>) {
        let handle = Handle::new(handle, &mut self.endpoint);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::Slice;
    use crate::nic::{external::External, Device};
    use crate::layer::eth::{Init, NeighborCache};
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

    fn simple_send<P: Payload + PayloadMut>(mut frame: packet::Raw<P>) {
        let src_addr = frame.handle.src_addr();
        let init = Init {
            src_addr,
            dst_addr: MAC_ADDR_1,
            ethertype: EthernetProtocol::Unknown(0xBEEF),
            payload: PAYLOAD_BYTES.len(),
        };
        let mut prepared = frame.prepare(init)
            .expect("Preparing frame mustn't fail in controlled environment");
        prepared
            .payload_mut_slice()
            .copy_from_slice(&PAYLOAD_BYTES[..]);
        prepared
            .send()
            .expect("Sending is possible");
    }

    fn simple_recv<P: Payload>(mut frame: packet::In<P>) {
        assert_eq!(frame.frame().payload().as_slice(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn simple() {
        let mut endpoint = Endpoint::new(MAC_ADDR_1, NeighborCache::new(&mut [][..]));
        let mut nic = External::new_send(Slice::One(vec![0; 1024]));

        let sent = nic.tx(
            1,
            endpoint
                .send_with(simple_send));
        assert_eq!(sent, Ok(1));

        nic.set_one_past_receive(1);
        let recv = nic.rx(
            1,
            endpoint
                .recv_with(simple_recv));
        assert_eq!(recv, Ok(1));
    }
}
