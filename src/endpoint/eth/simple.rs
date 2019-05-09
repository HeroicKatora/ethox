use crate::endpoint::{Error, Result};
use crate::wire::{EthernetAddress, EthernetFrame, EthernetRepr, EthernetProtocol, Payload, PayloadMut};
use crate::nic;

use super::{Handle, Packet, RawPacket, Recv, Send};

pub struct Endpoint {
    /// Our own address.
    ///
    /// We ignored any packets with mismatching destination.
    addr: EthernetAddress,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configurerd here, and not in the endpoint state.
pub struct Receiver<'a, H> {
    inner: &'a Endpoint,
    eth_handler: NoHandler,
    handler: H,
}

pub struct Sender<'a, H> {
    _inner: &'a Endpoint,
    eth_handler: WithSender,
    handler: H,
}

pub struct NoHandler;

pub struct WithSender {
    from: EthernetAddress,
    to: Option<EthernetAddress>,
    ethertype: Option<EthernetProtocol>,
}

impl Endpoint {
    pub fn recv<H>(&self, handler: H) -> Receiver<H> {
        Receiver { inner: self, eth_handler: NoHandler, handler, }
    }

    pub fn send<H>(&self, handler: H) -> Sender<H> {
        let eth_handler = WithSender {
            from: self.addr,
            to: None,
            ethertype: None,
        };

        Sender { _inner: self, eth_handler, handler, }
    }

    fn accepts(&self, dst_addr: EthernetAddress) -> bool {
        // TODO: broadcast and multicast
        self.addr == dst_addr
    }
}

impl Handle for NoHandler {
    fn initialize<P: PayloadMut>(&mut self, _: &mut P) -> Result<EthernetRepr> {
        // this context is not able to construct immediate responses.
        Err(Error::Illegal)
    }
}

impl Handle for WithSender {
    fn initialize<P: PayloadMut>(&mut self, _: &mut P) -> Result<EthernetRepr> {
        let dst_addr = self.to.ok_or(Error::Illegal)?;
        let ethertype = self.ethertype.ok_or(Error::Illegal)?;
        Ok(EthernetRepr {
            src_addr: self.from,
            dst_addr,
            ethertype,
        })
    }
}

impl<H, P, T> nic::Recv<H, P> for Receiver<'_, T>
where
    H: nic::Handle + ?Sized,
    P: Payload + ?Sized,
    T: for<'a> Recv<NoHandler, &'a mut P>,
{
    fn receive(&mut self, packet: nic::Packet<H, P>) {
        let frame = match EthernetFrame::new_checked(packet.payload) {
            Ok(frame) => frame,
            Err(_) => return,
        };

        let repr = frame.repr();
        if !self.inner.accepts(repr.dst_addr) {
            return
        }

        let packet = Packet::new(&mut self.eth_handler, frame);
        self.handler.receive(packet)
    }
}

impl<H, P, T> nic::Send<H, P> for Sender<'_, T>
where
    H: nic::Handle + ?Sized,
    P: Payload + PayloadMut + ?Sized,
    T: for<'a> Send<WithSender, &'a mut P>,
{
    fn send(&mut self, packet: nic::Packet<H, P>) {
        let packet = RawPacket::new(&mut self.eth_handler, packet.payload);
        self.handler.send(packet);
    }
}
