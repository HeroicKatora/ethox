//! The ethernet layer.
use crate::wire::{EthernetAddress, EthernetFrame, EthernetRepr, Payload};
use crate::nic;

pub struct Sock {
}

pub trait Recv<C: Payload> {
    fn receive(&mut self, repr: EthernetRepr, frame: EthernetFrame<C>);
}

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
    handler: H,
}

impl Endpoint {
    pub fn recv<H>(&self, handler: H) -> Receiver<H> {
        Receiver { inner: self, handler, }
    }

    fn accepts(&self, dst_addr: EthernetAddress) -> bool {
        // TODO: broadcast and multicast
        self.addr == dst_addr
    }
}

impl<'a, P: nic::Packet<'a>, H> nic::Recv<'a, P> for Receiver<'_, H> 
    where H: Recv<&'a mut P::Payload>
{
    fn receive(&mut self, packet: P) {
        let (_, payload) = packet.separate();
        let frame = match EthernetFrame::new_checked(payload) {
            Ok(frame) => frame,
            Err(_) => return,
        };

        let repr = frame.repr();
        if !self.inner.accepts(repr.dst_addr) {
            return
        }

        self.handler.receive(repr, frame)
    }
}
