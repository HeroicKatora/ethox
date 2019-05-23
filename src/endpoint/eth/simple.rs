use crate::endpoint::{Error, Result};
use crate::wire::{ethernet_frame, EthernetAddress, EthernetFrame, EthernetRepr, EthernetProtocol, Payload, PayloadMut};
use crate::nic;

use super::{Packet, RawPacket, Recv, Send};

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
    eth_handler: WithSender,
    handler: H,
}

pub struct Sender<'a, H> {
    _inner: &'a Endpoint,
    eth_handler: WithSender,
    handler: H,
}

pub(crate) struct WithSender {
    from: EthernetAddress,
    to: Option<EthernetAddress>,
    ethertype: Option<EthernetProtocol>,
    payload: usize,
}

pub struct FnHandle<F>(pub F);

impl Endpoint {
    pub fn new(addr: EthernetAddress) -> Self {
        Endpoint {
            addr,
        }
    }

    pub fn recv<H>(&self, handler: H) -> Receiver<H> {
        Receiver { inner: self, eth_handler: self.addr.into(), handler, }
    }

    pub fn recv_with<H>(&self, handler: H) -> Receiver<FnHandle<H>> {
        self.recv(FnHandle(handler))
    }

    pub fn send<H>(&self, handler: H) -> Sender<H> {
        Sender { _inner: self, eth_handler: self.addr.into(), handler, }
    }

    pub fn send_with<H>(&self, handler: H) -> Sender<FnHandle<H>> {
        self.send(FnHandle(handler))
    }

    fn accepts(&self, dst_addr: EthernetAddress) -> bool {
        // TODO: broadcast and multicast
        self.addr == dst_addr
    }
}

impl WithSender {
    pub fn set_dst_addr(&mut self, addr: EthernetAddress) {
        self.to = Some(addr);
    }

    pub fn set_ethertype(&mut self, ethertype: EthernetProtocol) {
        self.ethertype = Some(ethertype);
    }

    pub fn set_payload_len(&mut self, length: usize) {
        self.payload = length;
    }
}

impl WithSender {
    pub(crate) fn initialize<P: PayloadMut>(&mut self, nic: &mut nic::Handle, payload: &mut P) -> Result<EthernetRepr> {
        let dst_addr = self.to.ok_or(Error::Illegal)?;
        let ethertype = self.ethertype.ok_or(Error::Illegal)?;

        let real_len = ethernet_frame::buffer_len(self.payload);
        payload.resize(real_len)?;
        // We did our preconditions, now try to actually get that buffer ready to send.
        nic.queue()?;

        Ok(EthernetRepr {
            src_addr: self.from,
            dst_addr,
            ethertype,
        })
    }
}

impl<H, P, T> nic::Recv<H, P> for Receiver<'_, T>
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
        if !self.inner.accepts(repr.dst_addr) {
            return
        }

        let packet = Packet::new(
            packet.handle,
            &mut self.eth_handler,
            frame);
        self.handler.receive(packet)
    }
}

impl<H, P, T> nic::Send<H, P> for Sender<'_, T>
where
    H: nic::Handle,
    P: Payload + PayloadMut,
    T: Send<P>,
{
    fn send(&mut self, packet: nic::Packet<H, P>) {
        let packet = RawPacket::new(
            packet.handle,
            &mut self.eth_handler,
            packet.payload);
        self.handler.send(packet);
    }
}

impl<'a, P: Payload, F> Recv<P> for FnHandle<F>
    where F: FnMut(Packet<P>)
{
    fn receive(&mut self, frame: Packet<P>) {
        self.0(frame)
    }
}

impl<'a, P: Payload, F> Send<P> for FnHandle<F>
    where F: FnMut(RawPacket<P>)
{
    fn send(&mut self, frame: RawPacket<P>) {
        self.0(frame)
    }
}

impl From<EthernetAddress> for WithSender {
    fn from(addr: EthernetAddress) -> Self {
        WithSender {
            from: addr,
            to: None,
            ethertype: None,
            payload: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::Slice;
    use crate::nic::{external::External, Device};

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
        frame.set_dst_addr(MAC_ADDR_1);
        frame.set_ethertype(EthernetProtocol::Unknown(0xBEEF));
        frame.set_payload_len(PAYLOAD_BYTES.len());
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
        let endpoint = Endpoint::new(MAC_ADDR_1);
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
