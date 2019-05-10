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

pub struct FnHandle<F>(pub F);

impl Endpoint {
    pub fn new(addr: EthernetAddress) -> Self {
        Endpoint {
            addr,
        }
    }

    pub fn recv<H>(&self, handler: H) -> Receiver<H> {
        Receiver { inner: self, eth_handler: NoHandler, handler, }
    }

    pub fn recv_with<H>(&self, handler: H) -> Receiver<FnHandle<H>> {
        self.recv(FnHandle(handler))
    }

    pub fn send<H>(&self, handler: H) -> Sender<H> {
        let eth_handler = WithSender {
            from: self.addr,
            to: None,
            ethertype: None,
        };

        Sender { _inner: self, eth_handler, handler, }
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
        self.to = Some(addr)
    }

    pub fn set_ethertype(&mut self, ethertype: EthernetProtocol) {
        self.ethertype = Some(ethertype)
    }
}

impl Handle for NoHandler {
    fn initialize<P: PayloadMut>(&mut self, _: &mut nic::Handle, _: &mut P) -> Result<EthernetRepr> {
        // this context is not able to construct immediate responses.
        Err(Error::Illegal)
    }
}

impl Handle for WithSender {
    fn initialize<P: PayloadMut>(&mut self, nic: &mut nic::Handle, _: &mut P) -> Result<EthernetRepr> {
        let dst_addr = self.to.ok_or(Error::Illegal)?;
        let ethertype = self.ethertype.ok_or(Error::Illegal)?;

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
    P: Payload + PayloadMut + ?Sized,
    T: for<'a> Send<WithSender, &'a mut P>,
{
    fn send(&mut self, packet: nic::Packet<H, P>) {
        let packet = RawPacket::new(
            packet.handle,
            &mut self.eth_handler,
            packet.payload);
        self.handler.send(packet);
    }
}

impl<'a, H: Handle, P: Payload, F> Recv<H, &'a mut P> for FnHandle<F>
    where F: FnMut(Packet<H, &mut P>)
{
    fn receive(&mut self, frame: Packet<H, &'a mut P>) {
        self.0(frame)
    }
}

impl<'a, H: Handle, P: Payload, F> Send<H, &'a mut P> for FnHandle<F>
    where F: FnMut(RawPacket<H, &mut P>)
{
    fn send(&mut self, frame: RawPacket<H, &'a mut P>) {
        self.0(frame)
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

    fn simple_send<P: Payload + PayloadMut>(mut frame: RawPacket<WithSender, &mut P>) {
        frame.handle().set_dst_addr(MAC_ADDR_1);
        frame.handle().set_ethertype(EthernetProtocol::Unknown(0xBEEF));
        let mut prepared = frame.prepare()
            .expect("Preparing frame mustn't fail in controlled environment");
        prepared
            .frame()
            .payload_mut_slice()[..50] //FIXME: this should not be necessary, resize first.
            .copy_from_slice(&PAYLOAD_BYTES[..]);
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
    }
}
