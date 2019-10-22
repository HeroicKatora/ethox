use core::marker::PhantomData;

use crate::layer::FnHandler;
use crate::wire::{EthernetAddress, EthernetFrame, Payload, PayloadMut};
use crate::nic;

use super::{Recv, Send};
use super::packet::{self, Controller};

/// An ethernet endpoint, logical part of a device.
///
/// This structure contains the ethernet address considered to identify the device on the local
/// ethernet network. Then all parts of receiving and sending, except physical layer framing, can
/// be implemented in software.
///
/// Note that the ethernet wire layer does **not yet** support giant frames but if it did these
/// would need to be explicitely enabled here.
///
/// Otherwise, the endpoint holds no configuration state and options. To preserve future
/// compatibility it nevertheless has a lifetime parameter like other layer's endpoints. (ARP and
/// ICMP do not use the same reservation since they are less likely to break upper layer code by
/// having basically no upper layer). This allows introducing new state, as long as there is a
/// default value with static lifetime—such as is the case for slices.
pub struct Endpoint<'a> {
    /// Our own address.
    ///
    /// We ignored any packets with mismatching destination.
    addr: EthernetAddress,

    /// TODO: figure out if we need any dynamically sized, non-owned data.
    data: PhantomData<&'a ()>,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configurerd here, and not in the endpoint state.
pub struct Receiver<'a, 'e, H> {
    endpoint: EthEndpoint<'a, 'e>,

    /// The upper protocol receiver.
    handler: H,
}

/// An endpoint borrowed for sending.
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
    /// Construct a new endpoint with a specified address.
    ///
    /// The endpoint will filter incoming messages by the hardware address and allows inspection of
    /// that address for sending.
    pub fn new(addr: EthernetAddress) -> Self {
        Endpoint {
            addr,
            data: PhantomData,
        }
    }

    /// Receive frames using this mutably borrowed endpoint.
    pub fn recv<H>(&mut self, handler: H) -> Receiver<'_, 'a, H> {
        Receiver { endpoint: self.eth(), handler, }
    }

    /// Receive frames using this mutably borrowed endpoint and a function.
    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<'_, 'a, FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    /// Send frames using this mutably borrowed endpoint.
    pub fn send<H>(&mut self, handler: H) -> Sender<'_, 'a, H> {
        Sender { endpoint: self.eth(), handler, }
    }

    /// Send frames using this mutably borrowed endpoint and a function.
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
        self.addr == dst_addr || dst_addr.is_broadcast()
    }
}

impl packet::Endpoint for EthEndpoint<'_, '_> {
    fn src_addr(&mut self) -> EthernetAddress {
        self.inner.addr
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

        let control = Controller {
            nic_handle: packet.handle,
            endpoint: &mut self.endpoint,
        };

        let packet = packet::In { control, frame };
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
        let control = Controller {
            nic_handle: handle,
            endpoint: &mut self.endpoint,
        };

        let packet = packet::Raw { control, payload };
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
    use crate::layer::eth::Init;
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
        let src_addr = frame.control.src_addr();
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

    fn simple_recv<P: Payload>(frame: packet::In<P>) {
        assert_eq!(frame.frame.payload().as_slice(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn simple() {
        let mut endpoint = Endpoint::new(MAC_ADDR_1);
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
