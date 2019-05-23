//! The ethernet layer.
use crate::layer::Result;
use crate::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, Payload, PayloadMut};
use crate::nic;

mod endpoint;
mod neighbor;

use self::endpoint::WithSender as EthHandler;

pub use endpoint::{
    Endpoint,
    FnHandler,
    Receiver,
    Sender};

pub use neighbor::{
    Neighbor,
    Answer as NeighborAnswer,
    Cache as NeighborCache,
    Table as NeighborTable};


pub trait Recv<P: Payload> {
    fn receive(&mut self, frame: Packet<P>);
}

pub trait Send<P: Payload> {
    fn send(&mut self, raw: RawPacket<P>);
}

pub struct Packet<'a, P: Payload> {
    nic_handle: &'a mut nic::Handle,
    handle: &'a mut EthHandler,
    frame: EthernetFrame<&'a mut P>,
}

pub struct RawPacket<'a, P: Payload> {
    nic_handle: &'a mut nic::Handle,
    handle: &'a mut EthHandler,
    payload: &'a mut P,
}

impl<'a, P: Payload> Packet<'a, P> {
    pub(crate) fn new(
        nic_handle: &'a mut nic::Handle,
        handle: &'a mut EthHandler,
        frame: EthernetFrame<&'a mut P>)
    -> Self {
        Packet {
            nic_handle,
            handle,
            frame,
        }
    }

    pub fn frame(&mut self) -> &mut EthernetFrame<&'a mut P> {
        &mut self.frame
    }

    pub fn deinit(self) -> RawPacket<'a, P> {
        RawPacket {
            nic_handle: self.nic_handle,
            handle: self.handle,
            payload: self.frame.into_inner(),
        }
    }
}

impl<'a, P: Payload + PayloadMut> RawPacket<'a, P> {
    pub(crate) fn new(
        nic_handle: &'a mut nic::Handle,
        handle: &'a mut EthHandler,
        payload: &'a mut P,
    ) -> Self {
        RawPacket {
            nic_handle,
            handle,
            payload,
        }
    }

    pub fn set_dst_addr(&mut self, addr: EthernetAddress) {
        self.handle.set_dst_addr(addr)
    }

    pub fn set_ethertype(&mut self, ethertype: EthernetProtocol) {
        self.handle.set_ethertype(ethertype)
    }

    pub fn set_payload_len(&mut self, length: usize) {
        self.handle.set_payload_len(length)
    }

    pub fn payload(&mut self) -> &mut P {
        &mut self.payload
    }

    pub fn prepare(self) -> Result<Packet<'a, P>> {
        let mut payload = self.payload;
        let repr = self.handle.initialize(self.nic_handle, &mut payload)?;
        Ok(Packet {
            nic_handle: self.nic_handle,
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}
