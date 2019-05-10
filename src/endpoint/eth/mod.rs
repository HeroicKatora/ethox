//! The ethernet layer.
use crate::endpoint::Result;
use crate::wire::{EthernetFrame, EthernetRepr, Payload, PayloadMut};
use crate::nic;

pub mod simple;

pub trait Recv<H: Handle, P: Payload> {
    fn receive(&mut self, frame: Packet<H, P>);
}

pub trait Send<H: Handle, P: Payload> {
    fn send(&mut self, raw: RawPacket<H, P>);
}

/// A trait-object to something implementing the eth-layer.
pub trait Handle {
    /// Initialize the frame and return the supposed representation.
    fn initialize<P: PayloadMut>(&mut self, handle: &mut nic::Handle, frame: &mut P) -> Result<EthernetRepr>;
}

pub struct Packet<'a, H: Handle, P: Payload> {
    nic_handle: &'a mut nic::Handle,
    handle: &'a mut H,
    frame: EthernetFrame<P>,
}

pub struct RawPacket<'a, H: Handle, P: Payload> {
    nic_handle: &'a mut nic::Handle,
    handle: &'a mut H,
    payload: P,
}

impl<'a, H: Handle, P: Payload> Packet<'a, H, P> {
    pub fn new(
        nic_handle: &'a mut nic::Handle,
        handle: &'a mut H,
        frame: EthernetFrame<P>)
    -> Self {
        Packet {
            nic_handle,
            handle,
            frame,
        }
    }

    pub fn handle(&mut self) -> &mut H {
        self.handle
    }

    pub fn frame(&mut self) -> &mut EthernetFrame<P> {
        &mut self.frame
    }

    pub fn deinit(self) -> RawPacket<'a, H, P> {
        RawPacket {
            nic_handle: self.nic_handle,
            handle: self.handle,
            payload: self.frame.into_inner(),
        }
    }
}

impl<'a, H: Handle, P: Payload + PayloadMut> RawPacket<'a, H, P> {
    pub fn new(
        nic_handle: &'a mut nic::Handle,
        handle: &'a mut H,
        payload: P
    ) -> Self {
        RawPacket {
            nic_handle,
            handle,
            payload,
        }
    }

    pub fn handle(&mut self) -> &mut H {
        self.handle
    }

    pub fn payload(&mut self) -> &mut P {
        &mut self.payload
    }

    pub fn prepare(self) -> Result<Packet<'a, H, P>> {
        let mut payload = self.payload;
        let repr = self.handle.initialize(self.nic_handle, &mut payload)?;
        Ok(Packet {
            nic_handle: self.nic_handle,
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}
