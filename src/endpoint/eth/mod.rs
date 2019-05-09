//! The ethernet layer.
use crate::endpoint::Result;
use crate::wire::{EthernetFrame, EthernetRepr, Payload, PayloadMut};

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
    fn initialize<P: PayloadMut>(&mut self, frame: &mut P) -> Result<EthernetRepr>;
}

pub struct Packet<'a, H: Handle, P: Payload> {
    handle: &'a mut H,
    frame: EthernetFrame<P>,
}

pub struct RawPacket<'a, H: Handle, P: Payload> {
    handle: &'a mut H,
    payload: P,
}

impl<'a, H: Handle, P: Payload> Packet<'a, H, P> {
    pub fn new(handle: &'a mut H, frame: EthernetFrame<P>) -> Self {
        Packet {
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
            handle: self.handle,
            payload: self.frame.into_inner(),
        }
    }
}

impl<'a, H: Handle, P: Payload + PayloadMut> RawPacket<'a, H, P> {
    pub fn new(handle: &'a mut H, payload: P) -> Self {
        RawPacket {
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
        let repr = self.handle.initialize(&mut payload)?;
        Ok(Packet {
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}
