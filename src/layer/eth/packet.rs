use crate::layer::{Error, Result};
use crate::wire::{ethernet_frame, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, Payload, PayloadMut};
use crate::nic;

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub frame: EthernetFrame<&'a mut P>,
}

pub struct RawPacket<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
    pub init: Option<Init>,
}

/// A reference to the endpoint of layers below (phy + eth).
///
/// This is not really useful on its own but should instead be used either within a `Packet` or a
/// `RawPacket`. Some of the methods offered there will access the non-public members of this
/// struct to fulfill their task.
pub struct Handle<'a> {
    nic_handle: &'a mut nic::Handle,
    endpoint: &'a mut (Endpoint + 'a),
}

/// Initializer for a packet.
pub struct Init {
    pub src_addr: EthernetAddress,
    pub dst_addr: EthernetAddress,
    pub ethertype: EthernetProtocol,
    pub payload: usize,
}

/// The interface to the endpoint.
pub(crate) trait Endpoint{
    fn src_addr(&mut self) -> EthernetAddress;
    fn resolve(&mut self, _: IpAddress) -> Result<EthernetAddress>;
}

impl<'a> Handle<'a> {
    pub (crate) fn new(
        nic_handle: &'a mut nic::Handle,
        endpoint: &'a mut (Endpoint + 'a))
    -> Self {
        Handle {
            nic_handle,
            endpoint,
        }
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn coerce_lifetime<'b>(self) -> Handle<'b> where 'a: 'b {
        Handle {
            nic_handle: self.nic_handle,
            endpoint: self.endpoint,
        }
    }
}

impl<'a, P: Payload> Packet<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        frame: EthernetFrame<&'a mut P>)
    -> Self {
        Packet {
            handle,
            frame,
        }
    }

    pub fn frame(&mut self) -> &mut EthernetFrame<&'a mut P> {
        &mut self.frame
    }

    pub fn reinit(self) -> RawPacket<'a, P>
        where P: PayloadMut,
    {
        RawPacket::new(self.handle, self.frame.into_inner())
    }
}

impl<'a, P: Payload + PayloadMut> RawPacket<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        RawPacket {
            handle,
            init: None,
            payload,
        }
    }

    pub fn src_addr(&mut self) -> EthernetAddress {
        self.handle.endpoint.src_addr()
    }

    /// Try to initialize the destination from an upper layer protocol address.
    ///
    /// Failure to satisfy the request is clearly signalled.
    pub fn resolve(&mut self, dst_addr: IpAddress) -> Result<()> {
        let init = match &mut self.init {
            Some(init) => init,
            None => return Err(Error::Illegal),
        };
        init.dst_addr = self.handle.endpoint.resolve(dst_addr)?;
        Ok(())
    }

    pub fn prepare(mut self) -> Result<Packet<'a, P>> {
        let mut payload = self.payload;
        let repr = self.init
            .as_mut()
            .ok_or(Error::Illegal)?
            .initialize(&mut payload)?;
        self.handle.nic_handle.queue()?;
        Ok(Packet {
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}

impl Init {
    fn initialize<P: PayloadMut>(&mut self, payload: &mut P) -> Result<EthernetRepr> {
        let real_len = ethernet_frame::buffer_len(self.payload);
        let repr = EthernetRepr {
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            ethertype: self.ethertype,
        };

        payload.resize(real_len)?;
        let ethernet = ethernet_frame::new_unchecked_mut(payload.payload_mut());
        ethernet.check_len()
            .map_err(|_| Error::BadSize)?;
        repr.emit(ethernet);

        Ok(repr)
    }
}
