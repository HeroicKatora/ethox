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
    pub init: Init,
}

pub struct Handle<'a> {
    nic_handle: &'a mut nic::Handle,
    endpoint: &'a mut (Endpoint + 'a),
}

/// Initializer for a packet.
pub struct Init {
    pub from: EthernetAddress,
    pub to: Option<EthernetAddress>,
    pub ethertype: Option<EthernetProtocol>,
    pub payload: usize,
}

/// The interface to the endpoint.
pub(crate) trait Endpoint{
    fn init(&mut self) -> Init;
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
        let init = handle.endpoint.init();
        RawPacket {
            handle,
            init,
            payload,
        }
    }

    pub fn prepare(mut self) -> Result<Packet<'a, P>> {
        let mut payload = self.payload;
        let repr = self.init.initialize(&mut payload)?;
        self.handle.nic_handle.queue()?;
        Ok(Packet {
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}

impl Init {
    pub fn set_dst_addr(&mut self, addr: EthernetAddress) {
        self.to = Some(addr);
    }

    pub fn set_ethertype(&mut self, ethertype: EthernetProtocol) {
        self.ethertype = Some(ethertype);
    }

    pub fn set_payload_len(&mut self, length: usize) {
        self.payload = length;
    }

    fn initialize<P: PayloadMut>(&mut self, payload: &mut P) -> Result<EthernetRepr> {
        let dst_addr = self.to.ok_or(Error::Illegal)?;
        let ethertype = self.ethertype.ok_or(Error::Illegal)?;
        let real_len = ethernet_frame::buffer_len(self.payload);

        payload.resize(real_len)?;

        Ok(EthernetRepr {
            src_addr: self.from,
            dst_addr,
            ethertype,
        })
    }
}


impl From<EthernetAddress> for Init {
    fn from(addr: EthernetAddress) -> Self {
        Init {
            from: addr,
            to: None,
            ethertype: None,
            payload: 0,
        }
    }
}
