use crate::nic;
use crate::layer::{Error, Result};
use crate::time::Instant;
use crate::wire::{ethernet_frame, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, Payload, PayloadMut};

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub frame: EthernetFrame<&'a mut P>,
}

pub struct RawPacket<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
}

/// A reference to the endpoint of layers below (phy + eth).
///
/// This is not really useful on its own but should instead be used either within a `Packet` or a
/// `RawPacket`. Some of the methods offered there will access the non-public members of this
/// struct to fulfill their task.
pub struct Handle<'a> {
    pub(crate) nic_handle: &'a mut nic::Handle,
    pub(crate) endpoint: &'a mut (Endpoint + 'a),
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
    fn resolve(&mut self, _: IpAddress, _: Instant) -> Result<EthernetAddress>;
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
    pub fn borrow_mut(&mut self) -> Handle {
        Handle {
            nic_handle: self.nic_handle,
            endpoint: self.endpoint,
        }
    }

    pub fn info(&self) -> &nic::Info {
        self.nic_handle.info()
    }

    /// Try to initialize the destination from an upper layer protocol address.
    ///
    /// Failure to satisfy the request is clearly signalled. Use the result to initialize the
    /// representation to a valid eth frame.
    pub fn resolve(&mut self, dst_addr: IpAddress)
        -> Result<EthernetAddress>
    {
        let time = self.nic_handle.info().timestamp();
        self.endpoint.resolve(dst_addr, time)
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

    /// Try to send that packet.
    pub fn send(self) -> Result<()> {
        self.handle.nic_handle.queue()
    }
}

impl<'a, P: Payload + PayloadMut> RawPacket<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        RawPacket {
            handle,
            payload,
        }
    }

    pub fn src_addr(&mut self) -> EthernetAddress {
        self.handle.endpoint.src_addr()
    }

    pub fn prepare(self, init: Init) -> Result<Packet<'a, P>> {
        let mut payload = self.payload;
        let repr = init.initialize(&mut payload)?;
        Ok(Packet {
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}

impl Init {
    fn initialize<P: PayloadMut>(&self, payload: &mut P) -> Result<EthernetRepr> {
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
