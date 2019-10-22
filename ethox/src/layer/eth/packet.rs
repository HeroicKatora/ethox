use crate::nic;
use crate::layer::{Error, Result};
use crate::wire::{Payload, PayloadResult, PayloadMut, PayloadMutExt, Reframe, ReframePayload, payload};
use crate::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, ethernet_frame};

/// An incoming packet.
///
/// The contents were inspected and could be handled up to the eth layer.
pub struct In<'a, P: Payload> {
    /// A reference to the ethernet endpoint state.
    pub handle: Controller<'a>,
    /// The valid ethernet frame inside the buffer.
    pub frame: EthernetFrame<&'a mut P>,
}

/// An outgoing packet as prepared by the ethernet layer.
///
/// While the layers below have been initialized, the payload of the packet has not. Fill it by
/// grabbing the mutable slice for example.
#[must_use = "You need to call `send` explicitely on an OutPacket, otherwise no packet is sent."]
pub struct Out<'a, P: Payload> {
    handle: Controller<'a>,
    frame: EthernetFrame<&'a mut P>,
}

/// A buffer into which a packet can be placed.
pub struct Raw<'a, P: Payload> {
    /// A reference to the ethernet endpoint state.
    pub handle: Controller<'a>,
    /// A mutable reference to the payload buffer.
    pub payload: &'a mut P,
}

/// A reference to the endpoint of layers below (phy + eth).
///
/// This is not really useful on its own but should instead be used either within a `Packet` or a
/// `RawPacket`. Some of the methods offered there will access the non-public members of this
/// struct to fulfill their task.
pub struct Controller<'a> {
    pub(crate) nic_handle: &'a mut dyn nic::Handle,
    pub(crate) endpoint: &'a mut dyn Endpoint,
}

/// Initializer for a packet.
pub struct Init {
    /// The ethernet source address to use.
    ///
    /// Most often you'll want to select the address assigned to the ethernet endpoint at which
    /// responses are to be received. But in theory you are free to use other addresses, for
    /// example to emulate a very temporary endpoint or use manual addresses for less standard
    /// compliant networking.
    pub src_addr: EthernetAddress,
    /// The destination address for the frame.
    ///
    /// Can be broadcast, multi-cast, unicast or some application specific addressing magic within
    /// an organizational reserved block.
    pub dst_addr: EthernetAddress,
    /// The protocol of the next layer, contained in the frame payload.
    pub ethertype: EthernetProtocol,
    /// The length in bytes that the payload requires.
    pub payload: usize,
}

/// The interface to the endpoint.
pub(crate) trait Endpoint{
    /// Get the default source address.
    fn src_addr(&mut self) -> EthernetAddress;
}

impl<'a> Controller<'a> {
    pub (crate) fn new(
        nic_handle: &'a mut dyn nic::Handle,
        endpoint: &'a mut dyn Endpoint,
    ) -> Self {
        Controller { nic_handle, endpoint, }
    }

    pub(crate) fn wrap(self,
        wrap: impl FnOnce(&'a mut dyn nic::Handle) -> &'a mut dyn nic::Handle,
    ) -> Self {
        let nic_handle = wrap(self.nic_handle);
        Controller { nic_handle, endpoint: self.endpoint }
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn borrow_mut(&mut self) -> Controller {
        Controller {
            nic_handle: self.nic_handle,
            endpoint: self.endpoint,
        }
    }

    /// Get a reference to the network device information.
    ///
    /// This is a central method since the ethernet layer abstracts over the phsical media in use.
    /// It splits the raw packet buffers supplied by the network device into a dynamic trait object
    /// with the device info (part of the handle) on one hand and the payload buffer on the other.
    /// This removes some detailed information on the device but simplifies layers on top.
    pub fn info(&self) -> &dyn nic::Info {
        self.nic_handle.info()
    }

    /// Get the configured (source) address of the ethernet endpoint.
    pub fn src_addr(&mut self) -> EthernetAddress {
        self.endpoint.src_addr()
    }
}

impl<'a, P: Payload> In<'a, P> {
    /// Reuse the buffer underlying the packet.
    ///
    /// Note that the content will be lost entirely when reinitializing the frame.
    pub fn deinit(self) -> Raw<'a, P>
        where P: PayloadMut,
    {
        Raw::new(self.handle, self.frame.into_inner())
    }
}

impl<'a, P: PayloadMut> In<'a, P> {
    /// Prepare the incoming packet for retransmission, without altering the payload.
    ///
    /// If the length is changed then the longest slice at the end that fits into both
    /// representations is regarded as the payload of the packet.
    pub fn reinit(self, init: Init) -> Result<Out<'a, P>> {
        let In { handle, frame } = self;
        let new_len = ethernet_frame::buffer_len(init.payload);
        let new_repr = EthernetRepr {
            src_addr: init.src_addr,
            dst_addr: init.dst_addr,
            ethertype: init.ethertype,
        };
        let raw_repr = frame.repr();
        let raw_buffer = frame.into_inner();

        let raw_len = raw_buffer.payload().len();
        let raw_payload = raw_len - raw_repr.header_len();

        // The payload is the common tail.
        let payload = init.payload.min(raw_payload);
        let old_payload = raw_len - payload..raw_len;
        let new_payload = new_len - payload..new_len;

        raw_buffer.reframe_payload(ReframePayload {
            length: new_len,
            old_payload,
            new_payload,
        })?;

        // Now emit the header again:
        new_repr.emit(ethernet_frame::new_unchecked_mut(raw_buffer.payload_mut()));
        let frame = EthernetFrame::new_unchecked(raw_buffer, new_repr);

        Ok(Out {
            handle,
            frame,
        })
    }
}

impl<'a, P: Payload> Out<'a, P> {
    /// Pretend the packet has been initialized by the ethernet layer.
    ///
    /// This is fine to call if a previous call to `into_incoming` was used to destructure the
    /// initialized packet and its contents have not changed. Some changes are fine as well and
    /// nothing will cause unsafety but panics or dropped packets are to be expected.
    pub fn new_unchecked(
        handle: Controller<'a>,
        frame: EthernetFrame<&'a mut P>) -> Self
    {
        Out{ handle, frame, }
    }

    /// Unwrap the contained control handle and initialized ethernet frame.
    pub fn into_incoming(self) -> In<'a, P> {
        let Out { handle, frame } = self;
        In { handle, frame }
    }

    /// Deconstruct the initialized frame into a raw buffer.
    ///
    /// Pairing this with `new_unchecked` allows modifying the frame or handle in nearly arbitrary
    /// ways while explicitely warning that it is a bad idea to transmit arbitrary frames.
    pub fn into_raw(self) -> Raw<'a, P> {
        let Out { handle, frame } = self;
        Raw { handle, payload: frame.into_inner() }
    }
    
    /// Try to send that packet.
    pub fn send(self) -> Result<()> {
        self.handle.nic_handle.queue()
    }
}

impl<'a, P: PayloadMut> Out<'a, P> {
    /// A mutable slice containing the payload of the contained protocol.
    ///
    /// Prefer this an `into_raw` and `new_unchecked` in case a temporary reference to the payload
    /// is sufficient.
    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        self.frame.payload_mut_slice()
    }
}

impl<'a, P: Payload + PayloadMut> Raw<'a, P> {
    pub(crate) fn new(
        handle: Controller<'a>,
        payload: &'a mut P) -> Self
    {
        Raw { handle, payload, }
    }

    /// Initialize the raw packet buffer to a valid ethernet frame.
    pub fn prepare(self, init: Init) -> Result<Out<'a, P>> {
        let mut payload = self.payload;
        let repr = init.initialize(&mut payload)?;
        Ok(Out {
            handle: self.handle,
            frame: EthernetFrame::new_unchecked(payload, repr),
        })
    }
}

impl<P: Payload> Payload for Out<'_, P> {
    fn payload(&self) -> &payload {
        self.frame.payload()
    }
}

impl<P: PayloadMut> PayloadMut for Out<'_, P> {
    fn payload_mut(&mut self) -> &mut payload {
        self.frame.payload_mut()
    }

    fn resize(&mut self, length: usize) -> PayloadResult<()> {
        self.frame.resize(length)
    }

    fn reframe(&mut self, frame: Reframe) -> PayloadResult<()> {
        self.frame.reframe(frame)
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
