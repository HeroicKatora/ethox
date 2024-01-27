use crate::layer::{eth, Result, Error};
use crate::nic::Info;
use crate::wire::{arp, ethernet, ip, Payload, PayloadMut};

/// An incoming packet.
pub struct In<'a, P: Payload> {
    /// A reference to the ARP endpoint state.
    pub control: Controller<'a>,
    /// The valid packet inside the buffer.
    pub packet: arp::Packet<ethernet::Frame<&'a mut P>>,
}

/// An outgoing packet as prepared by the arp layer.
pub struct Out<'a, P: Payload> {
    control: Controller<'a>,
    packet: arp::Packet<ethernet::Frame<&'a mut P>>,
}

/// A buffer into which a packet can be placed.
pub struct Raw<'a, P: Payload> {
    /// A reference to the ARP endpoint state.
    pub control: Controller<'a>,
    /// A mutable reference to the payload buffer.
    pub payload: &'a mut P,
}


/// A reference to the endpoint of layers below (phy + eth + ip).
///
/// This is not really useful on its own but should instead be used either within a `In` or a
/// `Raw`. Some of the methods offered there will access the non-public members of this struct to
/// fulfill their task.
pub struct Controller<'a> {
    pub(crate) inner: eth::Controller<'a>,
}

/// Initializer for a packet.
pub enum Init {
    /// As an arp request for Ethernet-IPv4 translation.
    EthernetIpv4Request {
        /// The hardware source address to use.
        source_hardware_addr: ethernet::Address,
        /// The IPv4 source address to use.
        /// Might be the same as `target_protocol_addr` for gratuitous ARP.
        source_protocol_addr: ip::v4::Address,
        /// The hardware address of the target of the request, potentially broadcast.
        target_hardware_addr: ethernet::Address,
        /// The IPv4 address of the target.
        target_protocol_addr: ip::v4::Address,
    },
    /// Use a pre-defined arp representation.
    Raw {
        /// The full representation of the arp-part of the frame.
        inner: arp::Repr,
    },
}

impl<'a> Controller<'a> {
    pub(crate) fn new(control: eth::Controller<'a>) -> Self {
        Controller { inner: control }
    }

    /// Get the hardware info for that packet.
    pub fn info(&self) -> &dyn Info {
        self.inner.info()
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn borrow_mut(&mut self) -> Controller {
        Controller {
            inner: self.inner.borrow_mut(),
        }
    }
}

impl<'a, P: Payload> In<'a, P> {
    pub(crate) fn new(control: Controller<'a>, packet: arp::Packet<ethernet::Frame<&'a mut P>>) -> Self {
        In { control, packet }
    }

    /// Deconstruct the packet into the reusable buffer.
    pub fn deinit(self) -> Raw<'a, P>
    where
        P: PayloadMut,
    {
        let payload = self.packet.into_inner().into_inner();
        Raw::new(self.control, payload)
    }
}

impl<'a, P: PayloadMut> In<'a, P> {
    /// Try to answer an arp request in-place.
    pub fn answer(mut self) -> Result<Out<'a, P>> {
        let dst_address;
        let answer = match self.packet.repr() {
            arp::Repr::EthernetIpv4 {
                operation: arp::Operation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr: _,
                target_protocol_addr,
            } => {
                dst_address = source_hardware_addr;
                arp::Repr::EthernetIpv4 {
                    operation: arp::Operation::Reply,
                    source_hardware_addr: self.control.inner.src_addr(),
                    source_protocol_addr: target_protocol_addr,
                    target_hardware_addr: source_hardware_addr,
                    target_protocol_addr: source_protocol_addr,
                }
            }
            _ => return Err(Error::Illegal),
        };

        let eth_frame = self.packet.into_inner();
        let eth_init = eth::Init {
            src_addr: self.control.inner.src_addr(),
            dst_addr: dst_address,
            ethertype: ethernet::EtherType::Arp,
            payload: 28,
        };

        let eth_in = eth::InPacket {
            control: self.control.inner,
            frame: eth_frame,
        };

        let packet = eth_in.reinit(eth_init)?;
        let eth::InPacket { control, mut frame} = packet.into_incoming();

        answer.emit(
            arp::packet::new_unchecked_mut(frame.payload_mut_slice()),
        );

        let control = Controller::new(control);

        Ok(Out {
            control,
            packet: arp::Packet::new_unchecked(frame, answer),
        })
    }
}

impl<'a, P: Payload> Out<'a, P> {
    /// Called last after having initialized the payload.
    pub fn send(self) -> Result<()>
        where
            P: PayloadMut,
    {
        let lower = eth::OutPacket::new_unchecked(
            self.control.inner,
            self.packet.into_inner(),
        );
        lower.send()
    }
}

impl<'a, P: Payload + PayloadMut> Raw<'a, P> {
    pub(crate) fn new(control: Controller<'a>, payload: &'a mut P) -> Self {
        Raw { control, payload }
    }

    /// Initialize to a valid arp packet.
    pub fn prepare(self, init: Init) -> Result<Out<'a, P>> {
        let mut lower = eth::RawPacket {
            control: self.control.inner,
            payload: self.payload,
        };

        let eth_init = eth::Init {
            src_addr: lower.control.src_addr(),
            dst_addr: ethernet::Address::BROADCAST,
            ethertype: ethernet::EtherType::Arp,
            payload: 28,
        };

        let packet = lower.prepare(eth_init)?;
        let eth::InPacket { control, mut frame } = packet.into_incoming();
        let repr = init.initialize(&mut frame)?;

        // Reconstruct the control.
        let control = Controller::new(control);

        Ok(Out {
            control,
            packet: arp::Packet::new_unchecked(frame, repr),
        })
    }
}

impl Init {
    fn initialize(&self, payload: &mut impl PayloadMut) -> Result<arp::Repr> {
        let repr = self.repr();

        let packet = arp::packet::new_unchecked_mut(payload.payload_mut().as_mut_slice());

        repr.emit(packet);
        Ok(repr)
    }

    fn repr(&self) -> arp::Repr {
        match *self {
            Init::EthernetIpv4Request {
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => arp::Repr::EthernetIpv4 {
                operation: arp::Operation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            },
            Init::Raw { inner } => inner,
        }
    }
}
