use crate::layer::{eth, Result, Error};
use crate::nic::Info;
use crate::wire::Ipv4Address;
use crate::wire::{
    arp_packet, ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
};
use crate::wire::{Payload, PayloadMut};

/// An incoming packet.
pub struct In<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: ArpPacket<EthernetFrame<&'a mut P>>,
}

/// An outgoing packet as prepared by the arp layer.
pub struct Out<'a, P: Payload> {
    handle: Handle<'a>,
    packet: ArpPacket<EthernetFrame<&'a mut P>>,
}

/// A buffer into which a packet can be placed.
pub struct Raw<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
}

pub struct Handle<'a> {
    pub(crate) inner: eth::Handle<'a>,
}

/// Initializer for a packet.
pub enum Init {
    EthernetIpv4Request {
        source_hardware_addr: EthernetAddress,
        source_protocol_addr: Ipv4Address,
        target_hardware_addr: EthernetAddress,
        target_protocol_addr: Ipv4Address,
    },
}

impl<'a> Handle<'a> {
    pub(crate) fn new(handle: eth::Handle<'a>) -> Self {
        Handle { inner: handle }
    }

    /// Get the hardware info for that packet.
    pub fn info(&self) -> &Info {
        self.inner.info()
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn borrow_mut(&mut self) -> Handle {
        Handle {
            inner: self.inner.borrow_mut(),
        }
    }
}

impl<'a, P: Payload> In<'a, P> {
    pub(crate) fn new(handle: Handle<'a>, packet: ArpPacket<EthernetFrame<&'a mut P>>) -> Self {
        In { handle, packet }
    }

    pub fn deinit(self) -> Raw<'a, P>
    where
        P: PayloadMut,
    {
        let payload = self.packet.into_inner().into_inner();
        Raw::new(self.handle, payload)
    }
}

impl<'a, P: PayloadMut> In<'a, P> {
    /// Try to answer an arp request in-place.
    pub fn answer(mut self) -> Result<Out<'a, P>> {
        let answer = match self.packet.repr() {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr: _,
                target_protocol_addr,
            } => ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr: self.handle.inner.src_addr(),
                source_protocol_addr: target_protocol_addr,
                target_hardware_addr: source_hardware_addr,
                target_protocol_addr: source_protocol_addr,
            },
            _ => return Err(Error::Illegal),
        };

        let dst_address = match answer {
            ArpRepr::EthernetIpv4 {
                operation: _,
                source_hardware_addr: _,
                source_protocol_addr: _,
                target_hardware_addr,
                target_protocol_addr: _} => target_hardware_addr,
            _ => unreachable!(),
        };

        let eth_frame = self.packet.into_inner();
        let eth_init = eth::Init {
            src_addr: self.handle.inner.src_addr(),
            dst_addr: dst_address,
            ethertype: EthernetProtocol::Arp,
            payload: 28, // FIXME?
        };

        let eth_in = eth::InPacket {
            handle: self.handle.inner,
            frame: eth_frame,
        };

        let packet = eth_in.reinit(eth_init)?;
        let eth::InPacket { handle, mut frame} = packet.into_incoming();

        answer.emit(
            arp_packet::new_unchecked_mut(frame.payload_mut_slice()),
        );

        let handle = Handle::new(handle);

        Ok(Out {
            handle,
            packet: ArpPacket::new_unchecked(frame, answer),
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
            self.handle.inner,
            self.packet.into_inner(),
        );
        lower.send()
    }
}

impl<'a, P: Payload + PayloadMut> Raw<'a, P> {
    pub(crate) fn new(handle: Handle<'a>, payload: &'a mut P) -> Self {
        Raw { handle, payload }
    }

    /// Initialize to a valid arp packet.
    pub fn prepare(self, init: Init) -> Result<Out<'a, P>> {
        let mut lower = eth::RawPacket::new(self.handle.inner, self.payload);

        let eth_init = eth::Init {
            src_addr: lower.handle.src_addr(),
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
            payload: 28, // FIXME?
        };

        let packet = lower.prepare(eth_init)?;
        let eth::InPacket { handle, mut frame } = packet.into_incoming();
        let repr = init.initialize(&mut frame)?;

        // Reconstruct the handle.
        let handle = Handle::new(handle);

        Ok(Out {
            handle,
            packet: ArpPacket::new_unchecked(frame, repr),
        })
    }
}

impl Init {
    fn initialize(&self, payload: &mut impl PayloadMut) -> Result<ArpRepr> {
        let repr = self.repr();

        let packet = arp_packet::new_unchecked_mut(payload.payload_mut().as_mut_slice());

        repr.emit(packet);
        Ok(repr)
    }

    fn repr(&self) -> ArpRepr {
        match *self {
            Init::EthernetIpv4Request {
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            },
        }
    }
}
